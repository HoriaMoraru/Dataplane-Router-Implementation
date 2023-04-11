#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define INIT_RT 80000
#define INIT_ARP 10

#define CORRECT_CS 0
#define DEFAULT_TTL 64
#define COPY_BYTES 8

#define ARP_TYPE 0x0806
#define IP_TYPE 0x0800

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_ETHER 1

#define IP_ICMP 1
#define ICMP_ECHOREQUEST 8
#define ICMP_ECHOREPLY 0
#define ICMP_ECHOREPLYCODE 0
#define ICMP_TIMEEXCEEDED 11
#define ICMP_TIMEEXCEEDEDCODE 0
#define DEST_UNREACHABLE 3
#define NET_UNREACHABLE 0

#define HLEN 6
#define PLEN 4

struct pkt
{
	char buf[MAX_PACKET_LEN];
	int len;
}__attribute__((packed));

struct route_table_entry *best_rentry(uint32_t ip, int rt_len, struct route_table_entry *route_table)
{
	int left = 0;
	int right = rt_len;
	struct route_table_entry *best_match = NULL;

	while (left <= right)
	{
		int mid = left + ((right - left) >> 1);
		if (route_table[mid].prefix == (ip & route_table[mid].mask))
		{
			best_match = &route_table[mid];
			left = mid + 1;
		}
		else
		{
			if (ntohl(route_table[mid].prefix) < ntohl(ip))
			{
				left = mid + 1;
			}
			else
			{
				right = mid - 1;
			}
		}
	}
	return best_match;
}

uint8_t *get_arp_entry(uint32_t ip, int arp_len, struct arp_entry *arp_table)
{
	int index = -1;
	for (int i = 0; i < arp_len; i++)
	{
		if (memcmp(&arp_table[i].ip, &ip, sizeof(ip)) == 0)
		{
			index = i;
			break;
		}
	}
	if (index == -1)
	{
		return NULL;
	}
	return arp_table[index].mac;
}

int rtable_compare(const void *first, const void *second)
{
	const struct route_table_entry *f_entry = (const struct route_table_entry *)first;
	const struct route_table_entry *s_entry = (const struct route_table_entry *)second;

	uint32_t f_prefix = ntohl(f_entry->prefix);
	uint32_t s_prefix = ntohl(s_entry->prefix);
	uint32_t f_mask = ntohl(f_entry->mask);
	uint32_t s_mask = ntohl(s_entry->mask);

	if (f_prefix == s_prefix)
	{
		if (f_mask == s_mask)
		{
			return 0;
		}
		else
		{
			return (f_mask > s_mask) ? 1 : -1;
		}
	}
	else
	{
		return (f_prefix > s_prefix) ? 1 : -1;
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	struct route_table_entry *route_table;
	int rt_len;

	struct arp_entry *arp_table;
	int arp_len;

	route_table = (struct route_table_entry *)malloc(INIT_RT * sizeof(struct route_table_entry));
	DIE(route_table == NULL, "route table memory");
	rt_len = read_rtable(argv[1], route_table);

	arp_table = (struct arp_entry *)malloc(INIT_ARP * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "arp table memory");
	arp_len = INIT_ARP;

	int current_arp_entry = 0;

	queue pkt_queue = queue_create();
	DIE(pkt_queue == NULL, "cannot create queue");

	qsort(route_table, rt_len, sizeof(struct route_table_entry), rtable_compare);

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1)
	{
		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);

		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		if (ntohs(eth_hdr->ether_type) == ARP_TYPE)
		{
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == ARP_REQUEST)
			{
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				eth_hdr->ether_type = htons(ARP_TYPE);

				arp_hdr->htype = htons(ARP_ETHER);
				arp_hdr->ptype = htons(IP_TYPE);
				arp_hdr->op = htons(ARP_REPLY);
				arp_hdr->hlen = HLEN;
				arp_hdr->plen = PLEN;

				memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(arp_hdr->sha));
				memcpy(arp_hdr->tha, eth_hdr->ether_dhost, sizeof(arp_hdr->tha));

				uint32_t tmp = arp_hdr->spa;
				arp_hdr->spa = arp_hdr->tpa;
				arp_hdr->tpa = tmp;

				send_to_link(interface, buf, len);

				continue;
			}

			if (ntohs(arp_hdr->op) == ARP_REPLY)
			{
				if (inet_addr(get_interface_ip(interface)) != arp_hdr->tpa)
				{

					struct route_table_entry *best_route = best_rentry(arp_hdr->tpa, rt_len, route_table);
					if (best_route == NULL)
					{
						continue;
					}

					send_to_link(best_route->interface, buf, len);
					continue;
				}

				if (get_arp_entry(arp_hdr->spa, current_arp_entry + 1, arp_table) == NULL)
				{
					memcpy(arp_table[current_arp_entry].mac, arp_hdr->sha, sizeof(arp_table[current_arp_entry].mac));
					arp_table[current_arp_entry].ip = arp_hdr->spa;
					current_arp_entry++;
				}
				if (current_arp_entry == arp_len)
				{
					arp_len *= 2;
					arp_table = (struct arp_entry *)realloc(arp_table, arp_len * sizeof(struct arp_entry));
					DIE(arp_table == NULL, "arp table memory realloc");
				}

				while (!queue_empty(pkt_queue))
				{
					struct pkt *pkt = (struct pkt *)queue_deq(pkt_queue);

					struct ether_header *eth_hdr_pkt = (struct ether_header *)pkt->buf;
					struct iphdr *ip_hdr_pkt = (struct iphdr *)(pkt->buf + sizeof(struct ether_header));
					struct route_table_entry *best_route = best_rentry(ip_hdr_pkt->daddr, rt_len, route_table);

					uint8_t *new_mac = get_arp_entry(best_route->next_hop, current_arp_entry + 1, arp_table);
					if (new_mac == NULL)
					{
						queue_enq(pkt_queue, pkt);
						continue;
					}

					memcpy(eth_hdr_pkt->ether_dhost, new_mac, sizeof(eth_hdr->ether_dhost));
					send_to_link(best_route->interface, pkt->buf, pkt->len);

					free(pkt);

					continue;
				}
			}
		}
		else if (ntohs(eth_hdr->ether_type) == IP_TYPE)
		{
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			uint32_t copy_dest_ip = ip_hdr->daddr;

			uint16_t old_cs = ip_hdr->check;

			uint16_t cs = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

			if (ntohs(cs) != CORRECT_CS)
			{
				continue;
			}

			if (ip_hdr->ttl <= 1)
			{
				char copy_bytes[COPY_BYTES];
				memcpy(copy_bytes, buf + sizeof(struct ether_header) + sizeof(struct iphdr), COPY_BYTES);

				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				icmp_hdr->type = ICMP_TIMEEXCEEDED;
				icmp_hdr->code = ICMP_TIMEEXCEEDEDCODE;

				struct iphdr *orig_ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
				uint8_t *icmp_data = (uint8_t *)icmp_hdr + sizeof(struct icmphdr);

				memcpy(icmp_data, orig_ip_hdr, sizeof(struct iphdr));
				memcpy(icmp_data + sizeof(struct iphdr), copy_bytes, COPY_BYTES);

				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + COPY_BYTES));

				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = copy_dest_ip;
				ip_hdr->ttl = DEFAULT_TTL;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + COPY_BYTES);
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(interface, eth_hdr->ether_shost);
				size_t new_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + COPY_BYTES;

				send_to_link(interface, buf, new_len);

				continue;
			}

			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)))
			{
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				if (icmp_hdr->type == ICMP_ECHOREQUEST)
				{
					icmp_hdr->type = ICMP_ECHOREPLY;
					icmp_hdr->code = ICMP_ECHOREPLYCODE;
					icmp_hdr->checksum = 0;
					int icmp_header_len = len - sizeof(struct ether_header) - sizeof(struct iphdr);
					icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, icmp_header_len));

					ip_hdr->daddr = ip_hdr->saddr;
					ip_hdr->saddr = copy_dest_ip;
					ip_hdr->ttl = DEFAULT_TTL;
					ip_hdr->check = 0;
					ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
					get_interface_mac(interface, eth_hdr->ether_shost);

					send_to_link(interface, buf, len);

					continue;
				}
			}

			ip_hdr->ttl--;

			uint16_t new_cs = ~(~old_cs + ~((uint16_t)(ip_hdr->ttl + 1)) + (uint16_t)(ip_hdr->ttl)) - 1;
			ip_hdr->check = new_cs;

			struct route_table_entry *best_route = best_rentry(ip_hdr->daddr, rt_len, route_table);
			if (best_route == NULL)
			{
				char copy_bytes[COPY_BYTES];
				memcpy(copy_bytes, buf + sizeof(struct ether_header) + sizeof(struct iphdr), COPY_BYTES);

				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				icmp_hdr->type = DEST_UNREACHABLE;
				icmp_hdr->code = NET_UNREACHABLE;

				struct iphdr *orig_ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
				uint8_t *icmp_data = (uint8_t *)icmp_hdr + sizeof(struct icmphdr);

				memcpy(icmp_data, orig_ip_hdr, sizeof(struct iphdr));
				memcpy(icmp_data + sizeof(struct iphdr), copy_bytes, COPY_BYTES);

				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + COPY_BYTES));

				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = copy_dest_ip;
				ip_hdr->ttl = DEFAULT_TTL;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + COPY_BYTES);
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				size_t new_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + COPY_BYTES;

				send_to_link(interface, buf, new_len);

				continue;
			}
			uint8_t *new_mac = get_arp_entry(best_route->next_hop, arp_len, arp_table);
			if (new_mac == NULL)
			{
				struct pkt *new_pkt = malloc(sizeof(struct pkt));

				memcpy(new_pkt->buf, buf, len);
				new_pkt->len = len;

				queue_enq(pkt_queue, new_pkt);

				struct pkt arp_pkt;
				unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

				struct arp_header new_arp_hdr;

				new_arp_hdr.htype = htons(ARP_ETHER);
				new_arp_hdr.ptype = htons(IP_TYPE);
				new_arp_hdr.op = htons(ARP_REQUEST);
				new_arp_hdr.hlen = HLEN;
				new_arp_hdr.plen = PLEN;
				eth_hdr->ether_type = htons(ARP_TYPE);

				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				get_interface_mac(best_route->interface, new_arp_hdr.sha);
				new_arp_hdr.spa = inet_addr(get_interface_ip(best_route->interface));

				memcpy(eth_hdr->ether_dhost, broadcast_mac, sizeof(eth_hdr->ether_dhost));
				memcpy(new_arp_hdr.tha, broadcast_mac, sizeof(broadcast_mac));
				new_arp_hdr.tpa = best_route->next_hop;

				memset(arp_pkt.buf, 0, MAX_PACKET_LEN);
				memcpy(arp_pkt.buf, eth_hdr, sizeof(struct ether_header));
				memcpy(arp_pkt.buf + sizeof(struct ether_header), &new_arp_hdr, sizeof(struct arp_header));

				send_to_link(best_route->interface, arp_pkt.buf, sizeof(struct ether_header) + sizeof(struct arp_header));

				continue;
			}

			memcpy(eth_hdr->ether_dhost, new_mac, sizeof(eth_hdr->ether_dhost));
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			send_to_link(best_route->interface, buf, len);
		}
	}
}
