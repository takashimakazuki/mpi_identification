/*
 * Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <rte_ether.h>
#include <rte_ethdev.h>

#include "utils.h"

DOCA_LOG_REGISTER(UTILS);

void
print_header_info(const struct rte_mbuf *packet, const bool l2, const bool l3, const bool l4)
{
	print_l2_header(packet);
	print_l3_header(packet);
	print_l4_header(packet);
}

void
print_ether_addr(const struct rte_ether_addr *dmac, const struct rte_ether_addr *smac,
		 const uint32_t ethertype)
{
	char dmac_buf[RTE_ETHER_ADDR_FMT_SIZE];
	char smac_buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(dmac_buf, RTE_ETHER_ADDR_FMT_SIZE, dmac);
	rte_ether_format_addr(smac_buf, RTE_ETHER_ADDR_FMT_SIZE, smac);
	DOCA_LOG_DBG("DMAC=%s, SMAC=%s, ether_type=0x%04x", dmac_buf, smac_buf, ethertype);
}

void
print_l2_header(const struct rte_mbuf *packet)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);

	print_ether_addr(&eth_hdr->d_addr, &eth_hdr->s_addr, htonl(eth_hdr->ether_type) >> 16);
}

void
print_ipv4_addr(const rte_be32_t dip, const rte_be32_t sip, const char *packet_type)
{
	DOCA_LOG_DBG("DIP=%d.%d.%d.%d, SIP=%d.%d.%d.%d, %s",
		(dip & 0xff000000)>>24,
		(dip & 0x00ff0000)>>16,
		(dip & 0x0000ff00)>>8,
		(dip & 0x000000ff),
		(sip & 0xff000000)>>24,
		(sip & 0x00ff0000)>>16,
		(sip & 0x0000ff00)>>8,
		(sip & 0x000000ff),
		 packet_type);
}

void
print_l3_header(const struct rte_mbuf *packet)
{
	if (!RTE_ETH_IS_IPV4_HDR(packet->packet_type))
		return;

	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(packet,
		struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

	print_ipv4_addr(htonl(ipv4_hdr->dst_addr), htonl(ipv4_hdr->src_addr),
			rte_get_ptype_l4_name(packet->packet_type));
}

void
print_l4_header(const struct rte_mbuf *packet)
{
	uint8_t *l4_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	const struct rte_tcp_hdr *tcp_hdr;
	const struct rte_udp_hdr *udp_hdr;

	if (!RTE_ETH_IS_IPV4_HDR(packet->packet_type))
		return;

	ipv4_hdr = rte_pktmbuf_mtod_offset(packet,
		struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	l4_hdr = (typeof(l4_hdr))ipv4_hdr + rte_ipv4_hdr_len(ipv4_hdr);

	switch (ipv4_hdr->next_proto_id) {
	case IPPROTO_UDP:
		udp_hdr = (typeof(udp_hdr))l4_hdr;
		DOCA_LOG_DBG("UDP- DPORT %u, SPORT %u",
			rte_be_to_cpu_16(udp_hdr->dst_port),
			rte_be_to_cpu_16(udp_hdr->src_port));
	break;

	case IPPROTO_TCP:
		tcp_hdr = (typeof(tcp_hdr))l4_hdr;
		DOCA_LOG_DBG("TCP- DPORT %u, SPORT %u",
			rte_be_to_cpu_16(tcp_hdr->dst_port),
			rte_be_to_cpu_16(tcp_hdr->src_port));
	break;

	default:
		DOCA_LOG_DBG("Unsupported L4 protocol!");
	}
}
