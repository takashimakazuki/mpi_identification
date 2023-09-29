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
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <doca_log.h>
#include "mpiid_pkt.h"

DOCA_LOG_REGISTER(MPIID_PKT);

#define GTP_ESPN_FLAGS_ON(p) (p & 0x7)
#define GTP_EXT_FLAGS_ON(p) (p & 0x4)


static int mpiid_parse_pkt_format(uint8_t *data, int len, bool l2,
							struct mpiid_pkt_format *fmt)
{
	struct rte_ether_hdr *eth = NULL;
	struct rte_ipv4_hdr *iphdr;
	int l3_off = 0;
	int l4_off = 0;
	int l7_off = 0;

	fmt->l2 = data;
	if (l2)
	{
		eth = (struct rte_ether_hdr *)data;
		fmt->l2 = data;
		switch (rte_be_to_cpu_16(eth->ether_type))
		{
		case RTE_ETHER_TYPE_IPV4:
			l3_off = sizeof(struct rte_ether_hdr);
			break;
		case RTE_ETHER_TYPE_IPV6:
			l3_off = sizeof(struct rte_ether_hdr);
			fmt->l3_type = IPV6;
			return -1;
		case RTE_ETHER_TYPE_ARP:
			return -1;
		default:
			DOCA_LOG_WARN("unsupported l2 type %x",
				eth->ether_type);
			return -1;
		}
	}

	// 各レイヤの先頭をfmt変数に記録
	iphdr = (struct rte_ipv4_hdr *)(data + l3_off);
	if ((iphdr->version_ihl >> 4) != 4)
		return -1;
	if (iphdr->src_addr == 0 || iphdr->dst_addr == 0)
		return -1;
	fmt->l3 = (data + l3_off);
	fmt->l3_type = IPV4;
	l4_off = l3_off + rte_ipv4_hdr_len(iphdr);
	fmt->l4 = data + l4_off;

	switch (iphdr->next_proto_id)
	{
	case DOCA_PROTO_TCP:
	{
		struct rte_tcp_hdr *tcphdr =
			(struct rte_tcp_hdr *)(data + l4_off);

		l7_off = l4_off + ((tcphdr->data_off & 0xf0) >> 2);
		if (l7_off > len)
			return -1;
		fmt->l4_type = DOCA_PROTO_TCP;
		fmt->l7 = (data + l7_off);
		break;
	}
	case DOCA_PROTO_UDP:
	{
		struct rte_udp_hdr *udphdr =
			(struct rte_udp_hdr *)(data + l4_off);

		l7_off = l4_off + sizeof(*udphdr);
		fmt->l4_type = DOCA_PROTO_UDP;
		if (l7_off > len)
			return -1;
		fmt->l7 = (data + l7_off);
		break;
	}
	case DOCA_PROTO_GRE:
		fmt->l4_type = DOCA_PROTO_GRE;
		break;
	case IPPROTO_ICMP:
		fmt->l4_type = IPPROTO_ICMP;
		break;
	default:
		DOCA_LOG_INFO("unsupported l4 %d\n", iphdr->next_proto_id);
		return -1;
	}
	return 0;
}

/**
 * @brief - parse packet and put in packet info
 *
 * @param data    - packet raw data (including eth)
 * @param len     - len of the packet
 * @param pinfo   - extracted info is set here
 *
 * @return 0 on success and error otherwise.
 */
int mpiid_parse_packet(uint8_t *data, int len,
							struct mpiid_pkt_info *pinfo)
{
	if (!pinfo)
	{
		DOCA_LOG_ERR("pinfo =%p\n", pinfo);
		return -1;
	}
	pinfo->len = len;
	if (mpiid_parse_pkt_format(data, len, true, &pinfo->fmt))
		return -1;

	return 0;
}

