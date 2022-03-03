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

#ifndef _mpiid_PKT_H_
#define _mpiid_PKT_H_

#include <stdint.h>
#include <stdbool.h>
#include <doca_flow_net.h>

#define IPV4 (4)
#define IPV6 (6)

struct mpiid_pkt_format
{

	// 各レイヤデータの先頭
	uint8_t *l2;
	uint8_t *l3;
	uint8_t *l4;

	uint8_t l3_type;
	uint8_t l4_type;

	/* if tunnel it is the internal, if no tunnel then outer*/
	uint8_t *l7;
};

struct mpiid_pkt_tun_format
{
	doca_be32_t vni;
	bool l2;
	doca_be16_t proto;

	union
	{
		struct
		{
			uint8_t gtp_msg_type;
			uint8_t gtp_flags;
		};
	};
};

/**
 * @brief - packet parsing result.
 *  points to relevant point in packet and
 *  classify it.
 */
struct mpiid_pkt_info
{
	void *orig_data;
	uint16_t orig_port_id;
	uint32_t rss_hash;

	struct mpiid_pkt_format outer; // VXLANの外側のパケット
	enum doca_flow_tun_type tun_type;
	struct mpiid_pkt_tun_format tun;
	struct mpiid_pkt_format inner; // VXLANの内部パケット
	int len;
};

struct mpiid_ft_key
{
	doca_be32_t ipv4_1;
	doca_be32_t ipv4_2;
	doca_be16_t port_1;
	doca_be16_t port_2;
	doca_be32_t vni;
	uint8_t protocol;
	uint8_t tun_type;
	uint8_t pad[6];
	uint32_t rss_hash;
};

int mpiid_parse_packet(uint8_t *data,
							int len,
							struct mpiid_pkt_info *pinfo);

void mpiid_pinfo_decap(struct mpiid_pkt_info *pinfo);

#endif
