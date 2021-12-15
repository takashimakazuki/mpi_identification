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

#ifndef _SIMPLE_FWD_FT_H_
#define _SIMPLE_FWD_FT_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <rte_mbuf.h>
#include "simple_fwd_pkt.h"

struct simple_fwd_ft;
struct simple_fwd_ft_key;

struct simple_fwd_ft_user_ctx
{
	uint32_t fid;
	uint8_t data[0];
};

#define simple_fwd_ft_key_get_ipv4_src(inner, pinfo) \
	(inner ? simple_fwd_pinfo_inner_ipv4_src(pinfo)  \
		   : simple_fwd_pinfo_outer_ipv4_src(pinfo))
#define simple_fwd_ft_key_get_ipv4_dst(inner, pinfo) \
	(inner ? simple_fwd_pinfo_inner_ipv4_dst(pinfo)  \
		   : simple_fwd_pinfo_outer_ipv4_dst(pinfo))
#define simple_fwd_ft_key_get_src_port(inner, pinfo) \
	(inner ? simple_fwd_pinfo_inner_src_port(pinfo)  \
		   : simple_fwd_pinfo_outer_src_port(pinfo))
#define simple_fwd_ft_key_get_dst_port(inner, pinfo) \
	(inner ? simple_fwd_pinfo_inner_dst_port(pinfo)  \
		   : simple_fwd_pinfo_outer_dst_port(pinfo))

/**
 * @brief - build table key according to parsed packet.
 *
 * @param m
 * @param key
 *
 * @return 0 on success
 */
int simple_fwd_ft_key_fill(struct simple_fwd_pkt_info *m,
						   struct simple_fwd_ft_key *key);

/**
 * @brief - compare keys
 *
 * @param key1
 * @param key2
 *
 * @return true if keys are equal.
 */
bool simple_fwd_ft_key_equal(struct simple_fwd_ft_key *key1,
							 struct simple_fwd_ft_key *key2);

/**
 * @brief - create new flow table
 *
 * @param size             - number of flows
 * @param user_data_size   - private data for user
 *
 * @return pointer to new allocated flow table or NULL
 */
struct simple_fwd_ft *
simple_fwd_ft_create(int size, uint32_t user_data_size,
					 void (*simple_fwd_aging_cb)(struct simple_fwd_ft_user_ctx *ctx),
					 void (*simple_fwd_aging_hw_cb)(void));

void simple_fwd_ft_destroy(struct simple_fwd_ft *ft);

bool simple_fwd_ft_add_new(struct simple_fwd_ft *ft,
						   struct simple_fwd_pkt_info *pinfo,
						   struct simple_fwd_ft_user_ctx **ctx);

bool simple_fwd_ft_find(struct simple_fwd_ft *ft,
						struct simple_fwd_pkt_info *pinfo,
						struct simple_fwd_ft_user_ctx **ctx);

int simple_fwd_ft_destroy_flow(struct simple_fwd_ft *ft,
							   struct simple_fwd_ft_key *key);

#endif
