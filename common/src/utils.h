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

#ifndef UTILS_H
#define UTILS_H

#include "doca_log.h"
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define APP_EXIT(...)  				\
	do {					\
		DOCA_LOG_ERR( __VA_ARGS__);	\
		exit(1);			\
	} while (0)

void print_header_info(const struct rte_mbuf *packet, const bool l2, const bool l3, const bool l4);

void print_l2_header(const struct rte_mbuf *packet);

void print_l3_header(const struct rte_mbuf *packet);

void print_l4_header(const struct rte_mbuf *packet);

void set_time_stamp(struct tm *timeinfo);

#endif
