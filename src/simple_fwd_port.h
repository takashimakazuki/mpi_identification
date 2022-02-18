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

#ifndef _SIMPLE_FWD_PORT_H_
#define _SIMPLE_FWD_PORT_H_

#define NUM_OF_PORTS (2)

struct simple_fwd_port_cfg
{
	uint16_t nb_desc;
	uint16_t port_id;
	uint16_t nb_queues;
	uint16_t is_hairpin;
};

int simple_fwd_start_dpdk_port(struct simple_fwd_port_cfg *port);

int simple_fwd_init_port(int port_id, int nr_queues);

void simple_fwd_close_port(int port_id);

#endif
