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

#ifndef _SIMPLE_FWD_VNF_H_
#define _SIMPLE_FWD_VNF_H_

#include <stdint.h>
#include <stdbool.h>
#include <doca_flow.h>
#include "simple_fwd_pkt.h"
#include "simple_fwd_port.h"

#define SIMPLE_FWD_PORTS (2)
#define SIMPLE_FWD_MAX_FLOWS (8096)

struct simple_fwd_app {
	struct simple_fwd_ft *ft;
	struct doca_flow_port *port[SIMPLE_FWD_PORTS];
	struct doca_flow_pipe *pipe_vxlan[SIMPLE_FWD_PORTS];
	struct doca_flow_pipe *pipe_gre[SIMPLE_FWD_PORTS];
};

struct simple_fwd_pipe_entry {
	bool is_hw;
	uint64_t total_pkts;
	uint64_t total_bytes;
	struct doca_flow_pipe_entry *hw_entry;
};

struct app_vnf*
simple_fwd_get_doca_vnf(void);

#endif
