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

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "doca_flow.h"
#include <doca_log.h>
#include "app_vnf.h"
#include "simple_fwd_ft.h"
#include "simple_fwd_vnf.h"

DOCA_LOG_REGISTER(SIMPLE_FWD_VNF);

static struct simple_fwd_app *simple_fwd_ins;
struct doca_flow_fwd *fwd_tbl_port[SIMPLE_FWD_PORTS];
struct doca_flow_fwd *sw_rss_fwd_tbl_port[SIMPLE_FWD_PORTS];

static void
simple_fwd_aged_flow_cb(struct simple_fwd_ft_user_ctx *ctx)
{
	struct simple_fwd_pipe_entry *entry =
		(struct simple_fwd_pipe_entry *)&ctx->data[0];

	if (entry->is_hw) {
		doca_flow_pipe_rm_entry(0, entry->hw_entry);
		entry->hw_entry = NULL;
	}
}

static int
simple_fwd_create(void)
{
	simple_fwd_ins = (struct simple_fwd_app *)malloc
		(sizeof(struct simple_fwd_app));
	if (simple_fwd_ins == NULL) {
		DOCA_LOG_CRIT("failed to allocate SF");
		goto fail_init;
	}
	memset(simple_fwd_ins, 0, sizeof(struct simple_fwd_app));
	simple_fwd_ins->ft = simple_fwd_ft_create(SIMPLE_FWD_MAX_FLOWS,
					sizeof(struct simple_fwd_pipe_entry),
					&simple_fwd_aged_flow_cb, NULL);
	if (simple_fwd_ins->ft == NULL) {
		DOCA_LOG_CRIT("failed to allocate FT");
		goto fail_init_ft;
	}
	return 0;
fail_init_ft:
	if (simple_fwd_ins != NULL)
		free(simple_fwd_ins);
	simple_fwd_ins = NULL;
fail_init:
	return -1;
}

static struct doca_flow_fwd*
simple_fwd_build_port_fwd(struct simple_fwd_port_cfg *port_cfg)
{
	struct doca_flow_fwd *fwd = malloc(sizeof(struct doca_flow_fwd));

	memset(fwd, 0, sizeof(struct doca_flow_fwd));
	fwd->type = DOCA_FLOW_FWD_PORT;
	fwd->port_id = port_cfg->port_id;
	return fwd;
}

static struct doca_flow_fwd*
simple_fwd_build_rss_fwd(int n_queues)
{
	int i;
	struct doca_flow_fwd *fwd = malloc(sizeof(struct doca_flow_fwd));
	uint16_t *queues;

	memset(fwd, 0, sizeof(struct doca_flow_fwd));
	queues = malloc(sizeof(uint16_t) * n_queues);
	for (i = 1; i < n_queues; i++)
		queues[i - 1] = i;
	fwd->type = DOCA_FLOW_FWD_RSS;
	fwd->rss_queues = queues;
	fwd->rss_flags = DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_UDP;
	fwd->num_of_queues = n_queues - 1;
	fwd->rss_mark = 5;
	return fwd;
}

struct doca_flow_port*
simple_fwd_init_doca_port(struct simple_fwd_port_cfg *port_cfg)
{
#define MAX_PORT_STR (128)
	char port_id_str[MAX_PORT_STR];
	struct doca_flow_port_cfg doca_cfg_port;
	struct doca_flow_port *port;
	struct doca_flow_error error = {0};

	snprintf(port_id_str, MAX_PORT_STR, "%d", port_cfg->port_id);
	doca_cfg_port.type = DOCA_FLOW_PORT_DPDK_BY_ID;
	doca_cfg_port.devargs = port_id_str;
	doca_cfg_port.priv_data_size = sizeof(struct simple_fwd_port_cfg);

	if (port_cfg->port_id >= SIMPLE_FWD_PORTS) {
		DOCA_LOG_ERR("port id exceeds max ports id:%d",
			SIMPLE_FWD_PORTS);
		return NULL;
	}
	port = doca_flow_port_start(&doca_cfg_port, &error);
	if (port == NULL) {
		DOCA_LOG_ERR("failed to start port %s", error.message);
		return NULL;
	}

	*((struct simple_fwd_port_cfg *)doca_flow_port_priv_data(port)) =
		*port_cfg;
	sw_rss_fwd_tbl_port[port_cfg->port_id] =
	    simple_fwd_build_rss_fwd(port_cfg->nb_queues);

	fwd_tbl_port[port_cfg->port_id] = simple_fwd_build_port_fwd(port_cfg);
	return port;
}

static struct simple_fwd_port_cfg*
simple_fwd_get_port_cfg(struct doca_flow_port *port)
{
	return (struct simple_fwd_port_cfg *)
		doca_flow_port_priv_data(port);
}

static struct doca_flow_fwd*
simple_fwd_get_fwd(struct simple_fwd_port_cfg *port_cfg)
{
	uint16_t port_id = port_cfg->port_id;

	if (port_cfg->is_hairpin)
		return fwd_tbl_port[!port_id];
	else
		return sw_rss_fwd_tbl_port[port_id];
}

static struct doca_flow_pipe*
simple_fwd_build_vxlan_pipe(struct doca_flow_port *port)
{
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct simple_fwd_port_cfg *port_cfg;
	struct doca_flow_monitor monitor = {0};
	struct doca_flow_actions actions = {0};
	struct doca_flow_match match = {0};
	struct doca_flow_error error = {0};
	struct doca_flow_fwd *fwd;

	port_cfg = simple_fwd_get_port_cfg(port);

	/* build match part */
	match.out_dst_ip.ipv4_addr = 0xffffffff;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = IPPROTO_UDP;
	match.out_dst_port = rte_cpu_to_be_16(DOCA_VXLAN_DEFAULT_PORT);
	match.tun.type = DOCA_FLOW_TUN_VXLAN;
	match.tun.vxlan_tun_id = 0xffffffff;
	match.in_dst_ip.ipv4_addr = 0xffffffff;
	match.in_src_ip.ipv4_addr = 0xffffffff;
	match.in_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_l4_type = IPPROTO_TCP;
	match.in_src_port = 0xffff;
	match.in_dst_port = 0xffff;

	/* build action part */
	actions.decap = true;
	actions.mod_dst_ip.ipv4_addr = 0xffffffff;
	if (port_cfg->is_hairpin)
		actions.has_encap = true;

	/* build monitor part */
	monitor.flags = DOCA_FLOW_MONITOR_COUNT;
	monitor.flags |= DOCA_FLOW_MONITOR_METER;
	monitor.cir = 1000000 * 1000 / 8;
	monitor.cbs = monitor.cir / 8;

	/* build fwd part */
	fwd = simple_fwd_get_fwd(port_cfg);

	/* create pipe */
	pipe_cfg.name = "VXLAN_FWD";
	pipe_cfg.port = port;
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;
	pipe_cfg.monitor = &monitor;

	return doca_flow_create_pipe(&pipe_cfg, fwd, &error);
}

static struct doca_flow_pipe*
simple_fwd_build_gre_pipe(struct doca_flow_port *port)
{
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct doca_flow_actions actions = {0};
	struct doca_flow_match match = {0};
	struct doca_flow_error error = {0};

	/* build match part */
	match.out_dst_ip.ipv4_addr = 0xffffffff;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = IPPROTO_GRE;
	match.tun.type = DOCA_FLOW_TUN_GRE;
	match.tun.gre_key = 0xffffffff;
	match.in_dst_ip.ipv4_addr = 0xffffffff;
	match.in_src_ip.ipv4_addr = 0xffffffff;
	match.in_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_l4_type = IPPROTO_TCP;
	match.in_src_port = 0xffff;
	match.in_dst_port = 0xffff;

	/* build action part */
	actions.decap = true;
	actions.mod_dst_ip.ipv4_addr = 0xffffffff;

	/* create pipe */
	pipe_cfg.name = "GRE_FWD";
	pipe_cfg.port = port;
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;

	return doca_flow_create_pipe(&pipe_cfg, NULL, &error);
}

static int
simple_fwd_init_ports_and_pipes(struct simple_fwd_port_cfg *port_cfg)
{
	struct doca_flow_error error = {0};
	struct doca_flow_port *port;
	struct doca_flow_pipe *pipe;
	struct doca_flow_cfg cfg = {
		.total_sessions = SIMPLE_FWD_MAX_FLOWS,
		.queues = port_cfg->nb_queues,
		.is_hairpin = port_cfg->is_hairpin,
	};
	int index;

	if (doca_flow_init(&cfg, &error)) {
		DOCA_LOG_ERR("failed to init doca:%s", error.message);
		return -1;
	}
	/* build doca port */
	for (index = 0; index < SIMPLE_FWD_PORTS; index++) {
		port_cfg->port_id = index;
		port = simple_fwd_init_doca_port(port_cfg);
		if (port == NULL) {
			DOCA_LOG_ERR("failed to start port %d %s",
				index, error.message);
			return -1;
		}
		simple_fwd_ins->port[index] = port;
	}

	/* build pipe on each port */
	for (index = 0; index < SIMPLE_FWD_PORTS; index++) {
		port = simple_fwd_ins->port[index];
		pipe = simple_fwd_build_gre_pipe(port);
		if (pipe == NULL)
			return -1;
		simple_fwd_ins->pipe_gre[index] = pipe;
		pipe = simple_fwd_build_vxlan_pipe(port);
		if (pipe == NULL)
			return -1;
		simple_fwd_ins->pipe_vxlan[index] = pipe;
	}
	return 0;
}

static int
simple_fwd_init(void *p)
{
	struct simple_fwd_port_cfg *port_cfg;
	int ret = 0;

	ret = simple_fwd_create();
	if (ret)
		return ret;

	port_cfg = (struct simple_fwd_port_cfg *)p;
	return simple_fwd_init_ports_and_pipes(port_cfg);
}

struct doca_flow_pipe_entry*
simple_fwd_pipe_add_entry(struct doca_flow_pipe *pipe,
			  struct simple_fwd_pkt_info *pinfo,
			  struct doca_flow_fwd *fwd)
{
	struct doca_flow_match match;
	struct doca_flow_monitor mon = {0};
	struct doca_flow_actions actions = {0};
	struct doca_flow_error error = {0};

	if (pinfo->outer.l3_type != IPV4) {
		DOCA_LOG_WARN("IPv6 not supported");
		return NULL;
	}

	if (pinfo->tun_type != DOCA_FLOW_TUN_VXLAN
		&& pinfo->inner.l4_type != IPPROTO_TCP)
		return NULL;

	memset(&match, 0x0, sizeof(match));
	/* exact outer 5-tuple */
	match.out_dst_ip.ipv4_addr = simple_fwd_pinfo_outer_ipv4_dst(pinfo);
	match.out_l4_type = pinfo->outer.l4_type;
	match.tun.vxlan_tun_id = pinfo->tun.vni;
	match.in_dst_ip.ipv4_addr =
		simple_fwd_pinfo_inner_ipv4_dst(pinfo);
	match.in_src_ip.ipv4_addr =
		simple_fwd_pinfo_inner_ipv4_src(pinfo);
	match.in_l4_type = pinfo->inner.l4_type;
	match.in_src_port = simple_fwd_pinfo_inner_src_port(pinfo);
	match.in_dst_port = simple_fwd_pinfo_inner_dst_port(pinfo);

	actions.has_encap = true;
	actions.encap.src_ip.type = DOCA_FLOW_IP4_ADDR;
	actions.encap.src_ip.ipv4_addr =
		simple_fwd_pinfo_outer_ipv4_dst(pinfo);
	actions.encap.dst_ip.ipv4_addr =
		simple_fwd_pinfo_outer_ipv4_src(pinfo);
	memset(actions.encap.src_mac, 0xaa, sizeof(actions.encap.src_mac));
	memset(actions.encap.dst_mac, 0xbb, sizeof(actions.encap.src_mac));
	actions.encap.tun.type = pinfo->tun_type;
	if (pinfo->tun_type == DOCA_FLOW_TUN_VXLAN)
		actions.encap.tun.vxlan_tun_id = 0x42;
	actions.mod_dst_ip.ipv4_addr =
		(simple_fwd_pinfo_inner_ipv4_dst(pinfo)
	    & rte_cpu_to_be_32(0x00ffffff)) |
	    rte_cpu_to_be_32(0x25000000);
	mon.flags |= DOCA_FLOW_MONITOR_COUNT;
	return doca_flow_pipe_add_entry(0, pipe, &match, &actions, &mon,
		fwd, &error);
}

static int
simple_fwd_handle_new_flow(struct simple_fwd_pkt_info *pinfo,
			   struct simple_fwd_ft_user_ctx **ctx)
{
	struct simple_fwd_pipe_entry *entry = NULL;
	struct doca_flow_pipe *pipe;
	struct doca_flow_fwd *fwd = NULL;

	if ((pinfo->outer.l4_type != IPPROTO_TCP) &&
		(pinfo->outer.l4_type != IPPROTO_UDP) &&
		(pinfo->outer.l4_type != IPPROTO_GRE))
		return -1;

	if (pinfo->tun_type == DOCA_FLOW_TUN_VXLAN)
		pipe = simple_fwd_ins->pipe_vxlan[pinfo->orig_port_id];
	else if (pinfo->tun_type == DOCA_FLOW_TUN_GRE) {
		struct doca_flow_port *port;
		struct simple_fwd_port_cfg *port_cfg;

		port = simple_fwd_ins->port[pinfo->orig_port_id];
		port_cfg = simple_fwd_get_port_cfg(port);
		fwd = simple_fwd_get_fwd(port_cfg);
		pipe = simple_fwd_ins->pipe_gre[pinfo->orig_port_id];
	} else
		return -1;

	if (!simple_fwd_ft_add_new(simple_fwd_ins->ft, pinfo, ctx)) {
		DOCA_LOG_DBG("failed create new entry");
		return -1;
	}
	entry = (struct simple_fwd_pipe_entry *)&(*ctx)->data[0];
	entry->hw_entry = simple_fwd_pipe_add_entry(pipe, pinfo, fwd);
	if (entry->hw_entry == NULL) {
		DOCA_LOG_DBG("failed to offload");
		return -1;
	}
	entry->is_hw = true;
	return 0;
}

static int
simple_fwd_handle_packet(struct simple_fwd_pkt_info *pinfo)
{
	struct simple_fwd_ft_user_ctx *ctx = NULL;
	struct simple_fwd_pipe_entry *entry = NULL;

	if (!simple_fwd_ft_find(simple_fwd_ins->ft, pinfo, &ctx)) {
		if (simple_fwd_handle_new_flow(pinfo, &ctx))
			return -1;
	}
	entry = (struct simple_fwd_pipe_entry *)&ctx->data[0];
	entry->total_pkts++;
	return 0;
}

static int
simple_fwd_destroy(void)
{
	doca_flow_destroy();
	if (simple_fwd_ins != NULL) {
		if (simple_fwd_ins->ft != NULL)
			free(simple_fwd_ins->ft);
		free(simple_fwd_ins);
		simple_fwd_ins = NULL;
	}
	return 0;
}

struct app_vnf simple_fwd_vnf = {
	.vnf_init = &simple_fwd_init,
	.vnf_process_pkt = &simple_fwd_handle_packet,
	.vnf_destroy = &simple_fwd_destroy,
};

struct app_vnf *simple_fwd_get_doca_vnf(void)
{
	return &simple_fwd_vnf;
}
