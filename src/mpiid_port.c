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

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include "mpiid_port.h"
#include "doca_log.h"
#include "doca_flow.h"

DOCA_LOG_REGISTER(mpiid_PORT);

#define CHECK_INTERVAL 1000 /* 100ms */
#define MAX_REPEAT_TIMES 90 /* 9s (90 * 100ms) in total */
#define NS_PER_SEC 1E9
#define MEMPOOL_CACHE_SIZE 256
#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif

struct rte_mempool *mbuf_pool;

static void
mpiid_assert_link_status(int port_id)
{
	struct rte_eth_link link;
	uint8_t rep_cnt = MAX_REPEAT_TIMES;
	int link_get_err = -EINVAL;

	memset(&link, 0, sizeof(link));
	do
	{
		link_get_err = rte_eth_link_get(port_id, &link);
		if (link_get_err == 0 && link.link_status == ETH_LINK_UP)
			break;
		rte_delay_ms(CHECK_INTERVAL);
	} while (--rep_cnt);

	if (link_get_err < 0)
		rte_exit(EXIT_FAILURE, ":: error: link get is failing: %s\n",
				 rte_strerror(-link_get_err));
	if (link.link_status == ETH_LINK_DOWN)
		rte_exit(EXIT_FAILURE, ":: error: link is still down\n");
}

int mpiid_start_dpdk_port(struct mpiid_port_cfg *port_info)
{
	int ret;
	uint16_t i, total_queues, rxq;
	uint16_t peer_port_id = !port_info->port_id;
	uint16_t nr_queues = port_info->nb_queues;
	unsigned int nb_mbufs;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
	};
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
		},
		.txmode = {
			.offloads = DEV_TX_OFFLOAD_VLAN_INSERT | DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_SCTP_CKSUM | DEV_TX_OFFLOAD_TCP_TSO,
		},
	};
	struct rte_eth_txconf tx_queue_conf;
	struct rte_eth_rxconf rx_queue_conf;
	struct rte_eth_dev_info dev_info;

	if (mbuf_pool == NULL)
	{
		// NOTE: define mbuf size and allocate mbuf_pool
		nb_mbufs = NUM_OF_PORTS * nr_queues * 2048;
		mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
											nb_mbufs,
											MEMPOOL_CACHE_SIZE,
											0,
											RTE_MBUF_DEFAULT_BUF_SIZE,
											rte_socket_id());
		if (mbuf_pool == NULL)
		{
			DOCA_LOG_CRIT("Cannot init mbuf pool");
			return -1;
		}
	}

	total_queues = nr_queues + port_info->is_hairpin;
	ret = rte_eth_dev_info_get(port_info->port_id, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				 "Error during getting device (port_info %u) info: %s\n",
				 port_info->port_id,
				 strerror(-ret));

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	DOCA_LOG_INFO("initializing port_info: %d", port_info->port_id);
	ret = rte_eth_dev_configure(port_info->port_id,
								total_queues,
								total_queues,
								&port_conf);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE, ":: cannot configure device: err=%d, port_info=%u\n", ret, port_info->port_id);
	}

	rx_queue_conf = dev_info.default_rxconf;
	rx_queue_conf.offloads = port_conf.rxmode.offloads;
	for (i = 0; i < total_queues; i++)
	{
		ret = rte_eth_rx_queue_setup(port_info->port_id,
									 i,
									 port_info->nb_desc,
									 rte_eth_dev_socket_id(port_info->port_id),
									 &rx_queue_conf, mbuf_pool);
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE,
					 ":: Rx queue setup failed: err=%d, port_info=%u\n",
					 ret,
					 port_info->port_id);
		}
	}

	tx_queue_conf = dev_info.default_txconf;
	tx_queue_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < total_queues; i++)
	{
		ret = rte_eth_tx_queue_setup(port_info->port_id,
									 i,
									 port_info->nb_desc,
									 rte_eth_dev_socket_id(port_info->port_id),
									 &tx_queue_conf);
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE,
					 ":: Tx queue setup failed: err=%d, port_info=%u\n",
					 ret,
					 port_info->port_id);
		}
	}

	ret = rte_eth_promiscuous_enable(port_info->port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				 ":: promiscuous mode enable failed: err=%s, port_info=%u\n",
				 rte_strerror(-ret),
				 port_info->port_id);

	if (port_info->is_hairpin)
	{
		for (i = nr_queues, rxq = 0; i < total_queues; i++, rxq++)
		{
			hairpin_conf.peers[0].port = peer_port_id;
			hairpin_conf.peers[0].queue = nr_queues + rxq;
			hairpin_conf.manual_bind = 1;
			hairpin_conf.tx_explicit = 1;
			ret = rte_eth_rx_hairpin_queue_setup(port_info->port_id,
												 i,
												 port_info->nb_desc,
												 &hairpin_conf);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
						 "Hairpin rx setup failed:%d, port_info=%u\n",
						 ret,
						 port_info->port_id);

			ret = rte_eth_tx_hairpin_queue_setup(port_info->port_id,
												 i, port_info->nb_desc,
												 &hairpin_conf);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
						 "Hairpin tx setup failed:%d, port_info=%u\n",
						 ret,
						 port_info->port_id);
		}
	}
	ret = rte_eth_dev_start(port_info->port_id);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_start:err=%d, port_info=%u\n",
				 ret,
				 port_info->port_id);
	}
	mpiid_assert_link_status(port_info->port_id);
	DOCA_LOG_INFO("initializing port_info: %d done", port_info->port_id);
	return 0;
}

void mpiid_close_port(int port_id)
{
	struct rte_flow_error error;

	doca_flow_destroy_port(port_id);
	rte_flow_flush(port_id, &error);
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
}
