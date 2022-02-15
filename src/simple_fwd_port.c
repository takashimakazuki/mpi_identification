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
#include "simple_fwd_port.h"
#include "doca_log.h"
#include "doca_flow.h"

DOCA_LOG_REGISTER(SIMPLE_FWD_PORT);

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

void simple_fwd_hairpin_bind(void)
{
	rte_eth_hairpin_bind(0, 1);
	rte_eth_hairpin_bind(1, 0);
}

static void
simple_fwd_assert_link_status(int port_id)
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

int simple_fwd_start_dpdk_port(struct simple_fwd_port_cfg *port_info)
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
		nb_mbufs = NUM_OF_PORTS * nr_queues * 2048;
		mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
											nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
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
				 port_info->port_id, strerror(-ret));

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	DOCA_LOG_INFO("initializing port_info: %d", port_info->port_id);
	ret = rte_eth_dev_configure(port_info->port_id, total_queues,
								total_queues, &port_conf);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE,
				 ":: cannot configure device: err=%d, port_info=%u\n", ret,
				 port_info->port_id);
	}

	rx_queue_conf = dev_info.default_rxconf;
	rx_queue_conf.offloads = port_conf.rxmode.offloads;
	for (i = 0; i < total_queues; i++)
	{
		ret = rte_eth_rx_queue_setup(port_info->port_id, i, port_info->nb_desc,
									 rte_eth_dev_socket_id(port_info->port_id), &rx_queue_conf, mbuf_pool);
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE,
					 ":: Rx queue setup failed: err=%d, port_info=%u\n",
					 ret, port_info->port_id);
		}
	}

	tx_queue_conf = dev_info.default_txconf;
	tx_queue_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < total_queues; i++)
	{
		ret = rte_eth_tx_queue_setup(port_info->port_id, i, port_info->nb_desc,
									 rte_eth_dev_socket_id(port_info->port_id), &tx_queue_conf);
		if (ret < 0)
		{
			rte_exit(EXIT_FAILURE,
					 ":: Tx queue setup failed: err=%d, port_info=%u\n",
					 ret, port_info->port_id);
		}
	}

	ret = rte_eth_promiscuous_enable(port_info->port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				 ":: promiscuous mode enable failed: err=%s, port_info=%u\n",
				 rte_strerror(-ret), port_info->port_id);

	if (port_info->is_hairpin)
	{
		for (i = nr_queues, rxq = 0; i < total_queues; i++, rxq++)
		{
			hairpin_conf.peers[0].port = peer_port_id;
			hairpin_conf.peers[0].queue = nr_queues + rxq;
			hairpin_conf.manual_bind = 1;
			hairpin_conf.tx_explicit = 1;
			ret = rte_eth_rx_hairpin_queue_setup(port_info->port_id,
												 i, port_info->nb_desc, &hairpin_conf);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
						 "Hairpin rx setup failed:%d, port_info=%u\n",
						 ret, port_info->port_id);

			ret = rte_eth_tx_hairpin_queue_setup(port_info->port_id,
												 i, port_info->nb_desc, &hairpin_conf);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
						 "Hairpin tx setup failed:%d, port_info=%u\n",
						 ret, port_info->port_id);
		}
	}
	ret = rte_eth_dev_start(port_info->port_id);
	if (ret < 0)
	{
		rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_start:err=%d, port_info=%u\n",
				 ret, port_info->port_id);
	}
	simple_fwd_assert_link_status(port_info->port_id);
	DOCA_LOG_INFO("initializing port_info: %d done", port_info->port_id);
	return 0;
}

void simple_fwd_close_port(int port_id)
{
	struct rte_flow_error error;

	doca_flow_destroy_port(port_id);
	rte_flow_flush(port_id, &error);
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
}

static void
simple_fwd_port_stats_display(uint16_t port)
{
	uint32_t i;
	static uint64_t prev_pkts_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_pkts_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_ns[RTE_MAX_ETHPORTS];
	struct timespec cur_time;
	uint64_t diff_pkts_rx, diff_pkts_tx, diff_bytes_rx, diff_bytes_tx,
		diff_ns;
	uint64_t mpps_rx, mpps_tx, mbps_rx, mbps_tx;
	struct rte_eth_stats ethernet_stats;
	struct rte_eth_dev_info dev_info;
	static const char *nic_stats_border = "########################";

	rte_eth_stats_get(port, &ethernet_stats);
	rte_eth_dev_info_get(port, &dev_info);
	printf("\n  %s NIC statistics for port %-2d %s\n", nic_stats_border,
		   port, nic_stats_border);

	printf("  RX-packets: %-10" PRIu64 " RX-missed: %-10" PRIu64
		   " RX-bytes:  %-" PRIu64 "\n",
		   ethernet_stats.ipackets, ethernet_stats.imissed, ethernet_stats.ibytes);
	printf("  RX-errors: %-" PRIu64 "\n", ethernet_stats.ierrors);
	printf("  RX-nombuf:  %-10" PRIu64 "\n", ethernet_stats.rx_nombuf);
	printf("  TX-packets: %-10" PRIu64 " TX-errors: %-10" PRIu64
		   " TX-bytes:  %-" PRIu64 "\n",
		   ethernet_stats.opackets, ethernet_stats.oerrors, ethernet_stats.obytes);

	printf("\n");
	for (i = 0; i < dev_info.nb_rx_queues; i++)
	{
		printf("  ethernet_stats reg %2d RX-packets: %-10" PRIu64
			   "  RX-errors: %-10" PRIu64 "  RX-bytes: %-10" PRIu64 "\n",
			   i, ethernet_stats.q_ipackets[i], ethernet_stats.q_errors[i],
			   ethernet_stats.q_ibytes[i]);
	}

	printf("\n");
	for (i = 0; i < dev_info.nb_tx_queues; i++)
	{
		printf("  ethernet_stats reg %2d TX-packets: %-10" PRIu64
			   "  TX-bytes: %-10" PRIu64 "\n",
			   i, ethernet_stats.q_opackets[i], ethernet_stats.q_obytes[i]);
	}

	diff_ns = 0;
	if (clock_gettime(CLOCK_TYPE_ID, &cur_time) == 0)
	{
		uint64_t ns;

		ns = cur_time.tv_sec * NS_PER_SEC;
		ns += cur_time.tv_nsec;

		if (prev_ns[port] != 0)
			diff_ns = ns - prev_ns[port];
		prev_ns[port] = ns;
	}

	diff_pkts_rx = (ethernet_stats.ipackets > prev_pkts_rx[port])
					   ? (ethernet_stats.ipackets - prev_pkts_rx[port])
					   : 0;
	diff_pkts_tx = (ethernet_stats.opackets > prev_pkts_tx[port])
					   ? (ethernet_stats.opackets - prev_pkts_tx[port])
					   : 0;
	prev_pkts_rx[port] = ethernet_stats.ipackets;
	prev_pkts_tx[port] = ethernet_stats.opackets;
	mpps_rx = diff_ns > 0 ? (double)diff_pkts_rx / diff_ns * NS_PER_SEC : 0;
	mpps_tx = diff_ns > 0 ? (double)diff_pkts_tx / diff_ns * NS_PER_SEC : 0;

	diff_bytes_rx = (ethernet_stats.ibytes > prev_bytes_rx[port])
						? (ethernet_stats.ibytes - prev_bytes_rx[port])
						: 0;
	diff_bytes_tx = (ethernet_stats.obytes > prev_bytes_tx[port])
						? (ethernet_stats.obytes - prev_bytes_tx[port])
						: 0;
	prev_bytes_rx[port] = ethernet_stats.ibytes;
	prev_bytes_tx[port] = ethernet_stats.obytes;
	mbps_rx =
		diff_ns > 0 ? (double)diff_bytes_rx / diff_ns * NS_PER_SEC : 0;
	mbps_tx =
		diff_ns > 0 ? (double)diff_bytes_tx / diff_ns * NS_PER_SEC : 0;

	printf("\n  Throughput (since last show)\n");
	printf("  Rx-pps: %12" PRIu64 "          Rx-bps: %12" PRIu64
		   "\n  Tx-pps: %12" PRIu64 "          Tx-bps: %12" PRIu64 "\n",
		   mpps_rx, mbps_rx * 8, mpps_tx, mbps_tx * 8);

	printf("  %s############################%s\n", nic_stats_border,
		   nic_stats_border);
}

void simple_fwd_dump_port_stats(uint16_t port_id)
{
	const char clr[] = {27, '[', '2', 'J', '\0'};
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

	printf("%s%s", clr, topLeft);
	doca_flow_dump_pipe(port_id, stdout);
	simple_fwd_port_stats_display(port_id);
	fflush(stdout);
}
