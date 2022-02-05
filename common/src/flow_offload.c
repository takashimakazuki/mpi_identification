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

#include <rte_sft.h>

#include "flow_offload.h"
#include "utils.h"

DOCA_LOG_REGISTER(FOFLD);

#define SFT_ZONE 0xcafe
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

#define MAX_PATTERN_NUM 5
#define MAX_ACTION_NUM 4
#define GROUP_POST_SFT 1001

enum POST_SFT_GROUP_PRIORITY {
	SET_STATE_PRIORITY,
	SFT_TO_RSS_PRIORITY,
};

enum PRE_SFT_GROUP_PRIORITY {
	JUMP_TO_SFT_PRIORITY = 0,
	HAIRPIN_NON_L4_PRIORITY = 3,
};

static struct rte_flow *jump_to_sft[8];
static struct rte_flow *query_hairpin[4];
static struct rte_flow *rss_non_state[2];
static struct rte_flow *hair_non_l4[2];

static struct rte_flow *
forward_fid_with_state(uint16_t port_id, uint16_t hairpin_queue, uint8_t sft_state,
	struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow_action_queue queue = { .index = hairpin_queue };
	struct rte_flow_item_sft sft_spec_and_mask = { .fid_valid = 1,
						       .state = sft_state };
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.priority = SET_STATE_PRIORITY;
	attr.group = GROUP_POST_SFT;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	if (sft_state == HAIRPIN_MATCHED_FLOW) {
		action[1].type = RTE_FLOW_ACTION_TYPE_QUEUE;
		action[1].conf = &queue;
	} else if (sft_state == DROP_FLOW)
		action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_SFT;
	pattern[0].mask = &sft_spec_and_mask;
	pattern[0].spec = &sft_spec_and_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	ret = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (ret == 0)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

static struct rte_flow *
rss_non_state_traffic(uint16_t port_id, struct rte_flow_action_rss *action_rss,
	struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.priority = SFT_TO_RSS_PRIORITY;
	attr.group = GROUP_POST_SFT;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_RSS;
	action[1].conf = action_rss;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ACTION_TYPE_VOID;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	ret = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (ret == 0)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

static struct rte_flow *
forward_l4_to_sft(uint8_t port_id, uint8_t l3_protocol, uint8_t l4_protocol,
	struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow_action_sft action_sft = { .zone = SFT_ZONE };
	struct rte_flow_action_jump action_jump = { .group = GROUP_POST_SFT };
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.group = 0;
	attr.priority = JUMP_TO_SFT_PRIORITY;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_SFT;
	action[1].conf = &action_sft;
	action[2].type = RTE_FLOW_ACTION_TYPE_JUMP;
	action[2].conf = &action_jump;
	action[3].type = RTE_FLOW_ACTION_TYPE_END;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	if (l3_protocol != IPPROTO_IPV6)
		pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	else
		pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
	if (l4_protocol == IPPROTO_UDP)
		pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	else
		pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[3].type = RTE_FLOW_ACTION_TYPE_END;

	ret = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (ret == 0)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

static struct rte_flow *
hairpin_non_l4_packets(uint16_t port_id, uint16_t hairpin_queue, struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow_action_queue queue = { .index = hairpin_queue };
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.group = 0;
	attr.priority = HAIRPIN_NON_L4_PRIORITY;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[1].conf = &queue;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	ret = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (ret == 0)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

int
enable_hairpin_queues(uint16_t port_id, uint16_t *peer_ports, uint16_t peer_ports_len)
{
	/* Configure the Rx and Tx hairpin queues for the selected port. */
	int ret;
	uint16_t peer_port;

	ret = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, peer_ports_len, 1);
	if (ret < 0)
		return ret;
	for (peer_port = 0; peer_port < peer_ports_len; peer_port++)
		ret = rte_eth_hairpin_bind(port_id, peer_ports[peer_port]);
			if (ret < 0)
				return ret;
	/* bind all peer Tx to current Rx */
	ret = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, peer_ports_len, 0);
	if (ret < 0)
		return ret;
	for (peer_port = 0; peer_port < peer_ports_len; peer_port++)
		ret = rte_eth_hairpin_bind(port_id, peer_ports[peer_port]);
			if (ret < 0)
				return ret;
	return 0;
}

static int
setup_hairpin_queues(uint16_t port_id, uint16_t peer_port_id, uint16_t reserved_hairpin_queue)
{
	/* Port:
	 *	0. RX queue
	 *	1. RX hairpin queue rte_eth_rx_hairpin_queue_setup
	 *	2. TX hairpin queue rte_eth_tx_hairpin_queue_setup
	 */

	int ret;
	uint16_t nb_tx_rx_desc = 2048;
	uint32_t manual = 1;
	uint32_t tx_exp = 1;
	struct rte_eth_hairpin_conf hairpin_conf = { .peer_count = 1, };

	//RX
	hairpin_conf.peers[0].port = peer_port_id;
	hairpin_conf.peers[0].queue = reserved_hairpin_queue;
	hairpin_conf.manual_bind = !!manual;
	hairpin_conf.tx_explicit = !!tx_exp;
	ret = rte_eth_tx_hairpin_queue_setup(port_id, reserved_hairpin_queue,
				nb_tx_rx_desc, &hairpin_conf);
	if (ret != 0)
		return ret;
	//TX
	hairpin_conf.peers[0].port = peer_port_id;
	hairpin_conf.peers[0].queue = reserved_hairpin_queue;
	hairpin_conf.manual_bind = !!manual;
	hairpin_conf.tx_explicit = !!tx_exp;
	ret = rte_eth_rx_hairpin_queue_setup(port_id, reserved_hairpin_queue,
				nb_tx_rx_desc, &hairpin_conf);
	if (ret != 0)
		return ret;
	return 0;
}

static void
haripin_traffic(uint8_t nb_ports, uint16_t reserved_hairpin_queue)
{
	uint16_t port_id;
	uint16_t peer_ports;
	struct rte_flow_error rte_error;

	/* Enable hairpin and create forwarding rule. */
	for (port_id = 0; port_id < nb_ports; port_id++) {
		if (enable_hairpin_queues(port_id, &peer_ports, 1) != 0)
			APP_EXIT("Hairpin bind failed");
		hair_non_l4[port_id] =
			hairpin_non_l4_packets(port_id, reserved_hairpin_queue, &rte_error);
		if (hair_non_l4[port_id] == NULL)
			APP_EXIT("Hairpin flow creation failed: %s", rte_error.message);
	}
}

void
dpdk_sft_init(bool ct, int nb_queues, unsigned int nb_ports)
{
	int ret = 0;
	uint8_t port_id = 0;
	uint8_t queue_index;
	uint8_t rss_key[40];
	uint16_t queue_list[nb_queues];
	struct rte_sft_conf sft_config = {
		.nb_queues = nb_queues,
		.nb_max_entries = 1<<20, /* This is max number of connections */
		.tcp_ct_enable = ct,
		.ipfrag_enable = 1,
		.reorder_enable = 1,
		.default_aging = 60,
		.nb_max_ipfrag = 4096,
		.app_data_len = 1,
	};
	struct rte_sft_error sft_error;
	struct rte_flow_error rte_error;
	struct rte_eth_rss_conf rss_conf = {
		.rss_key = rss_key,
		.rss_key_len = 40,
	};

	ret = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	if (ret != 0)
		APP_EXIT("Get port RSS configuration failed :ret=%d", ret);

	for (queue_index = 0; queue_index < nb_queues; queue_index++)
		queue_list[queue_index] = queue_index;

	struct rte_flow_action_rss action_rss = {
		.types = rss_conf.rss_hf,
		.key_len = rss_conf.rss_key_len,
		.queue_num = nb_queues,
		.key = rss_conf.rss_key,
		.queue = queue_list,
	};

	ret = rte_sft_init(&sft_config, &sft_error);
	if (ret < 0)
		APP_EXIT("SFT init failed");

	for (port_id = 0; port_id < nb_ports; port_id++) {
		jump_to_sft[port_id] =
			forward_l4_to_sft(port_id, IPPROTO_IP, IPPROTO_UDP, &rte_error);
		if (jump_to_sft[port_id] == NULL)
			APP_EXIT("Forward to SFT IPV4-UDP failed, error=%s", rte_error.message);
		jump_to_sft[port_id + 2] =
			forward_l4_to_sft(port_id, IPPROTO_IP, IPPROTO_TCP, &rte_error);
		if (jump_to_sft[port_id + 2] == NULL)
			APP_EXIT("Forward to SFT IPV4-TCP failed, error=%s", rte_error.message);
		jump_to_sft[port_id + 4] =
			forward_l4_to_sft(port_id, IPPROTO_IPV6, IPPROTO_UDP, &rte_error);
		if (jump_to_sft[port_id + 4] == NULL)
			APP_EXIT("Forward to SFT IPV6-UDP failed, error=%s", rte_error.message);
		jump_to_sft[port_id + 6] =
			forward_l4_to_sft(port_id, IPPROTO_IPV6, IPPROTO_TCP,  &rte_error);
		if (jump_to_sft[port_id + 6] == NULL)
			APP_EXIT("Forward to SFT IPV6-TCP failed, error=%s", rte_error.message);
		query_hairpin[port_id] =
			forward_fid_with_state(port_id, nb_queues, HAIRPIN_MATCHED_FLOW,
				&rte_error);
		if (query_hairpin[port_id] == NULL)
			APP_EXIT("Forward fid with state, error=%s", rte_error.message);
		query_hairpin[port_id + 2] =
			forward_fid_with_state(port_id, nb_queues, DROP_FLOW, &rte_error);
		if (query_hairpin[port_id + 2] == NULL)
			APP_EXIT("Forward fid with state, error=%s", rte_error.message);
		rss_non_state[port_id] = rss_non_state_traffic(port_id, &action_rss, &rte_error);
		if (rss_non_state[port_id] == NULL)
			APP_EXIT("SFT set fid failed, error=%s", rte_error.message);
	}
	haripin_traffic(nb_ports, nb_queues);
}

static struct rte_mempool *
allocate_mempool(uint8_t nb_ports, int nb_queues)
{
	struct rte_mempool *mbuf_pool;
	/* Creates a new mempool in memory to hold the mbufs */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports * nb_queues,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		APP_EXIT("Cannot allocate mbuf pool");
	return mbuf_pool;
}

static int
port_init(uint8_t port, struct rte_mempool *mbuf_pool, const uint8_t queues, bool hairpin)
{
	int ret;
	int symmetric_hash_key_length = 40;
	const uint8_t nb_ports = rte_eth_dev_count_avail();
	const uint16_t rx_rings = queues;
	const uint16_t tx_rings = queues;
	uint16_t q;
	struct rte_ether_addr addr;
	struct rte_eth_dev_info dev_info;
	uint8_t symmetric_hash_key[40] = {
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, };
	const struct rte_eth_conf port_conf_default = {
		.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN },
		.rx_adv_conf = {
			.rss_conf = {
			.rss_key_len = symmetric_hash_key_length,
			.rss_key = symmetric_hash_key,
			.rss_hf = ETH_RSS_PROTO_MASK,
			},
		},
	};
	struct rte_eth_conf port_conf = port_conf_default;

	if (!rte_eth_dev_is_valid_port(port))
		APP_EXIT("Invalid port");
	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0)
		APP_EXIT("Failed getting device (port %u) info, error=%s", port, strerror(-ret));
	if (port >= nb_ports)
		return -1;
	port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
	/* Configure the Ethernet device */
	ret = rte_eth_dev_configure(port, rx_rings + hairpin, tx_rings + hairpin, &port_conf);
	if (ret != 0)
		return ret;
	if (port_conf_default.rx_adv_conf.rss_conf.rss_hf !=
		port_conf.rx_adv_conf.rss_conf.rss_hf) {
		DOCA_LOG_DBG("Port %u modified RSS hash function based on hardware support, requested:%#"PRIx64" configured:%#"PRIx64"",
			port,
			port_conf_default.rx_adv_conf.rss_conf.rss_hf,
			port_conf.rx_adv_conf.rss_conf.rss_hf);
	}
	/* Enable RX in promiscuous mode for the Ethernet device */
	rte_eth_promiscuous_enable(port);
	/* Allocate and set up 1 RX queue per Ethernet port */
	for (q = 0; q < rx_rings; q++) {
		ret = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (ret < 0)
			return ret;
	}
	/* Allocate and set up 1 TX queue per Ethernet port */
	for (q = 0; q < tx_rings; q++) {
		ret = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (ret < 0)
			return ret;
	}
	/* Enabled hairpin queue before port start */
	if (hairpin) {
		ret = setup_hairpin_queues(port, port ^ 1, queues);
		if (ret != 0)
			APP_EXIT("Cannot hairpin port %"PRIu8 ", ret=%d", port, ret);
	}

	/* Start the Ethernet port */
	ret = rte_eth_dev_start(port);
	if (ret < 0)
		return ret;
	/* Display the port MAC address */
	rte_eth_macaddr_get(port, &addr);
	DOCA_LOG_DBG("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "",
		(unsigned int)port,
		addr.addr_bytes[0], addr.addr_bytes[1],
		addr.addr_bytes[2], addr.addr_bytes[3],
		addr.addr_bytes[4], addr.addr_bytes[5]);
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 && rte_eth_dev_socket_id(port) !=
		    (int)rte_socket_id()) {
			DOCA_LOG_INFO("WARNING, port %u is on remote NUMA node to polling thread",
				 port);
			DOCA_LOG_INFO("\tPerformance will not be optimal.");
		}
	return 0;
}

int
dpdk_ports_init(unsigned int nb_ports, int nb_queues)
{
	int ret;
	uint8_t port_id;
	struct rte_mempool *mbuf_pool;

	/* Initialize mbuf */
	mbuf_pool = allocate_mempool(nb_ports, nb_queues);

	/* Needed by SFT to mark packets */
	ret = rte_flow_dynf_metadata_register();
	if (ret < 0)
		APP_EXIT("Metadata register failed");

	for (port_id = 0; port_id < nb_ports; port_id++)
		if (port_init(port_id, mbuf_pool, nb_queues, true) != 0)
			APP_EXIT("Cannot init port %"PRIu8 "\n", port_id);
	return 0;
}

void
flow_offload_query_counters(void)
{
	struct rte_flow_action action[2];
	struct rte_flow_query_count count = {0};
	struct rte_flow_error rte_error;
	uint32_t total_ingress = 0;
	uint32_t total_egress = 0;
	uint32_t total_ingress_non_l4 = 0;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	DOCA_LOG_DBG("-------Jump to SFT--------");
	if (rte_flow_query(0, jump_to_sft[0], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("UDP Port 0- %d", count.hits);
	total_ingress += count.hits;
	if (rte_flow_query(1, jump_to_sft[1], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("UDP Port 1- %d", count.hits);
	total_ingress += count.hits;
	if (rte_flow_query(0, jump_to_sft[2], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("TCP Port 0- %d", count.hits);
	total_ingress += count.hits;
	if (rte_flow_query(1, jump_to_sft[3], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("TCP Port 1- %d", count.hits);
	total_ingress += count.hits;
	if (rte_flow_query(0, jump_to_sft[4], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("IPV6 UDP Port 0- %d", count.hits);
	total_ingress += count.hits;
	if (rte_flow_query(1, jump_to_sft[5], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("IPV6 UDP Port 1- %d", count.hits);
	total_ingress += count.hits;
	if (rte_flow_query(0, jump_to_sft[6], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("IPV6 TCP Port 0- %d", count.hits);
	total_ingress += count.hits;
	if (rte_flow_query(1, jump_to_sft[7], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("IPV6 TCP Port 1- %d", count.hits);
	total_ingress += count.hits;
	DOCA_LOG_DBG("-----Hairpin non L4 traffic-------");
	if (rte_flow_query(0, hair_non_l4[0], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("port 0 non l4 - %d", count.hits);
	total_ingress_non_l4 += count.hits;
	if (rte_flow_query(1, hair_non_l4[1], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("port 1 non l4 - %d", count.hits);
	total_ingress_non_l4 += count.hits;
	DOCA_LOG_DBG("----------- Hairpin using state post SFT --------------");
	if (rte_flow_query(0, query_hairpin[0], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	total_egress += count.hits;
	DOCA_LOG_DBG("Port 0 state hairpin - %d", count.hits);
	if (rte_flow_query(1, query_hairpin[1], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	total_egress += count.hits;
	DOCA_LOG_DBG("Port 1 state hairpin - %d", count.hits);
	if (rte_flow_query(0, query_hairpin[2], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("Port 0 state drop - %d", count.hits);
	if (rte_flow_query(1, query_hairpin[3], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	DOCA_LOG_DBG("Port 1 state drop - %d", count.hits);
	DOCA_LOG_DBG("---------------RSS post SFT-----------------");
	if (rte_flow_query(0, rss_non_state[0], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	total_egress += count.hits;
	DOCA_LOG_DBG("Port 0 non state rss - %d", count.hits);
	if (rte_flow_query(1, rss_non_state[1], &action[0], &count, &rte_error) != 0)
		APP_EXIT("query failed, error=%s", rte_error.message);
	total_egress += count.hits;
	DOCA_LOG_DBG("Port 1 non state rss - %d", count.hits);
	DOCA_LOG_DBG("-----------------------------------------------");
	DOCA_LOG_DBG("TOTAL INGRESS TRAFFIC:%d", total_ingress);
	DOCA_LOG_DBG("TOTAL EGRESS TRAFFIC:%d", total_egress);
	DOCA_LOG_DBG("TOTAL INGRESS NON_L4 TRAFFIC:%d", total_ingress_non_l4);
	DOCA_LOG_DBG("TOTAL DROPPED TRAFFIC:%d", total_ingress - total_egress);
}

void
dpdk_init(int *argc, char **argv[], unsigned int *nb_cores, unsigned int *nb_ports)
{
	int ret = 0;

	/* Initialize the Environment Abstraction Layer (EAL) */
	ret = rte_eal_init(*argc, *argv);
	if (ret < 0)
		APP_EXIT("EAL initialization failed");
	*argc -= ret;
	*argv += ret;

	/* EAL init also sets number of available cores */
	*nb_cores = rte_lcore_count();
	if (*nb_cores < 2)
		APP_EXIT("At least 2 Cores are a needed to run, available_cores=%d", *nb_cores);

	/* 1 Core is reserved to the main thread */
	// *nb_cores -= 1;

	/* Check that there are only 2 ports to send/receive on */
	*nb_ports = rte_eth_dev_count_avail();
	if (*nb_ports != 2)
		APP_EXIT("Application will only function with 2 ports, num_of_ports=%d", *nb_ports);
}
