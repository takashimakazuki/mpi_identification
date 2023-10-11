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

// 実行コマンド
// sudo ./mpiid -a auxiliary:mlx5_core.sf.4 -a auxiliary:mlx5_core.sf.5 -- --nr_queues=4 --stats_timer=2 --log_level=8

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <doca_flow.h>
#include <doca_log.h>
#include "flow_offload.h"
#include "utils.h"
#include "app_vnf.h"
#include "mpiid_port.h"
#include "mpiid_pkt.h"
#include "mpiid_timer_cb.h"

#include "mpi.h"
#include "mpidpre.h"
#include "mpidpkt.h"
#include "mpir_tags.h"
#include "logger.h"

DOCA_LOG_REGISTER(MPIID);

// #define DEBUG

// 計測用の変数
static uint64_t timer_resolution_cycles;
static struct rte_timer timers[RTE_MAX_LCORE];
__thread uint32_t processed_bytes = 0;
__thread uint32_t processed_pkts = 0;
__thread uint32_t enqueued_pkts = 0;
__thread uint32_t enqueued_bytes = 0;
__thread uint32_t rx_bytes = 0;
__thread uint32_t tx_bytes = 0;


uint16_t nr_queues = 4;
uint16_t nr_desc = 512;
static volatile bool force_quit;

// 論理コアごとの設定項目
struct vnf_per_core_params
{
	int ports[NUM_OF_PORTS];
	int queues[NUM_OF_PORTS];
	int core_id;
	bool used;
	struct rte_ring *ring; // スレッド間でのパケット受け渡しを行うRingキュー
};
struct vnf_per_core_params core_params_arr[RTE_MAX_LCORE];

struct rte_hash *hash;
struct rte_hash_parameters params;


void get_ipv4_addr(const rte_be32_t dip, const rte_be32_t sip, char *buf)
{
	sprintf(buf, "DIP=%d.%d.%d.%d, SIP=%d.%d.%d.%d",
			(dip & 0xff000000) >> 24,
			(dip & 0x00ff0000) >> 16,
			(dip & 0x0000ff00) >> 8,
			(dip & 0x000000ff),
			(sip & 0xff000000) >> 24,
			(sip & 0x00ff0000) >> 16,
			(sip & 0x0000ff00) >> 8,
			(sip & 0x000000ff));
}

char* parse_ip_packet(struct rte_ipv4_hdr *iph)
{
	char* log_buf = (char *) rte_malloc(NULL, 1024 * sizeof(char), 0);
	sprintf(log_buf + strlen(log_buf), "IP Version: %d\n", (unsigned int)iph->version);
    sprintf(log_buf + strlen(log_buf), "IP Header Length: %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
    sprintf(log_buf + strlen(log_buf), "IP Total Length: %d  Bytes(Size of Packet)\n",ntohs(iph->total_length));
    sprintf(log_buf + strlen(log_buf), "Identification: %d\n", ntohs(iph->packet_id));
    sprintf(log_buf + strlen(log_buf), "Protocol: %d\n", (unsigned int)iph->next_proto_id);
    sprintf(log_buf + strlen(log_buf), "Checksum: %d\n", ntohs(iph->hdr_checksum));
    sprintf(log_buf + strlen(log_buf), "Source Adddress: %.4x\n", iph->src_addr);
    sprintf(log_buf + strlen(log_buf), "Destination Adddress: %.4x\n", iph->dst_addr);
    sprintf(log_buf + strlen(log_buf), "Fragment Offset:  %d\n", iph->fragment_offset);
	
	sprintf(log_buf + strlen(log_buf), "=================================\n");
	return log_buf;
}

char *mpifunc_strings[11] = {
	"",
	"MPI_SEND",
	"MPIR_BCAST_TAG",
	"MPIR_GATHER_TAG",
	"MPIR_GATHERV_TAG",
 	"MPIR_SCATTER_TAG",
	"MPIR_SCATTERV_TAG",
	"MPIR_ALLGATHER_TAG", 
	"MPIR_ALLGATHERV_TAG",
	"MPIR_ALLTOALL_TAG",
	"MPIR_ALLTOALLV_TAG",
};

char *get_mpifunc_string(int32_t tag)
{
	if (tag < 2 || tag > 11) {
		return mpifunc_strings[1];
	}
	return mpifunc_strings[(int)tag];
}

struct tcp_flow_tuple4 {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
};

static struct rte_hash_parameters ut_params = {
	.name = "mpiflowhash",
	.entries = 16,
	.key_len = sizeof(struct tcp_flow_tuple4),
	.hash_func = NULL,
	.hash_func_init_val = 0,
	.socket_id = 0,
};

__thread struct rte_hash *handle;

int create_mpi_flow_hash()
{
	handle = rte_hash_create(&ut_params);
	if (handle == NULL) {
		DOCA_DLOG_ERR("failed to create rte_hash");
		return -1;
	}

	return 0;
}

int32_t add_mpi_flow(uint32_t saddr, uint32_t daddr, uint16_t src_port, uint16_t dst_port)
{
	if (handle == NULL) {
		DOCA_DLOG_ERR("rte_hash is not created");
		return -1;
	}

	struct tcp_flow_tuple4 tuple = {
		.ip_src = saddr,
		.ip_dst = daddr,
		.port_src = src_port,
		.port_dst = dst_port,
	};
	return rte_hash_add_key(handle, &tuple);
}

int32_t lookup_mpi_flow(uint32_t saddr, uint32_t daddr, uint16_t src_port, uint16_t dst_port)
{
	if (handle == NULL) {
		DOCA_DLOG_ERR("rte_hash is not created");
		return -1;
	}

	struct tcp_flow_tuple4 tuple = {
		.ip_src = saddr,
		.ip_dst = daddr,
		.port_src = src_port,
		.port_dst = dst_port,
	};
	return rte_hash_lookup(handle, &tuple);
}

int32_t delete_mpi_flow(uint32_t saddr, uint32_t daddr, uint16_t src_port, uint16_t dst_port)
{
	if (handle == NULL) {
		DOCA_DLOG_ERR("rte_hash is not created");
		return -1;
	}
	struct tcp_flow_tuple4 tuple = {
		.ip_src = saddr,
		.ip_dst = daddr,
		.port_src = src_port,
		.port_dst = dst_port,
	};
	return rte_hash_del_key(handle, &tuple);
}

const char pattern[5] = "kvs_";

void analyze_packets(struct mpiid_pkt_info *pinfo)
{
	MPIDI_CH3_Pkt_t *pkt;
	struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)pinfo->fmt.l4;
	struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)pinfo->fmt.l3;
	// TCPペイロードの先頭ポインタ
	uint8_t *tcp_payload = pinfo->fmt.l7;

	if (iph->next_proto_id != IPPROTO_TCP) 
	{
		return;
	}

	// MPICH kvm message
	if (strncmp((char *)&(tcp_payload[MPI_PKT_KVS_STR_OFFSET]), pattern, 4))
	{
		add_mpi_flow(iph->src_addr, iph->dst_addr, tcph->src_port, tcph->dst_port);
		add_mpi_flow(iph->dst_addr, iph->src_addr, tcph->dst_port, tcph->src_port);
	} else {
		return;
	}

	// Check if this packet is mpi flow. if the packet is not MPI, finish this function.
	if (!(lookup_mpi_flow(iph->src_addr, iph->dst_addr, tcph->src_port, tcph->dst_port) > 0 || 
		lookup_mpi_flow(iph->dst_addr, iph->src_addr, tcph->dst_port, tcph->src_port) > 0)) {
		return;
	}

	// Following script is for MPI packet

	// Add a log message
	
	// MPI FIN packet?
	if (tcph->fin == 1) {
		delete_mpi_flow(iph->src_addr, iph->dst_addr, tcph->src_port, tcph->dst_port);
		delete_mpi_flow(iph->dst_addr, iph->src_addr, tcph->dst_port, tcph->src_port);
#ifdef DEBUG
		char ip_src[INET_ADDRSTRLEN];
		char ip_dst[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(iph->src_addr), ip_src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(iph->dst_addr), ip_dst, INET_ADDRSTRLEN);
		printf("[mpi flow finish packet %s(%" PRIu16 ")->%s(%" PRIu16 ")] [len=%d] [flows=%d]\n", 
		ip_src, tcph->th_sport, ip_dst, tcph->th_dport, pkt_len, rte_hash_count(handle));
#endif
	}

	if (ntohs(tcph->dst_port) >= MPI_PORT_RANGE_START && ntohs(tcph->dst_port) <= MPI_PORT_RANGE_END)
	{
		// 型キャスト
		pkt = (MPIDI_CH3_Pkt_t *)tcp_payload;

		char ip_str_buf[50];
		get_ipv4_addr(htonl(iph->dst_addr), htonl(iph->src_addr), ip_str_buf);

		switch (pkt->type)
		{
		case MPIDI_CH3_PKT_EAGERSHORT_SEND:
		{
#ifdef DEBUG
			struct timeval start;
			struct timeval end;
			gettimeofday(&start, NULL);
#endif
			MPIDI_CH3_Pkt_eagershort_send_t *eagershort_pkt = &pkt->eagershort_send;
			putLog("EAGERSHORT\t %s rank=%d size=%ld tag=0x%x func=%s",
				   ip_str_buf,
				   eagershort_pkt->match.parts.rank,
				   eagershort_pkt->data_sz,
				   (int)eagershort_pkt->match.parts.tag,
				   get_mpifunc_string(eagershort_pkt->match.parts.tag));

#ifdef DEBUG
			gettimeofday(&end, NULL);
			float diff = end.tv_sec - start.tv_sec + (float)(end.tv_usec - start.tv_usec);
			DOCA_LOG_INFO("putLog time: %f[us]", diff);
#endif
			break;
		}
		// case MPIDI_CH3_PKT_RNDV_REQ_TO_SEND:
		// {
		// 	break;
		// }
		// case MPIDI_CH3_PKT_RNDV_SEND:
		// {
		// 	break;
		// }
		case MPIDI_CH3_PKT_EAGER_SEND:
		{
#ifdef DEBUG
			struct timeval start;
			struct timeval end;
			gettimeofday(&start, NULL);
#endif
			MPIDI_CH3_Pkt_eager_send_t *eager_send = &pkt->eager_send;
			putLog("EAGER_SEND\t %s rank=%d size=%ld tag=0x%x func=%s",
				   ip_str_buf,
				   eager_send->match.parts.rank,
				   eager_send->data_sz,
				   (int)eager_send->match.parts.tag,
				   get_mpifunc_string(eager_send->match.parts.tag));
#ifdef DEBUG
			gettimeofday(&end, NULL);
			float diff = end.tv_sec - start.tv_sec + (float)(end.tv_usec - start.tv_usec);
			DOCA_LOG_INFO("putLog time: %f[us]", diff);
#endif
			break;
		}

		case MPIDI_CH3_PKT_EAGER_SYNC_SEND:
		{
			MPIDI_CH3_Pkt_eager_sync_send_t *eagersync_send = &pkt->eager_sync_send;
			putLog("EAGER_SYNC_SEND\t %s rank=%d size=%d func=%s",
				   ip_str_buf,
				   eagersync_send->match.parts.rank,
				   eagersync_send->data_sz,
				   get_mpifunc_string(eagersync_send->match.parts.tag));
		}
		case MPIDI_CH3_PKT_READY_SEND:
		{
			MPIDI_CH3_Pkt_ready_send_t *ready_send = &pkt->ready_send;
			putLog("READY_SEND\t %s rank=%d size=%d func=%s",
				   ip_str_buf,
				   ready_send->match.parts.rank,
				   ready_send->data_sz,
				   get_mpifunc_string(ready_send->match.parts.tag));
			break;
		}
		default:
		{
		}
		}
	}
}

/*this is very bad wasy to do it, need to set start time and use rte_*/
static inline uint64_t mpiid_get_time_usec(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

static void mpiid_process_offload(struct rte_mbuf *mbuf)
{
	// 各レイヤのヘッダの位置などの情報
	struct mpiid_pkt_info pinfo;

	memset(&pinfo, 0, sizeof(struct mpiid_pkt_info));
	if (mpiid_parse_packet(VNF_PKT_L2(mbuf), VNF_PKT_LEN(mbuf), &pinfo))
	{
		return;
	}

	pinfo.orig_data = mbuf;
	pinfo.orig_port_id = mbuf->port;
	pinfo.rss_hash = mbuf->hash.rss;
	if (pinfo.fmt.l3_type != IPV4)
		return;
	analyze_packets(&pinfo);
}

static int poll_packet_thread_fn(void *p)
{
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t nb_rx, nb_tx, queue_id;
	uint32_t port_id = 0, core_id = rte_lcore_id();
	struct vnf_per_core_params *params = (struct vnf_per_core_params *)p;
	int cur_tsc;
	int prev_tsc;
	uint16_t nb_q;

	// Flow watching initialization
	create_mpi_flow_hash();


	DOCA_LOG_INFO("core %u process queue %u start (poll_packet_thread_fn)", core_id, params->queues[port_id]);
	while (!force_quit)
	{

		for (port_id = 0; port_id < NUM_OF_PORTS; port_id++)
		{
			queue_id = params->queues[port_id];
			nb_rx = rte_eth_rx_burst(port_id, queue_id, mbufs, VNF_RX_BURST_SIZE);
			for (int i=0; i<nb_rx; i++)
			{
				rx_bytes += mbufs[i]->pkt_len;
			}
			
			if (likely(nb_rx > 0))
			{
				nb_q = rte_ring_enqueue_burst(params->ring, (void **)mbufs, nb_rx, NULL);
				enqueued_pkts += nb_q;
				for (int i=0; i<nb_q; i++)
				{
					enqueued_bytes += mbufs[i]->pkt_len;
				}
			}

			// パケット送信，mbufの解放
			nb_tx = rte_eth_tx_burst(port_id == 0 ? 1 : 0, queue_id, mbufs, nb_rx);
			for (int i=0; i<nb_tx; i++)
			{
				tx_bytes += mbufs[i]->pkt_len;
			}

			if (nb_tx < nb_rx)
			{
				for (int i = nb_tx; i < nb_rx; i++)
				{
					rte_pktmbuf_free(mbufs[i]);
				}
			}
		}
		// 1sごとに出力
		cur_tsc = rte_get_timer_cycles();
		if ((cur_tsc - prev_tsc) > timer_resolution_cycles) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}

	// Flow watching deconstruction
	rte_hash_free(handle);
	return 0;
}

static int worker_thread_fn(void *p)
{
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t j, nb_rx;
	uint32_t core_id = rte_lcore_id();
	struct vnf_per_core_params *params = (struct vnf_per_core_params *)p;
	DOCA_LOG_INFO("core %u process start (worker_thread_fn)", core_id);
	int cur_tsc;
	int prev_tsc;

	// MPIログ出力初期化処理
	init_mpilog_buf();
	
	while (!force_quit)
	{
		nb_rx = rte_ring_mc_dequeue_burst(params->ring, (void *)mbufs, VNF_RX_BURST_SIZE, NULL);

		processed_pkts += nb_rx;
		for (j = 0; j < nb_rx; j++)
		{
			processed_bytes += mbufs[j]->pkt_len;
			mpiid_process_offload(mbufs[j]);
		}

		// [start] rte timer manager
		cur_tsc = rte_get_timer_cycles();
		if ((cur_tsc - prev_tsc) > timer_resolution_cycles) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
		// [end] rte timer manager
	}

	// 終了処理
	flush_mpilog_buf(core_id);
	return 0;
}

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
		printf("\n\nSignal %d received, preparing to exit...\n",
			   signum);
		force_quit = true;
	}
}

static void mpiid_info_usage(const char *prgname)
{
	printf("%s [EAL options] --\n"
		   "  --log_level: set log level\n"
		   "  --nr_queues: set queues number\n",
		   prgname);
}

static int mpiid_parse_uint32(const char *uint32_value)
{
	char *end = NULL;
	uint32_t value;

	// convert a string to an unsigned long intager
	// 文字列->Long Int
	value = strtoul(uint32_value, &end, 10);
	if ((uint32_value[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	return value;
}

static int
mpiid_info_parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	char *prgname = argv[0];
	uint32_t log_level = 0;
	static struct option long_option[] = {
		{"log_level", 1, NULL, 0},
		{"nr_queues", 1, NULL, 1},
		{NULL, 0, 0, 0},
	};

	if (argc == 1)
	{
		mpiid_info_usage(prgname);
		return 0;
	}
	while ((opt = getopt_long(argc, argv, "", long_option,
							  &option_index)) != EOF)
	{
		switch (opt)
		{
		case 0:
			log_level = mpiid_parse_uint32(optarg);
			if (log_level > DOCA_LOG_LEVEL_DEBUG)
				log_level = DOCA_LOG_LEVEL_DEBUG;
			printf("set debug_level:%u\n", log_level);
			doca_log_global_level_set(log_level);
			break;
		case 1:
			nr_queues = mpiid_parse_uint32(optarg);
			if (nr_queues > 16)
			{
				printf("nr_queues should be 2 - 16\n");
				return -1;
			}
			printf("set nr_queues:%u.\n", nr_queues);
			break;
		default:
			mpiid_info_usage(prgname);
			return -1;
		}
	}
	return 0;
}

static int
adjust_queue_by_fwd(uint16_t nb_queues, struct rte_ring *ring)
{
	int i, core_idx = 0;

	memset(core_params_arr, 0, sizeof(core_params_arr));
	for (i = 0; i < nb_queues; i++)
	{
		if (rte_lcore_is_enabled(i))
		{
			core_params_arr[core_idx].ports[0] = 0;
			core_params_arr[core_idx].ports[1] = 1;
			core_params_arr[core_idx].queues[0] = core_idx;
			core_params_arr[core_idx].queues[1] = core_idx;
			core_params_arr[core_idx].core_id = i;
			core_params_arr[core_idx].used = true;
			core_params_arr[core_idx].ring = ring;
			core_idx++;
		}
	}
	if (nb_queues > core_idx)
		nb_queues = core_idx;
	return nb_queues;
}

void printPacketTypeEnum()
{
	DOCA_LOG_DBG("+=====================================+");
	DOCA_LOG_DBG("MPIDI_CH3_PKT_EAGER_SEND: %d", MPIDI_CH3_PKT_EAGER_SEND);
	DOCA_LOG_DBG("MPIDI_CH3_PKT_EAGERSHORT_SEND: %d", MPIDI_CH3_PKT_EAGERSHORT_SEND);
	DOCA_LOG_DBG("MPIDI_CH3_PKT_EAGER_SYNC_SEND: %d", MPIDI_CH3_PKT_EAGER_SYNC_SEND);
	DOCA_LOG_DBG("MPIDI_CH3_PKT_READY_SEND: %d", MPIDI_CH3_PKT_READY_SEND);
	DOCA_LOG_DBG("MPIDI_CH3_PKT_RNDV_REQ_TO_SEND: %d", MPIDI_CH3_PKT_RNDV_REQ_TO_SEND);
	DOCA_LOG_DBG("MPIDI_CH3_PKT_RNDV_CLR_TO_SEND: %d", MPIDI_CH3_PKT_RNDV_CLR_TO_SEND);
	DOCA_LOG_DBG("MPIDI_CH3_PKT_RNDV_SEND: %d", MPIDI_CH3_PKT_RNDV_SEND);

	DOCA_LOG_DBG("sizeof enum MPIDI_CH3_Pkt_t: %ld bytes", sizeof(MPIDI_CH3_Pkt_t));
	DOCA_LOG_DBG("sizeof MPIDI_CH3_Pkt_send_t: %ld bytes", sizeof(MPIDI_CH3_Pkt_send_t));
	DOCA_LOG_DBG("sizeof MPIDI_CH3_Pkt_eagershort_send_t: %ld bytes", sizeof(MPIDI_CH3_Pkt_eagershort_send_t));
	DOCA_LOG_DBG("sizeof MPIDI_CH3_Pkt_type_t: %ld bytes", sizeof(MPIDI_CH3_Pkt_type_t));
	DOCA_LOG_DBG("sizeof MPIDI_Message_match: %ld bytes", sizeof(MPIDI_Message_match));
	DOCA_LOG_DBG("sizeof   - MPIDI_Message_match_parts_t: %ld bytes", sizeof(MPIDI_Message_match_parts_t));
	DOCA_LOG_DBG("sizeof     - int32_t tag: %ld bytes", sizeof(int32_t));
	DOCA_LOG_DBG("sizeof     - MPIDI_Rank_t rank: %ld bytes", sizeof(MPIDI_Rank_t));
	DOCA_LOG_DBG("sizeof     - MPIR_Context_id_t context_id: %ld bytes", sizeof(MPIR_Context_id_t));
	DOCA_LOG_DBG("sizeof   - uintptr_t: %ld bytes", sizeof(uintptr_t));
	DOCA_LOG_DBG("sizeof MPI_Request: %ld bytes", sizeof(MPI_Request));
	DOCA_LOG_DBG("sizeof intptr_t: %ld bytes", sizeof(intptr_t));
	DOCA_LOG_DBG("+=====================================+");
}

// Ringキューの作成
// mainスレッドは取得したパケットを全てこのRingキューにエンキューする
// workerスレッドはRingキューからパケットを取り出してログ抽出処理を行う
struct rte_ring *create_ring()
{
	struct rte_ring *ring;
	ring = rte_ring_create("wk_ring0", RING_Q_COUNT, rte_socket_id(), RING_F_SP_ENQ);
	if (ring == NULL)
	{
		rte_exit(EXIT_FAILURE, "Cannot create rx/tx ring\n");
	}
	return ring;
}


int main(int argc, char **argv)
{
	int ret, i = 0;
	struct doca_logger_backend *stdout_logger = NULL;
	uint32_t nb_queues, nb_ports;
	uint16_t port_id;
	struct mpiid_port_cfg port_cfg = {0};
	struct rte_ring *ring;

	ret = doca_log_create_file_backend(stdout, &stdout_logger);
	if (ret != DOCA_SUCCESS)
		return EXIT_FAILURE;

	// Logger初期化
	gLogCurNo = 0;
	// ログファイルのデフォルトパス
	strcpy(gIniValLog.logFilePathName, LOG_FILE_DEF_PATH);
	// ログファイルのデフォルト最大サイズ
	gIniValLog.logFileSizeMax = LOG_FILE_DEF_SIZE_MAX;
	// ログファイルのデフォルト最大世代数
	gIniValLog.logFileNumMax = LOG_FILE_DEF_NUM_MAX;
	// ログファイルNo取得
	getCurrentLogFileNo(LOG_TYPE_APL);

	dpdk_init(&argc, &argv, &nb_queues, &nb_ports);
	if (nb_ports != NUM_OF_PORTS)
	{
		rte_exit(EXIT_FAILURE, "simple fwd need 2 ports\n");
		return -1;
	}
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = mpiid_info_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid simple fwd arguments\n");

	if (nb_queues > nr_queues)
		nb_queues = nr_queues;

	// スレッド間でのパケット受け渡し用のRing作成
	ring = create_ring();
	port_cfg.nb_queues = adjust_queue_by_fwd(nb_queues, ring);
	port_cfg.nb_desc = nr_desc;
	RTE_ETH_FOREACH_DEV(port_id)
	{
		port_cfg.port_id = port_id;
		mpiid_start_dpdk_port(&port_cfg);
	}

	/* [measurement] init RTE timer library */
	uint64_t hz;
	rte_timer_subsystem_init();
	hz = rte_get_timer_hz();
	timer_resolution_cycles = hz * 1; /* around 1s */
    for (int i = 0; i < nb_queues; i++)
	{
		rte_timer_init(&timers[i]);
		rte_timer_reset(&timers[i], hz, PERIODICAL, i, (rte_timer_cb_t)timer_cb, ring);
	}

	// グローバル変数vnfの設定
	for (i = 0; i < RTE_MAX_LCORE; i++)
	{
		if (!core_params_arr[i].used)
			continue;
		if (rte_lcore_id() == core_params_arr[i].core_id)
		{
			continue;
		}
		// スレッドを作成
		rte_eal_remote_launch(
			(lcore_function_t *)worker_thread_fn,
			&core_params_arr[i],
			core_params_arr[i].core_id);
	}

#ifdef DEBUG
	printPacketTypeEnum();
#endif
	poll_packet_thread_fn(&core_params_arr[rte_lcore_id()]);

	/* Termination process */
	DOCA_LOG_DBG("rte_eal_mp_wait_lcore");
	rte_eal_mp_wait_lcore();

	DOCA_LOG_DBG("mpiid_close_port");
	RTE_ETH_FOREACH_DEV(port_id)
	mpiid_close_port(port_id);
	return 0;
}