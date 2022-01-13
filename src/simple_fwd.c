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
// sudo ./doca_simple_fwd_vnf -a auxiliary:mlx5_core.sf.4 -a auxiliary:mlx5_core.sf.5 -- --nr_queues=4 --stats_timer=2 --log_level=8

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
#include <netinet/tcp.h>
#include <netinet/ip.h>

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
#include <doca_flow.h>
#include <doca_log.h>
#include "flow_offload.h"
#include "utils.h"
#include "app_vnf.h"
#include "simple_fwd_vnf.h"
#include "simple_fwd_ft.h"
#include "simple_fwd_port.h"

#include "mpi.h"
#include "mpidpre.h"
#include "mpidpkt.h"
#include "mpir_tags.h"
#include "logger.h"

DOCA_LOG_REGISTER(SIMPLE_FWD);

// #define DEBUG
#define VNF_PKT_L2(M) rte_pktmbuf_mtod(M, uint8_t *)
#define VNF_PKT_LEN(M) rte_pktmbuf_pkt_len(M)
#define VNF_RX_BURST_SIZE (32)

uint16_t nr_queues = 4;
uint16_t rx_only;
uint16_t hw_offload = 1;
uint64_t stats_timer = 100000;
uint16_t is_hairpin;
uint16_t nr_desc = 512;
static struct app_vnf *vnf;
static volatile bool force_quit;

// 論理コアごとの設定項目
struct vnf_per_core_params
{
	int ports[NUM_OF_PORTS];
	int queues[NUM_OF_PORTS];
	int core_id;
	bool used;
};
struct vnf_per_core_params core_params_arr[RTE_MAX_LCORE];

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

char *mpifunc_strings[4] = {
	"BCAST",
	"ALLGATHER",
	"ALLTOALL",
	"SEND",
};

char *get_mpifunc_string(int32_t tag)
{
	if (tag == MPIR_BCAST_TAG)
	{
		return mpifunc_strings[0];
	}
	else if (tag == MPIR_ALLGATHER_TAG)
	{
		return mpifunc_strings[1];
	}
	else if (tag == MPIR_ALLTOALL_TAG)
	{
		return mpifunc_strings[2];
	}
	return mpifunc_strings[3];
}

void analyze_packets(struct simple_fwd_pkt_info *pinfo)
{
	MPIDI_CH3_Pkt_t *pkt;
	struct tcphdr *tcph = (struct tcphdr *)pinfo->outer.l4;
	struct iphdr *iph = (struct iphdr *)pinfo->outer.l3;
	// TCPペイロードの先頭ポインタ
	uint8_t *l4_payload = pinfo->outer.l4 + tcph->doff * 4;
	int pkt_len;

	// TCPペイロードのデータ長(bytes)
	pkt_len = ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4;

	// TCPパケットペイロードがない場合
	if (pkt_len <= 0)
	{
		return;
	}

	// MPIヘッダ長の長さに足りないためMPI送信パケットではない
	if (pkt_len < sizeof(MPIDI_CH3_Pkt_t))
	{
		return;
	}

	if (
		(ntohs(tcph->source) >= 50000 && ntohs(tcph->source) <= 50100) ||
		(ntohs(tcph->dest) >= 50000 && ntohs(tcph->dest) <= 50100))
	{
		// 型キャスト
		pkt = (MPIDI_CH3_Pkt_t *)l4_payload;

		char ip_str_buf[50];
		get_ipv4_addr(htonl(iph->daddr), htonl(iph->saddr), ip_str_buf);

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
			putLog("EAGERSHORT_SEND, %s, type=%d, tag=%d, rank=%d, context_id=%d, size=%d, func=%s",
				   ip_str_buf,
				   eagershort_pkt->type,
				   eagershort_pkt->match.parts.tag,
				   eagershort_pkt->match.parts.rank,
				   eagershort_pkt->match.parts.context_id,
				   eagershort_pkt->data_sz,
				   get_mpifunc_string(eagershort_pkt->match.parts.tag));

#ifdef DEBUG
			gettimeofday(&end, NULL);
			float diff = end.tv_sec - start.tv_sec + (float)(end.tv_usec - start.tv_usec);
			DOCA_LOG_INFO("putLog time: %f[us]", diff);
#endif
			break;
		}
		case MPIDI_CH3_PKT_RNDV_REQ_TO_SEND:
		{
			break;
		}
		case MPIDI_CH3_PKT_RNDV_SEND:
		{
			break;
		}
		case MPIDI_CH3_PKT_EAGER_SEND:
		{
#ifdef DEBUG
			struct timeval start;
			struct timeval end;
			gettimeofday(&start, NULL);
#endif
			MPIDI_CH3_Pkt_eager_send_t *eager_send = &pkt->eager_send;
			putLog("EAGER_SEND, %s type=%d, tag=%d, rank=%d, context_id=%d, size=%d func=%s",
				   ip_str_buf,
				   eager_send->type,
				   eager_send->match.parts.tag,
				   eager_send->match.parts.rank,
				   eager_send->match.parts.context_id,
				   eager_send->data_sz,
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
			putLog("EAGERSYNC_SEND, %s type=%d, tag=%d, rank=%d, context_id=%d, size=%d func=%s",
				   ip_str_buf,
				   eagersync_send->type,
				   eagersync_send->match.parts.tag,
				   eagersync_send->match.parts.rank,
				   eagersync_send->match.parts.context_id,
				   eagersync_send->data_sz,
				   get_mpifunc_string(eagersync_send->match.parts.tag));
		}
		default:
		{
		}
		}
	}
}

/*this is very bad wasy to do it, need to set start time and use rte_*/
static inline uint64_t simple_fwd_get_time_usec(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

static void vnf_adjust_mbuf(struct rte_mbuf *m,
							struct simple_fwd_pkt_info *pinfo)
{
	int diff = pinfo->outer.l2 - VNF_PKT_L2(m);

	rte_pktmbuf_adj(m, diff);
}

static void simple_fwd_process_offload(struct rte_mbuf *mbuf)
{
	// 各レイヤのヘッダの位置などの情報
	struct simple_fwd_pkt_info pinfo;

	memset(&pinfo, 0, sizeof(struct simple_fwd_pkt_info));
	if (simple_fwd_parse_packet(VNF_PKT_L2(mbuf), VNF_PKT_LEN(mbuf), &pinfo))
	{
		return;
	}

	pinfo.orig_data = mbuf;
	pinfo.orig_port_id = mbuf->port;
	pinfo.rss_hash = mbuf->hash.rss;
	if (pinfo.outer.l3_type != IPV4)
		return;
	vnf->vnf_process_pkt(&pinfo);
	analyze_packets(&pinfo);

	vnf_adjust_mbuf(mbuf, &pinfo);
}

static int simple_fwd_process_pkts(void *p)
{
	uint64_t cur_tsc, last_tsc;
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	struct rte_mbuf *mbufs_cpy[VNF_RX_BURST_SIZE];
	uint16_t j, nb_rx, queue_id;
	uint32_t port_id = 0, core_id = rte_lcore_id();
	struct vnf_per_core_params *params = (struct vnf_per_core_params *)p;

	DOCA_LOG_INFO("core %u process queue %u start", core_id,
				  params->queues[port_id]);
	last_tsc = rte_rdtsc();
	while (!force_quit)
	{
		if (core_id == 0)
		{
			// 統計情報の出力
			cur_tsc = rte_rdtsc();
			if (cur_tsc > last_tsc + stats_timer)
			{
				simple_fwd_dump_port_stats(0);
				last_tsc = cur_tsc;
			}
		}
		for (port_id = 0; port_id < NUM_OF_PORTS; port_id++)
		{
			queue_id = params->queues[port_id];
			nb_rx = rte_eth_rx_burst(port_id, queue_id, mbufs,
									 VNF_RX_BURST_SIZE);

			// パケット受信から送信までの時間を短縮するため，
			// rte_eth_rx_burstで受け取ったmbufはコピーし，以降のパケット参照時にはコピーしたmbufs_cpyを使用する
			for (j = 0; j < nb_rx; j++)
			{
				mbufs_cpy[j] = mbufs[j];
				// パケット送信，mbufの解放
				rte_eth_tx_burst(port_id == 0 ? 1 : 0, queue_id, &mbufs[j], 1);
			}

			for (j = 0; j < nb_rx; j++)
			{
				if (hw_offload && !core_id)
				{
					simple_fwd_process_offload(mbufs_cpy[j]);
				}
			}
		}
	}
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

static void simple_fwd_info_usage(const char *prgname)
{
	printf("%s [EAL options] --\n"
		   "  --log_level: set log level\n"
		   "  --stats_timer: set interval to dump stats information\n"
		   "  --nr_queues: set queues number\n"
		   "  --rx_only: set rx_only 0 or 1\n"
		   "  --hw_offload: set hw offload 0 or 1\n"
		   "  --hairpinq: set forwarding to hairpin queue\n",
		   prgname);
}

static int simple_fwd_parse_uint32(const char *uint32_value)
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
simple_fwd_info_parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	char *prgname = argv[0];
	uint32_t log_level = 0;
	static struct option long_option[] = {
		{"log_level", 1, NULL, 0},
		{"stats_timer", 1, NULL, 1},
		{"nr_queues", 1, NULL, 2},
		{"rx_only", 1, NULL, 3},
		{"hw_offload", 1, NULL, 4},
		{"hairpinq", 0, NULL, 5},
		{NULL, 0, 0, 0},
	};

	if (argc == 1)
	{
		simple_fwd_info_usage(prgname);
		return 0;
	}
	while ((opt = getopt_long(argc, argv, "", long_option,
							  &option_index)) != EOF)
	{
		switch (opt)
		{
		case 0:
			log_level = simple_fwd_parse_uint32(optarg);
			if (log_level > DOCA_LOG_LEVEL_DEBUG)
				log_level = DOCA_LOG_LEVEL_DEBUG;
			printf("set debug_level:%u\n", log_level);
			doca_log_global_level_set(log_level);
			break;
		case 1:
			stats_timer = simple_fwd_parse_uint32(optarg);
			printf("set stats_timer:%lu\n", stats_timer);
			break;
		case 2:
			nr_queues = simple_fwd_parse_uint32(optarg);
			if (nr_queues > 16)
			{
				printf("nr_queues should be 2 - 16\n");
				return -1;
			}
			printf("set nr_queues:%u.\n", nr_queues);
			break;
		case 3:
			rx_only = simple_fwd_parse_uint32(optarg);
			printf("set rx_only:%u.\n", rx_only == 0 ? 0 : 1);
			break;
		case 4:
			hw_offload = simple_fwd_parse_uint32(optarg);
			printf("set hw_offload:%u.\n", hw_offload == 0 ? 0 : 1);
			break;
		case 5:
			is_hairpin = 1;
			printf("set is_hairpin:%u.\n", is_hairpin);
			break;
		default:
			simple_fwd_info_usage(prgname);
			return -1;
		}
	}
	return 0;
}

static int
adjust_queue_by_fwd(uint16_t nb_queues)
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

	DOCA_LOG_DBG("sizeof enum MPIDI_CH3_Pkt_t: %d bytes", sizeof(MPIDI_CH3_Pkt_t));
	DOCA_LOG_DBG("sizeof MPIDI_CH3_Pkt_send_t: %d bytes", sizeof(MPIDI_CH3_Pkt_send_t));
	DOCA_LOG_DBG("sizeof MPIDI_CH3_Pkt_eagershort_send_t: %d bytes", sizeof(MPIDI_CH3_Pkt_eagershort_send_t));
	DOCA_LOG_DBG("sizeof MPIDI_CH3_Pkt_type_t: %d bytes", sizeof(MPIDI_CH3_Pkt_type_t));
	DOCA_LOG_DBG("sizeof MPIDI_Message_match: %d bytes", sizeof(MPIDI_Message_match));
	DOCA_LOG_DBG("sizeof   - MPIDI_Message_match_parts_t: %d bytes", sizeof(MPIDI_Message_match_parts_t));
	DOCA_LOG_DBG("sizeof     - int32_t tag: %d bytes", sizeof(int32_t));
	DOCA_LOG_DBG("sizeof     - MPIDI_Rank_t rank: %d bytes", sizeof(MPIDI_Rank_t));
	DOCA_LOG_DBG("sizeof     - MPIR_Context_id_t context_id: %d bytes", sizeof(MPIR_Context_id_t));
	DOCA_LOG_DBG("sizeof   - uintptr_t: %d bytes", sizeof(uintptr_t));
	DOCA_LOG_DBG("sizeof MPI_Request: %d bytes", sizeof(MPI_Request));
	DOCA_LOG_DBG("sizeof intptr_t: %d bytes", sizeof(intptr_t));
	DOCA_LOG_DBG("+=====================================+");
}

int gLogCurNo;

int main(int argc, char **argv)
{
	int ret, i = 0;
	uint32_t nb_queues, nb_ports;
	uint16_t port_id;
	struct simple_fwd_port_cfg port_cfg = {0};
	bool me = false;

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

	ret = simple_fwd_info_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid simple fwd arguments\n");

	/* convert to number of cycles */
	stats_timer *= rte_get_timer_hz();

	if (nb_queues > nr_queues)
		nb_queues = nr_queues;
	port_cfg.nb_queues = adjust_queue_by_fwd(nb_queues);
	port_cfg.is_hairpin = is_hairpin;
	port_cfg.nb_desc = nr_desc;
	RTE_ETH_FOREACH_DEV(port_id)
	{
		port_cfg.port_id = port_id;
		simple_fwd_start_dpdk_port(&port_cfg);
	}

	// Hairpin キューの設定
	if (is_hairpin)
		simple_fwd_hairpin_bind();

	// グローバル変数vnfの設定
	vnf = simple_fwd_get_doca_vnf();
	vnf->vnf_init((void *)&port_cfg); // simple_fwd_init();
	for (i = 0; i < RTE_MAX_LCORE; i++)
	{
		if (!core_params_arr[i].used)
			continue;
		if (rte_lcore_id() == core_params_arr[i].core_id)
		{
			me = true;
			continue;
		}
		// スレッドを作成
		rte_eal_remote_launch(
			(lcore_function_t *)simple_fwd_process_pkts,
			&core_params_arr[i],
			core_params_arr[i].core_id);
	}

	printPacketTypeEnum();
	if (!me)
		rte_eal_mp_wait_lcore();
	else
		simple_fwd_process_pkts(&core_params_arr[rte_lcore_id()]);

	RTE_ETH_FOREACH_DEV(port_id)
	simple_fwd_close_port(port_id);
	vnf->vnf_destroy();
	return 0;
}