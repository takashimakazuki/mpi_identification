#ifndef _mpiid_TIMER_CB_H_
#define _mpiid_TIMER_CB_H_

#include <stdio.h>
#include <rte_lcore.h>
#include <rte_timer.h>
#include <rte_common.h>

#define VNF_PKT_L2(M) rte_pktmbuf_mtod(M, uint8_t *)
#define VNF_PKT_LEN(M) rte_pktmbuf_pkt_len(M)
#define VNF_RX_BURST_SIZE (64)
#define RING_Q_COUNT (65536*16)
#define MPI_PKT_KVS_STR_OFFSET (80)

#define MPI_PORT_RANGE_START 30000
#define MPI_PORT_RANGE_END 80000

extern __thread uint32_t processed_bytes;
extern __thread uint32_t processed_pkts;
extern __thread uint32_t tx_bytes;
extern __thread uint32_t rx_bytes;
extern __thread uint32_t enqueued_pkts;
extern __thread uint32_t enqueued_bytes;

void timer_cb(struct rte_timer *tim, struct rte_ring *ring)
{
	unsigned lcore_id = rte_lcore_id();
	unsigned int cnt = lcore_id == 0 ? 0 : rte_ring_count(ring);

	printf("[lcore %u] ring%u_cnt: %07d(%.1lf%%), ring%u_deq(pps/Gbps): %07u/%.2lf, ringX_enq(pps/Gbps): %07u/%.2lf, rx_deq/tx_enq(Gbps): %.2lf/%.2lf,\n",
	lcore_id,
	lcore_id,
	cnt,
	(double)cnt / RING_Q_COUNT * 100,
	lcore_id,
	processed_pkts,
	(double)(processed_bytes)*8/1024/1024/1024,
	enqueued_pkts,
	(double)(enqueued_bytes)*8/1024/1024/1024,
	(double)(rx_bytes)*8/1024/1024/1024,
	(double)(tx_bytes)*8/1024/1024/1024);


	processed_pkts = 0;
	processed_bytes = 0;
	enqueued_pkts = 0;
	enqueued_bytes = 0;
	rx_bytes = 0;
	tx_bytes=0;
}
#endif