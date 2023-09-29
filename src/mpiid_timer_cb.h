#ifndef _mpiid_TIMER_CB_H_
#define _mpiid_TIMER_CB_H_

#include <stdio.h>
#include <rte_lcore.h>
#include <rte_timer.h>
#include <rte_common.h>

extern uint32_t processed_bytes, processed_pkts, tx_bytes, rx_bytes, enqueued_pkts, enqueued_bytes;

static void timer_cb(__rte_unused struct rte_timer *tim, __rte_unused void *arg)
{
	// static unsigned counter = 0;
	unsigned lcore_id = rte_lcore_id();

	printf("%s() on lcore %u, pkts(pps/Gbps）: %u/%.2lf, enq_pks(pps/Gbps): %u/%.2lf, rx/tx(Gbps): %.2lf/%.2lf\n", 
	__func__, 
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