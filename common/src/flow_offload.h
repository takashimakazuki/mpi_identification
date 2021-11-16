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

/*
 *                                                                                              ┌───┐ ┌────┐ ┌────┐
 *                                                                         MATCHED TRAFFIC      │DPI│ │    │ │    │
 *        FLOW_OFFLOAD_DIAGRAM                                             ┌────────────────────┤WORKERS   │ │    │
 *                                                                         │ SET STATE TO       │   │ │    │ │    │
 *                                                                         │ HAIRPIN/DROP       │   │ │    │ │    │
 *                                                                         │                    │   │ │    │ │    │
 *     ┌───────────────────────────────────────────────────────────────────┼────────────────────┼───┼─┼────┼─┼────┼──┐
 *     │                                                                   │                    │   │ │    │ │    │  │
 *     │                                                                   │                    │   │ │    │ │    │  │
 *     │     NIC HW STEERING                                               │                    └─▲─┘ └──▲─┘ └──▲─┘  │
 *     │                                                                   │                      │      │      │    │
 *     │                                                                   │                      │      │      │    │
 *     │                                                                   │                      │      │      │    │
 *     │                                                                   │                      │      │      │    │
 *     │                                                                   ▼            ┌─────────┴──────┤      │    │
 *     │                     RTE_FLOW                RTE_SFT            RTE_SFT         │                ├──────┘    │
 *     │                                                                                │      RSS       │           │
 *     │                 ┌──────────────┐         ┌────────────┐      ┌──────────┐      │                │           │
 *     │                 │              │         │            │      │ POST_SFT │      └────────────────┘           │
 *     │                 │  SFT ACTION  │         │ MARK STATE │      │          │              ▲                    │
 *     │                 │  JUMP TO     │         │ IN SFT     │      │ CHECK    │              │                    │
 *     │    L4 TRAFFIC   │  TABLE WITH  ├────────►│            ├─────►│ VALID FID├──────────────┘                    │
 *     │ ┌─────────────► │  PREDEFINED  │         │            │      │ &&       │                                   │
 *     │ │               │  ZONE        │         │            │      │ VALID    │                                   │
 *     │ │               │              │         │            │      │   STATE  │                                   │
 *     │ │               └──────────────┘         └────────────┘      └┬─────────┘                                   │
 *     │ │                                                             │                                             │
 *     │ │                                                             │                                             │
 *     │ │                                                             │HAIRPIN MATCHED                              │
 *┌────┼─┴┐                                                            │  TRAFFIC      ┌─────────┐                   │
 *│    │  │                                                            └───────────────►         │              ┌────┼──┐
 *│ PORT  │                         NON L4 TRAFFIC                                     │  HAIRPIN│              │    │  │
 *│ RX │  ├────────────────────────────────────────────────────────────────────────────►         │              │  PORT │
 *│    │  │                                                                            │  QUEUE  ├─────────────►│  TX│  │
 *└────┼──┘                                                                            │         │              │    │  │
 *     │                                                                               └─────────┘              └────┼──┘
 *     │_____________________________________________________________________________________________________________│
 *
 */

#ifndef FLOW_OFFLOAD_H
#define FLOW_OFFLOAD_H

enum SFT_USER_STATE {
	RSS_FLOW = 0,
	HAIRPIN_MATCHED_FLOW = 1,
	HAIRPIN_SKIPPED_FLOW = 1,
	DROP_FLOW = 2,
};

void flow_offload_query_counters(void);

int enable_hairpin_queues(uint16_t port_id, uint16_t *peer_ports,
	uint16_t peer_ports_len);

void dpdk_sft_init(bool ct, int nb_queues, unsigned int nb_ports);

int dpdk_ports_init(unsigned int nb_ports, int available_cores);

void dpdk_init(int *argc, char **argv[], unsigned int *nb_cores, unsigned int *nb_ports);

#endif
