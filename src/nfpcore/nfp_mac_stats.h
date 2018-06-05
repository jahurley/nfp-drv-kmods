/*
 * Copyright (C) 2018 Netronome Systems, Inc.
 *
 * This software is dual licensed under the GNU General License Version 2,
 * June 1991 as shown in the file COPYING in the top-level directory of this
 * source tree or the BSD 2-Clause License provided below.  You have the
 * option to license this software under the complete terms of either license.
 *
 * The BSD 2-Clause License:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      1. Redistributions of source code must retain the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer.
 *
 *      2. Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials
 *         provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef NSP_MAC_H
#define NSP_MAC_H 1

#include <linux/types.h>

#include "nfp_cpp.h"
#include "nfp_nsp.h"

/* Per port statistics accumulate structure */
struct nfp_mac_stats_port {
	union {
		struct {
			u64 rxpifinoctets;
			u64 rxpifinoctets_unused;
			u64 rxframetoolongerrors;
			u64 rxinrangelengtherrors;
			u64 rxvlanreceivedok;
			u64 rxpifinerrors;
			u64 rxpifinbroadcastpkts;
			u64 rxpstatsdropevents;
			u64 rxalignmenterrors;
			u64 rxpausemacctlframes;
			u64 rxframesreceivedok;
			u64 rxframechecksequenceerrors;
			u64 rxpifinunicastpkts;
			u64 rxpifinmulticastpkts;
			u64 rxpstatspkts;
			u64 rxpstatsundersizepkts;
			u64 rxpstatspkts64octets;
			u64 rxpstatspkts65to127octets;
			u64 rxpstatspkts512to1023octets;
			u64 rxpstatspkts1024to1518octets;
			u64 rxpstatsjabbers;
			u64 rxpstatsfragments;
			u64 rxcbfcpauseframesreceived2;
			u64 rxcbfcpauseframesreceived3;
			u64 rxpstatspkts128to255octets;
			u64 rxpstatspkts256to511octets;
			u64 rxpstatspkts1519tomaxoctets;
			u64 rxpstatsoversizepkts;
			u64 rxcbfcpauseframesreceived0;
			u64 rxcbfcpauseframesreceived1;
			u64 rxcbfcpauseframesreceived4;
			u64 rxcbfcpauseframesreceived5;
			u64 rxcbfcpauseframesreceived6;
			u64 rxcbfcpauseframesreceived7;
			u64 rxmacctlframesreceived;
			u64 rxmacheaddrop;
			u64 unused0;
			u64 unused1;
			u64 unused2;
			u64 txqueuedrop;
			u64 txpifoutoctets;
			u64 txpifoutoctets_unused;
			u64 txvlantransmittedok;
			u64 txpifouterrors;
			u64 txpifoutbroadcastpkts;
			u64 txpstatspkts64octets;
			u64 txpstatspkts256to511octets;
			u64 txpstatspkts512to1023octets;
			u64 txpausemacctlframestransmitted;
			u64 txframestransmittedok;
			u64 txpifoutunicastpkts;
			u64 txpifoutmulticastpkts;
			u64 txpstatspkts65to127octets;
			u64 txpstatspkts128to255octets;
			u64 txpstatspkts1024to1518octets;
			u64 txpstatspkts1518tomaxoctets;
			u64 txcbfcpauseframestransmitted0;
			u64 txcbfcpauseframestransmitted1;
			u64 txcbfcpauseframestransmitted4;
			u64 txcbfcpauseframestransmitted5;
			u64 txcbfcpauseframestransmitted2;
			u64 txcbfcpauseframestransmitted3;
			u64 txcbfcpauseframestransmitted6;
			u64 txcbfcpauseframestransmitted7;
		};
		u64 raw[64];
	};
};

int nfp_mac_stats_port_accum(struct nfp_cpp *cpp,
			     struct nfp_eth_table_port *port,
			     struct nfp_mac_stats_port *stats);

#endif
