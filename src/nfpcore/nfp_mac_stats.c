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

#include "nfp6000/nfp6000.h"
#include "nfp_mac_stats.h"

#define PORTS_PER_MAC_CORE	12
#define CORES_PER_NBI		2
#define NBI_COUNT		2
#define MAX_PORT		(NBI_COUNT * \
				(CORES_PER_NBI * PORTS_PER_MAC_CORE))

#define MACSTATS_BASE		0x100000
#define MACSTATS_PER_CORE_SIZE	4096
#define MACSTATS_PER_PORT_SIZE	256

#define MACSTATS_PORT_ADDR(_nbi, _core, _seg) \
	(MACSTATS_BASE + ((_nbi) << 30) + (_core) * MACSTATS_PER_CORE_SIZE + \
	(_seg) * MACSTATS_PER_PORT_SIZE)

/* Per port statistics
 * Each segment (12 per MAC core) has 256 bytes of stats counters.
 */
struct nfp_mac_stats_port_raw {
	u32 rxpifinoctetslo;
	u8 rxpifinoctetshi;
	u8 rxpifinoctetshi_res[3];
	u32 rxframetoolongerrors;
	u32 rxinrangelengtherrors;
	u32 rxvlanreceivedok;
	u32 rxpifinerrors;
	u32 rxpifinbroadcastpkts;
	u32 rxpstatsdropevents;
	u32 rxalignmenterrors;
	u32 rxpausemacctlframes;
	u32 rxframesreceivedok;
	u32 rxframechecksequenceerrors;
	u32 rxpifinunicastpkts;
	u32 rxpifinmulticastpkts;
	u32 rxpstatspkts;
	u32 rxpstatsundersizepkts;
	u32 rxpstatspkts64octets;
	u32 rxpstatspkts65to127octets;
	u32 rxpstatspkts512to1023octets;
	u32 rxpstatspkts1024to1518octets;
	u32 rxpstatsjabbers;
	u32 rxpstatsfragments;
	u32 rxcbfcpauseframesreceived2;
	u32 rxcbfcpauseframesreceived3;
	u32 rxpstatspkts128to255octets;
	u32 rxpstatspkts256to511octets;
	u32 rxpstatspkts1519tomaxoctets;
	u32 rxpstatsoversizepkts;
	u32 rxcbfcpauseframesreceived0;
	u32 rxcbfcpauseframesreceived1;
	u32 rxcbfcpauseframesreceived4;
	u32 rxcbfcpauseframesreceived5;
	u32 rxcbfcpauseframesreceived6;
	u32 rxcbfcpauseframesreceived7;
	u32 rxmacctlframesreceived;
	u32 unused0;
	u32 unused1;
	u32 unused2;
	u32 unused3;
	u32 unused4;
	u32 txpifoutoctetslo;
	u8 txpifoutoctetshi;
	u8 txpifoutoctetshi_res[3];
	u32 txvlantransmittedok;
	u32 txpifouterrors;
	u32 txpifoutbroadcastpkts;
	u32 txpstatspkts64octets;
	u32 txpstatspkts256to511octets;
	u32 txpstatspkts512to1023octets;
	u32 txpausemacctlframestransmitted;
	u32 txframestransmittedok;
	u32 txpifoutunicastpkts;
	u32 txpifoutmulticastpkts;
	u32 txpstatspkts65to127octets;
	u32 txpstatspkts128to255octets;
	u32 txpstatspkts1024to1518octets;
	u32 txpstatspkts1518tomaxoctets;
	u32 txcbfcpauseframestransmitted0;
	u32 txcbfcpauseframestransmitted1;
	u32 txcbfcpauseframestransmitted4;
	u32 txcbfcpauseframestransmitted5;
	u32 txcbfcpauseframestransmitted2;
	u32 txcbfcpauseframestransmitted3;
	u32 txcbfcpauseframestransmitted6;
	u32 txcbfcpauseframestransmitted7;
};

int nfp_mac_stats_port_accum(struct nfp_cpp *cpp,
			     struct nfp_eth_table_port *port,
			     struct nfp_mac_stats_port *stats)
{
	struct nfp_mac_stats_port_raw raw;
	int err, seg, core = 0;
	u32 addr, dest;

	/* Let's determine the port parameters in terms of the address space */
	if (port->base >= PORTS_PER_MAC_CORE)
		core = 1;
	seg = port->base - (core * PORTS_PER_MAC_CORE);

	if (seg > PORTS_PER_MAC_CORE)
		return -EINVAL;

	/* Read the entire MAC stats block at once. We cannot use simple CPP
	 * read transactions, we need to use an explicit transaction for this.
	 */
	dest = NFP_CPP_ID(NFP_CPP_TARGET_NBI, NFP_CPP_ACTION_RW, 0);
	addr = MACSTATS_PORT_ADDR(port->nbi, core, seg);

	err = nfp_cpp_explicit_read(cpp, dest, addr, &raw, sizeof(raw), 8);
	if (err < 0)
		return err;
	if (err != sizeof(raw))
		return -EINVAL;

	stats->rxpifinoctets += raw.rxpifinoctetslo +
		((u64)raw.rxpifinoctetshi << 32);
	stats->rxframetoolongerrors += raw.rxframetoolongerrors;
	stats->rxinrangelengtherrors += raw.rxinrangelengtherrors;
	stats->rxvlanreceivedok += raw.rxvlanreceivedok;
	stats->rxpifinerrors += raw.rxpifinerrors;
	stats->rxpifinbroadcastpkts += raw.rxpifinbroadcastpkts;
	stats->rxpstatsdropevents += raw.rxpstatsdropevents;
	stats->rxalignmenterrors += raw.rxalignmenterrors;
	stats->rxpausemacctlframes += raw.rxpausemacctlframes;
	stats->rxframesreceivedok += raw.rxframesreceivedok;
	stats->rxframechecksequenceerrors += raw.rxframechecksequenceerrors;
	stats->rxpifinunicastpkts += raw.rxpifinunicastpkts;
	stats->rxpifinmulticastpkts += raw.rxpifinmulticastpkts;
	stats->rxpstatspkts += raw.rxpstatspkts;
	stats->rxpstatsundersizepkts += raw.rxpstatsundersizepkts;
	stats->rxpstatspkts64octets += raw.rxpstatspkts64octets;
	stats->rxpstatspkts65to127octets += raw.rxpstatspkts65to127octets;
	stats->rxpstatspkts512to1023octets += raw.rxpstatspkts512to1023octets;
	stats->rxpstatspkts1024to1518octets +=
		raw.rxpstatspkts1024to1518octets;
	stats->rxpstatsjabbers += raw.rxpstatsjabbers;
	stats->rxpstatsfragments += raw.rxpstatsfragments;
	stats->rxcbfcpauseframesreceived2 += raw.rxcbfcpauseframesreceived2;
	stats->rxcbfcpauseframesreceived3 += raw.rxcbfcpauseframesreceived3;
	stats->rxpstatspkts128to255octets += raw.rxpstatspkts128to255octets;
	stats->rxpstatspkts256to511octets += raw.rxpstatspkts256to511octets;
	stats->rxpstatspkts1519tomaxoctets += raw.rxpstatspkts1519tomaxoctets;
	stats->rxpstatsoversizepkts += raw.rxpstatsoversizepkts;
	stats->rxcbfcpauseframesreceived0 += raw.rxcbfcpauseframesreceived0;
	stats->rxcbfcpauseframesreceived1 += raw.rxcbfcpauseframesreceived1;
	stats->rxcbfcpauseframesreceived4 += raw.rxcbfcpauseframesreceived4;
	stats->rxcbfcpauseframesreceived5 += raw.rxcbfcpauseframesreceived5;
	stats->rxcbfcpauseframesreceived6 += raw.rxcbfcpauseframesreceived6;
	stats->rxcbfcpauseframesreceived7 += raw.rxcbfcpauseframesreceived7;
	stats->rxmacctlframesreceived += raw.rxmacctlframesreceived;
	stats->txpifoutoctets += raw.txpifoutoctetslo +
		((u64)raw.txpifoutoctetshi << 32);
	stats->txvlantransmittedok += raw.txvlantransmittedok;
	stats->txpifouterrors += raw.txpifouterrors;
	stats->txpifoutbroadcastpkts += raw.txpifoutbroadcastpkts;
	stats->txpstatspkts64octets += raw.txpstatspkts64octets;
	stats->txpstatspkts256to511octets += raw.txpstatspkts256to511octets;
	stats->txpstatspkts512to1023octets += raw.txpstatspkts512to1023octets;
	stats->txpausemacctlframestransmitted +=
		raw.txpausemacctlframestransmitted;
	stats->txframestransmittedok += raw.txframestransmittedok;
	stats->txpifoutunicastpkts += raw.txpifoutunicastpkts;
	stats->txpifoutmulticastpkts += raw.txpifoutmulticastpkts;
	stats->txpstatspkts65to127octets += raw.txpstatspkts65to127octets;
	stats->txpstatspkts128to255octets += raw.txpstatspkts128to255octets;
	stats->txpstatspkts1024to1518octets +=
		raw.txpstatspkts1024to1518octets;
	stats->txpstatspkts1518tomaxoctets += raw.txpstatspkts1518tomaxoctets;
	stats->txcbfcpauseframestransmitted0 +=
		raw.txcbfcpauseframestransmitted0;
	stats->txcbfcpauseframestransmitted1 +=
		raw.txcbfcpauseframestransmitted1;
	stats->txcbfcpauseframestransmitted4 +=
		raw.txcbfcpauseframestransmitted4;
	stats->txcbfcpauseframestransmitted5 +=
		raw.txcbfcpauseframestransmitted5;
	stats->txcbfcpauseframestransmitted2 +=
		raw.txcbfcpauseframestransmitted2;
	stats->txcbfcpauseframestransmitted3 +=
		raw.txcbfcpauseframestransmitted3;
	stats->txcbfcpauseframestransmitted6 +=
		raw.txcbfcpauseframestransmitted6;
	stats->txcbfcpauseframestransmitted7 +=
		raw.txcbfcpauseframestransmitted7;

	return 0;
}
