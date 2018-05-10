/*
 * Copyright (C) 2017 Netronome Systems, Inc.
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

#include <net/xfrm.h>

#include "nfp_net.h"
#include "nfp_net_compat.h"
#include "nfp_net_ctrl.h"
#include "nfp_net_ipsec.h"
#include "nfp_net_repr.h"
#include "nfp_port.h"

struct nfp_net_ipsec_data {
};

static struct nfp_net_ipsec_data *
nfp_ipsec_get_handle(struct net_device *netdev)
{
	struct nfp_repr *repr;
	struct nfp_net *nn;

	if (nfp_netdev_is_nfp_repr(netdev)) {
		repr = netdev_priv(netdev);
		return repr->ipsec_data;
	} else {
		nn = netdev_priv(netdev);
		return nn->ipsec_data;
	}
}

static int nfp_net_xfrm_add_state(struct xfrm_state *x)
{
	return -EOPNOTSUPP;
}

static bool nfp_net_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	return false;
}

const struct xfrmdev_ops nfp_net_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add = nfp_net_xfrm_add_state,
	.xdo_dev_offload_ok = nfp_net_ipsec_offload_ok,
};

int nfp_net_ipsec_init(struct net_device *netdev)
{
	struct nfp_net_ipsec_data *ipd;
	struct nfp_repr *repr;
	struct nfp_net *nn;

	ipd = kzalloc(sizeof(*ipd), GFP_KERNEL);
	if (!ipd)
		return -ENOMEM;

	netdev->xfrmdev_ops = &nfp_net_ipsec_xfrmdev_ops;

	if (nfp_netdev_is_nfp_repr(netdev)) {
		repr = netdev_priv(netdev);
		repr->ipsec_data = ipd;
	} else {
		nn = netdev_priv(netdev);
		nn->ipsec_data = ipd;
	}

	return 0;
}

void nfp_net_ipsec_clean(struct net_device *netdev)
{
	struct nfp_net_ipsec_data *ipd = nfp_ipsec_get_handle(netdev);
	struct nfp_repr *repr;
	struct nfp_net *nn;

	if (!ipd)
		return;

	kfree(ipd);

	if (nfp_netdev_is_nfp_repr(netdev)) {
		repr = netdev_priv(netdev);
		repr->ipsec_data = NULL;
	} else {
		nn = netdev_priv(netdev);
		nn->ipsec_data = NULL;
	}
}
