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
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "nfpcore/nfp_cpp.h"
#include "nfpcore/nfp_nffw.h"
#include "nfpcore/nfp_nsp.h"
#include "nfp_app.h"
#include "nfp_main.h"
#include "nfp_ual.h"

#include "main.h"

#define UALT_NAME	"ualt_module"

/* The base header for a control message packet.
 * Defines an 8-bit version, and an 8-bit type, padded
 * to a 32-bit word. Rest of the packet is type-specific.
 */
struct ualt_cmsg_hdr {
	__be16 pad;
	u8 type;
	u8 version;
};

#define UALT_CMSG_HLEN			sizeof(struct ualt_cmsg_hdr)
#define UALT_CMSG_VERSION		1

enum ualt_cmsg_type {
	UALT_CMSG_PORT =		1,
};

struct ualt_cmsg_port {
	u32 port_id;
	u8 pad;
	u8 pcie;
	u8 nbi;
	u8 port;
};

static int scratchpad;

static struct ualt_cmsg_hdr *ualt_cmsg_get_hdr(struct sk_buff *skb)
{
	return (struct ualt_cmsg_hdr *)skb->data;
}

static void *ualt_cmsg_get_data(struct sk_buff *skb)
{
	return (unsigned char *)skb->data + UALT_CMSG_HLEN;
}

static struct sk_buff *
ualt_cmsg_alloc(unsigned int size, enum ualt_cmsg_type type)
{
	struct ualt_cmsg_hdr *hdr;
	struct sk_buff *skb;

	size += UALT_CMSG_HLEN;

	skb = nfp_ual_ctrl_msg_alloc(size, GFP_KERNEL);
	if (!skb)
		return NULL;

	hdr = ualt_cmsg_get_hdr(skb);
	hdr->pad = 0;
	hdr->version = UALT_CMSG_VERSION;
	hdr->type = type;
	skb_put(skb, size);

	return skb;
}

static int ualt_cmsg_port(struct nfp_repr *repr, u8 rx_vnic)
{
	struct nfp_eth_table_port *eth_port;
	struct ualt_cmsg_port *msg;
	struct sk_buff *skb;

	eth_port = nfp_ual_get_eth_port_from_repr(repr);
	if (!eth_port)
		return -ENODEV;

	skb = ualt_cmsg_alloc(sizeof(*msg), UALT_CMSG_PORT);
	if (!skb)
		return -ENOMEM;

	msg = ualt_cmsg_get_data(skb);
	msg->port_id = nfp_ual_get_port_id(repr);
	msg->nbi = eth_port->nbi;
	msg->port = eth_port->eth_index;
	msg->pcie = rx_vnic;
	msg->pad = 0;

	nfp_ual_ctrl_tx(skb);
	return 0;
}

static void ualt_bringup_reprs(struct nfp_repr *repr, void *cookie)
{
	struct nfp_mbl_repr *mbl_repr = repr->app_priv;
	struct nfp_eth_table_port *eth_port;
	struct ualt_cookie *priv = cookie;
	struct ualt_repr_meta *repr_meta;
	int err;

	repr_meta = vzalloc(sizeof(*repr_meta));
	if (!repr_meta) {
		pr_err("%s: unable to allocate memory, bringup failed\n",
		       repr->netdev->name);
		return;
	}

	mbl_repr->ual_priv = repr_meta;

	/* Stripe over the available PCIe units */
	while (!((priv->pcie_map >> scratchpad) & 0x1)) {
		scratchpad++;

		if (!(priv->pcie_map >> scratchpad))
			scratchpad = 0;
	}

	repr_meta->tx_vnic = scratchpad++;
	repr_meta->rx_vnic = repr_meta->tx_vnic;

	err = nfp_ual_set_port_id(repr, 0);
	if (err)
		pr_warn("unable to set %s port ID\n", repr->netdev->name);

	eth_port = nfp_ual_get_eth_port_from_repr(repr);
	if (!eth_port) {
		pr_err("%s: unable to get eth_port, bringup failed\n",
		       repr->netdev->name);
		return;
	}

	pr_info("%s: phys port representor\n", repr->netdev->name);
	pr_info("  eth_index=%u\n", eth_port->eth_index);
	pr_info("  nbi.base=%u.%u\n", eth_port->nbi, eth_port->base);
	pr_info("  label=%u.%u\n", eth_port->label_port,
		eth_port->label_subport);
	pr_info("  vNIC=rx:%u,tx:%u\n", repr_meta->rx_vnic, repr_meta->tx_vnic);

	err = nfp_ual_select_tx_dev(repr, repr_meta->tx_vnic);
	if (err)
		pr_warn("%s: unable to select data vNIC\n",
			repr->netdev->name);

	err = ualt_cmsg_port(repr, repr_meta->rx_vnic);
	if (err)
		pr_err("%s: unable to send port ctrl msg: %i\n",
		       repr->netdev->name, err);
}

static void ualt_cleanup_reprs(struct nfp_repr *repr, void *cookie)
{
	struct nfp_mbl_repr *mbl_repr = repr->app_priv;

	pr_info("%s: resetting representor\n", repr->netdev->name);

	nfp_ual_set_port_id(repr, NFP_UAL_PORTID_UNSPEC);
	nfp_ual_select_tx_dev(repr, 0);

	if (mbl_repr->ual_priv) {
		vfree(mbl_repr->ual_priv);
		mbl_repr->ual_priv = NULL;
	}
}

static int ualt_init(void *cookie, enum nfp_mbl_status_type status)
{
	struct ualt_cookie *priv = cookie;
	struct nfp_app *app;
	u64 version;
	int err, i;

	app = nfp_ual_get_app(NFP_MBL_DEV_INDEX_PRIMARY);
	version = nfp_rtsym_read_le(app->pf->rtbl, "_ualt_version", &err);
	if (err) {
		pr_warn("%s requires _ualt_version memory symbol\n", UALT_NAME);
		return err;
	}

	pr_info("starting %s version %02llx\n", UALT_NAME, version);

	err = nfp_ual_get_pcie_unit_count(&priv->pcie_map);
	if (err <= 0 || !priv->pcie_map) {
		pr_warn("%s: unable to determine PCIe count: %i\n", UALT_NAME,
			err);
		return err;
	}

	i = -1;
	while (priv->pcie_map >> ++i) {
		if (status == NFP_MBL_STATUS_SUCCESS)
			pr_info("%s: OPERATIONAL: device #%i %s\n", UALT_NAME,
				i, (((priv->pcie_map >> i) & 0x1) ?
					"<active>" : "<inactive>"));
		else
			pr_warn("%s: DEGRADED[%u]: device #%i %s\n", UALT_NAME,
				status, i, (((priv->pcie_map >> i) & 0x1) ?
					"<active>" : "<inactive>"));
	}

	nfp_ual_foreach_repr(NULL, cookie, ualt_bringup_reprs);

	return 0;
}

static void ualt_clean(void *cookie)
{
	nfp_ual_foreach_repr(NULL, cookie, ualt_cleanup_reprs);
}

static int ualt_repr_open(void *cookie, struct nfp_repr *repr)
{
	pr_info("%s: opened\n", repr->netdev->name);
	return 0;
}

static int ualt_repr_stop(void *cookie, struct nfp_repr *repr)
{
	pr_info("%s: stopped\n", repr->netdev->name);
	return 0;
}

const struct nfp_ual_ops ops = {
	.name = UALT_NAME,

	.init = ualt_init,
	.clean = ualt_clean,

	.repr_open = ualt_repr_open,
	.repr_stop = ualt_repr_stop,
};

static int __init nfp_ualt_module_init(void)
{
	struct ualt_cookie *priv;
	int err;

	priv = vzalloc(sizeof(*priv));
	if (!priv)
		return -ENOMEM;

	priv->label = 0xD000DDAD;

	err = nfp_ual_register(&ops, priv);
	if (err)
		goto err_free_priv;

	return 0;

err_free_priv:
	vfree(priv);
	return err;
}

static void __exit nfp_ualt_module_exit(void)
{
	struct ualt_cookie *priv;

	priv = nfp_ual_unregister();
	if (priv)
		vfree(priv);
}

module_init(nfp_ualt_module_init);
module_exit(nfp_ualt_module_exit);

MODULE_AUTHOR("Netronome Systems <oss-drivers@netronome.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("The Netronome Flow Processor (NFP) UAL test app.");
