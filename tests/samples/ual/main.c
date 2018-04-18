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

/* Set to non-zero to wait up to specified seconds for UAL registration to
 * succeed. This is useful for cases where other PCIe devices are known to not
 * present.
 */
static int nfp_ualt_wait = 5;
module_param(nfp_ualt_wait, int, 0644);
MODULE_PARM_DESC(nfp_ualt_wait, "Wait up to specified seconds for UAL registration if PCIe's not probed (Default 5s)");

#define UALT_NAME	"ualt_module"

struct ualt_app_meta {
	u32 timestamp_lo;
	u32 timestamp_hi;
};

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
	UALT_CMSG_HEARTBEAT =	2,
};

struct ualt_cmsg_port {
	u32 port_id;
	u8 flags;
	u8 pcie;
	u8 nbi;
	u8 port;
};

struct ualt_cmsg_heartbeat {
	u16 label;
	u8 me;
	u8 ctx;
};

#define UALT_PORTID_VLAN		GENMASK(18, 9)
#define UALT_NICMOD_PORT		BIT(7)

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

int ualt_cmsg_port(struct nfp_repr *repr, unsigned int port_id, u8 rx_vnic,
		   unsigned int flags)
{
	struct nfp_eth_table_port *eth_port;
	struct nfp_mbl_dev_ctx *dev_ctx;
	struct ualt_cmsg_port *msg;
	struct sk_buff *skb;

	eth_port = nfp_ual_get_eth_port_from_repr(repr);
	if (!eth_port)
		return -ENODEV;

	skb = ualt_cmsg_alloc(sizeof(*msg), UALT_CMSG_PORT);
	if (!skb)
		return -ENOMEM;

	dev_ctx = nfp_ual_get_mbl_dev_ctx_from_netdev(repr->netdev);

	msg = ualt_cmsg_get_data(skb);
	msg->port_id = port_id;
	msg->nbi = eth_port->nbi;
	msg->port = eth_port->eth_index;
	if (dev_ctx->type == NFP_MBL_DEV_TYPE_NICMOD)
		msg->port |= UALT_NICMOD_PORT;
	msg->pcie = rx_vnic;
	msg->flags = flags;

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

	err = ualt_cmsg_port(repr, nfp_ual_get_port_id(repr),
			     repr_meta->rx_vnic, UALT_PORT_FLAG_ADD);
	if (err)
		pr_err("%s: unable to send port ctrl msg: %i\n",
		       repr->netdev->name, err);

	err = ualt_debugfs_add_repr(priv, repr);
	if (err)
		pr_err("%s: unable to create debugfs entry\n",
		       repr->netdev->name);
}

static void ualt_cleanup_reprs(struct nfp_repr *repr, void *cookie)
{
	struct nfp_mbl_repr *mbl_repr = repr->app_priv;

	pr_info("%s: resetting representor\n", repr->netdev->name);

	nfp_ual_set_port_id(repr, NFP_UAL_PORTID_UNSPEC);
	nfp_ual_select_tx_dev(repr, 0);
	ualt_cmsg_port(repr, nfp_ual_get_port_id(repr), 0,
		       UALT_PORT_FLAG_REMOVE);

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
	priv->status = status;

	return 0;
}

static void ualt_clean(void *cookie)
{
	struct ualt_cookie *priv = cookie;

	ualt_debugfs_destroy_reprs(priv);
	nfp_ual_foreach_repr(NULL, cookie, ualt_cleanup_reprs);

	priv->status = UALT_STATUS_UNINITIALIZED;
}

static void ualt_free(void **cookie)
{
	struct ualt_cookie *priv = *cookie;

	ualt_debugfs_destroy(priv);
	vfree(priv);
	cookie = NULL;
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

/* The app specific metadata is as the name suggests app specific.
 * The following code only serves an a very simplistic example, that reads a
 * timestamp word from the packet. On TX, the system timestamp is inserted
 * into the packet metadata.
 *
 * The app can set the metadata fields any way it wants, but it needs to take
 * the following assumptions into account:
 * 1) The app_meta_desc field must be non-zero whenever the app has parsed
 *    any metadata.
 * 2) The app_meta field is a total of 64bits in length. This could potentially
 *    be used to store a pointer to an app specific data struct if the app
 *    wishes to do so. Any memory allocated during the parse_meta callback must
 *    be freed again in the skb_set_meta handler.
 *    It is not recommended to allocate memory for this, it may be required on a
 *    case by case basis.
 */

#define UALT_APP_META_POPULATED	1

static int
ualt_parse_meta(void *cookie, struct net_device *netdev,
		struct nfp_meta_parsed *meta, char *data, int meta_len)
{
	struct ualt_app_meta *app_meta =
		(struct ualt_app_meta *)&meta->app_meta_data;

	BUILD_BUG_ON(sizeof(*app_meta) != sizeof(meta->app_meta_data));

	meta->app_meta_desc = UALT_APP_META_POPULATED;
	app_meta->timestamp_lo = get_unaligned_be32(data);
	app_meta->timestamp_hi = get_unaligned_be32(data + 4);

	return sizeof(*app_meta);
}

static void ualt_skb_set_meta(void *cookie, struct sk_buff *skb,
			      struct nfp_meta_parsed *meta)
{
	struct ualt_app_meta *app_meta =
		(struct ualt_app_meta *)&meta->app_meta_data;

	pr_debug("rx-ts=0x%08x 0x%08x\n", app_meta->timestamp_lo,
		 app_meta->timestamp_hi);
}

static int ualt_prep_tx_meta(void *cookie, struct sk_buff *skb)
{
	struct ualt_cookie *priv = cookie;
	unsigned char *data;

	if (unlikely(skb_cow_head(skb, 8)))
		return -ENOMEM;

	data = skb_push(skb, 8);
	put_unaligned_be32((u32)jiffies, data);
	put_unaligned_be32(priv->label, data + 4);
	pr_debug("tx-ts=0x%08x 0x%08x\n", (u32)jiffies, priv->label);

	return 8;
}

static void ualt_ctrl_msg_rx(void *cookie, struct sk_buff *skb)
{
	struct ualt_cmsg_heartbeat *payload;
	struct ualt_cmsg_hdr *cmsg_hdr;

	cmsg_hdr = ualt_cmsg_get_hdr(skb);

	if (unlikely(cmsg_hdr->version != UALT_CMSG_VERSION)) {
		pr_warn("cannot handle control message version %u\n",
			cmsg_hdr->version);
		goto out_free_skb;
	}

	if (cmsg_hdr->type == UALT_CMSG_HEARTBEAT) {
		payload = ualt_cmsg_get_data(skb);
		pr_debug("rx-heartbeat=[%d/%d]:0x%04x\n", payload->ctx,
			 payload->me, payload->label);
	} else {
		pr_warn("discarding, no handler available for cmsg type %d\n",
			cmsg_hdr->type);
		goto out_free_skb;
	}

out_free_skb:
	dev_kfree_skb_any(skb);
}

static int
ualt_sriov_enable(void *cookie, struct nfp_mbl_dev_ctx *ctx, int num_vfs)
{
	dev_info(&ctx->app->pf->pdev->dev, "created %i VFs\n", num_vfs);
	return 0;
}

static void ualt_sriov_disable(void *cookie, struct nfp_mbl_dev_ctx *ctx)
{
	dev_info(&ctx->app->pf->pdev->dev, "destroyed VFs\n");
}

static int
ualt_repr_vlan_rx_add_vid(void *cookie, struct net_device *netdev, __be16 proto,
			  u16 vid)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct ualt_repr_meta *meta;
	unsigned int port_id;
	int err;

	/* Do nothing for filter with VID 0. */
	if (!vid)
		return 0;

	meta = ualt_get_repr_meta(repr);
	if (!meta)
		return -ENODEV;

	port_id = nfp_ual_get_port_id(repr);
	port_id |= FIELD_PREP(UALT_PORTID_VLAN, vid);

	pr_info("%s: added VLAN %u with port ID 0x%08x\n", netdev->name, vid,
		port_id);

	err = ualt_cmsg_port(repr, port_id, meta->rx_vnic, UALT_PORT_FLAG_ADD);
	if (err)
		pr_err("%s: unable to send port ctrl msg: %i\n",
		       repr->netdev->name, err);

	return err;
}

static int
ualt_repr_vlan_rx_kill_vid(void *cookie, struct net_device *netdev,
			   __be16 proto, u16 vid)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	unsigned int port_id;
	int err;

	port_id = nfp_ual_get_port_id(repr);
	port_id |= FIELD_PREP(UALT_PORTID_VLAN, vid);

	pr_info("%s: removed VLAN %u with port ID 0x%08x\n", netdev->name, vid,
		port_id);

	err = ualt_cmsg_port(repr, port_id, 0, UALT_PORT_FLAG_REMOVE);
	if (err)
		pr_err("%s: unable to send port ctrl msg: %i\n",
		       repr->netdev->name, err);

	return err;
}

static u32
ualt_repr_get_vlan_portid(void *cookie, struct net_device *netdev, __be16 proto,
			  u16 vid)
{
	return FIELD_PREP(UALT_PORTID_VLAN, vid);
}

static int
ualt_repr_change_mtu(void *cookie, struct net_device *netdev, int new_mtu)
{
	pr_info("%s: updated repr MTU to %i\n", netdev->name, new_mtu);
	return 0;
}

static int
ualt_vnic_change_mtu(void *cookie, struct nfp_mbl_dev_ctx *ctx,
		     struct net_device *netdev, int new_mtu)
{
	pr_info("%s: updated vNIC #%u MTU to %i\n", netdev->name,
		ctx->pcie_unit, new_mtu);
	return 0;
}

static int
ualt_repr_set_mac_address(void *cookie, struct net_device *netdev, void *addr)
{
	struct sockaddr *saddr = addr;

	pr_info("%s: updated repr MAC: %pM\n", netdev->name, saddr->sa_data);
	return 0;
}

const struct nfp_ual_ops ops = {
	.name = UALT_NAME,
	.spawn_vf_reprs = false,

	.init = ualt_init,
	.clean = ualt_clean,
	.free = ualt_free,

	.repr_open = ualt_repr_open,
	.repr_stop = ualt_repr_stop,

	.parse_meta = ualt_parse_meta,
	.skb_set_meta = ualt_skb_set_meta,
	.prep_tx_meta = ualt_prep_tx_meta,

	.vnic_change_mtu = ualt_vnic_change_mtu,

	.ctrl_msg_rx = ualt_ctrl_msg_rx,

	.sriov_enable = ualt_sriov_enable,
	.sriov_disable = ualt_sriov_disable,

	.repr_vlan_rx_add_vid = ualt_repr_vlan_rx_add_vid,
	.repr_vlan_rx_kill_vid = ualt_repr_vlan_rx_kill_vid,
	.repr_get_vlan_portid = ualt_repr_get_vlan_portid,

	.repr_change_mtu = ualt_repr_change_mtu,
	.repr_set_mac_address = ualt_repr_set_mac_address,
};

static int __init nfp_ualt_module_init(void)
{
	const unsigned long wait_until = jiffies + nfp_ualt_wait * HZ;
	struct ualt_cookie *priv;
	int err;

	priv = vzalloc(sizeof(*priv));
	if (!priv)
		return -ENOMEM;

	priv->label = 0xD000DDAD;
	priv->status = UALT_STATUS_UNINITIALIZED;

	err = ualt_debugfs_create(priv);
	if (err)
		goto err_free_priv;

	err = nfp_ual_register(&ops, priv);
	while (err == -EAGAIN) {
		if (time_is_before_eq_jiffies(wait_until)) {
			pr_err("UAL registration timeout\n");
			break;
		}

		if (msleep_interruptible(1000)) {
			err = -ERESTARTSYS;
			break;
		}

		pr_warn("retrying UAL registration\n");
		err = nfp_ual_register(&ops, priv);
	}
	if (err)
		goto err_debugfs_destroy;

	return 0;

err_debugfs_destroy:
	ualt_debugfs_destroy(priv);
err_free_priv:
	vfree(priv);
	return err;
}

static void __exit nfp_ualt_module_exit(void)
{
	nfp_ual_unregister();
}

module_init(nfp_ualt_module_init);
module_exit(nfp_ualt_module_exit);

MODULE_AUTHOR("Netronome Systems <oss-drivers@netronome.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("The Netronome Flow Processor (NFP) UAL test app.");
