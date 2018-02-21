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

#include "nfp_net_compat.h"

#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <net/devlink.h>
#include <net/dst_metadata.h>

#include "main.h"
#include "nfpcore/nfp_cpp.h"
#include "nfpcore/nfp_nsp.h"
#include "nfp_app.h"
#include "nfp_main.h"
#include "nfp_net.h"
#include "nfp_net_repr.h"
#include "nfp_port.h"
#include "nfp_ual.h"

/* Timeout in seconds to wait for more devices to probe. */
#define NFP_MBL_PROBE_TIMEOUT	60

/* Link state monitoring interval in ms */
#define NFP_MBL_LINK_TIMER	750

/* This is a global context data structure, shared by all NFP devices. */
static struct nfp_mbl_global_data *ctx;

static void nfp_mbl_probe_work(struct work_struct *work)
{
	mutex_lock(&ctx->mbl_lock);
	if (ctx->ual_running)
		goto out_unlock;

	if (ctx->status != NFP_MBL_STATUS_SUCCESS)
		pr_warn("MBL timeout. Not all devices probed successfully.\n");

	/* If we hit this path, we have timed out. */
	ctx->status = NFP_MBL_STATUS_TIMEOUT;
	nfp_mbl_try_init_ual();

out_unlock:
	mutex_unlock(&ctx->mbl_lock);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static void nfp_mbl_phys_link_timer(unsigned long timer)
#else
static void nfp_mbl_phys_link_timer(struct timer_list *timer)
#endif
{
	struct nfp_pf *pf;

	if (!NFP_MBL_PRIMARY_DEV_CTX(ctx))
		return;

	pf = NFP_MBL_PRIMARY_DEV_CTX(ctx)->app->pf;

	queue_work(pf->wq, &pf->port_refresh_work);
	mod_timer(&ctx->link_timer, jiffies + NFP_MBL_LINK_TIMER * HZ / 1000);
}

static int nfp_mbl_alloc_global_ctx(void)
{
	if (ctx)
		return -EEXIST;

	ctx = vzalloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	timer_setup(&ctx->link_timer, nfp_mbl_phys_link_timer, 0);
	INIT_DELAYED_WORK(&ctx->probe_dw, nfp_mbl_probe_work);
	mutex_init(&ctx->mbl_lock);
	return 0;
}

static void nfp_mbl_dealloc_ctx(int dev_index)
{
	if (!ctx->dev_ctx[dev_index])
		return;

	ctx->dev_ctx[dev_index] = NULL;
	ctx->ref_count--;

	WARN_ON(ctx->ref_count < 0);

	if (!ctx->ref_count) {
		cancel_delayed_work_sync(&ctx->probe_dw);
		del_timer_sync(&ctx->link_timer);

		vfree(ctx);
		ctx = NULL;
	}
}

struct nfp_mbl_global_data *nfp_mbl_get_global_ctx(void)
{
	return ctx;
}

int nfp_mbl_try_init_ual(void)
{
	if (ctx->status == NFP_MBL_STATUS_PROBE)
		return -EAGAIN;

	if (!ctx->ual_ops)
		return -EAGAIN;

	ctx->ual_running = true;
	if (ctx->ual_ops->init)
		return ctx->ual_ops->init(ctx->ual_cookie, ctx->status);

	return 0;
}

static void nfp_mbl_repr_close_cb(struct nfp_repr *repr, void *cookie)
{
	if (!netif_running(repr->netdev))
		return;

	netdev_warn(repr->netdev, "closing device\n");
	dev_close(repr->netdev);
}

void nfp_mbl_stop_ual(void)
{
	mutex_lock(&ctx->mbl_lock);
	if (!ctx->ual_ops || !ctx->ual_running)
		goto out_unlock;

	/* To ensure we are left in a sane state, close all representors. */
	nfp_ual_foreach_repr(NULL, NULL, nfp_mbl_repr_close_cb);

	ctx->ual_running = false;
	if (ctx->ual_ops->clean)
		ctx->ual_ops->clean(ctx->ual_cookie);

out_unlock:
	mutex_unlock(&ctx->mbl_lock);
}

static enum devlink_eswitch_mode eswitch_mode_get(struct nfp_app *app)
{
	return DEVLINK_ESWITCH_MODE_SWITCHDEV;
}

static struct net_device *
nfp_mbl_app_repr_get(struct nfp_app *app, u32 port_id)
{
	struct nfp_reprs *reprs;
	struct nfp_app *dp_app;
	int dev, type, index;

	dev = FIELD_GET(NFP_MBL_PORTID_MBL_DEV_MASK, port_id);
	type = FIELD_GET(NFP_MBL_PORTID_MBL_TYPE_MASK, port_id);
	index = FIELD_GET(NFP_MBL_PORTID_MBL_INDEX_MASK, port_id);

	if (dev >= NFP_MBL_DEV_INDEX_MAX || !ctx->dev_ctx[dev])
		return NULL;

	dp_app = ctx->dev_ctx[dev]->app;
	if (!dp_app)
		return NULL;

	if (type > NFP_REPR_TYPE_MAX)
		return NULL;

	reprs = rcu_dereference(dp_app->reprs[type]);
	if (!reprs)
		return NULL;

	if (index >= reprs->num_reprs)
		return NULL;

	return rcu_dereference(reprs->reprs[index]);
}

static int
nfp_mbl_app_repr_netdev_open(struct nfp_app *app, struct nfp_repr *repr)
{
	int err;

	if (!ctx->ual_ops || !ctx->ual_ops->repr_open)
		return -EOPNOTSUPP;

	err = ctx->ual_ops->repr_open(ctx->ual_cookie, repr);
	if (err)
		return err;

	netif_tx_wake_all_queues(repr->netdev);
	return 0;
}

static int
nfp_mbl_app_repr_netdev_stop(struct nfp_app *app, struct nfp_repr *repr)
{
	if (!ctx->ual_ops || !ctx->ual_ops->repr_stop)
		return -EOPNOTSUPP;

	netif_tx_disable(repr->netdev);

	return ctx->ual_ops->repr_stop(ctx->ual_cookie, repr);
}

static int
nfp_mbl_app_spawn_vnic_reprs(struct nfp_app *app, unsigned int cnt)
{
	struct nfp_mbl_dev_ctx *dev_ctx = app->priv;
	struct nfp_reprs *reprs;
	int i, err, dev_index;

	reprs = nfp_reprs_alloc(cnt);
	if (!reprs)
		return -ENOMEM;

	dev_index = NFP_MBL_DEV_INDEX(dev_ctx->type, dev_ctx->pcie_unit);
	for (i = 0; i < cnt; i++) {
		struct net_device *repr;
		struct nfp_port *port;
		u32 port_id;

		repr = nfp_repr_alloc(app);
		if (!repr) {
			err = -ENOMEM;
			goto err_reprs_clean;
		}
		RCU_INIT_POINTER(reprs->reprs[i], repr);

		port = nfp_port_alloc(app, NFP_PORT_VF_PORT, repr);
		port->pf_id = dev_ctx->pcie_unit;
		port->vf_id = i;
		port->vnic = app->pf->vf_cfg_mem + i * NFP_NET_CFG_BAR_SZ;

		eth_hw_addr_random(repr);

		port_id = nfp_mbl_portid(dev_index, NFP_REPR_TYPE_VF,
					 port->vf_id);
		err = nfp_repr_init(app, repr,
				    port_id, port, dev_ctx->nn->dp.netdev);
		if (err) {
			nfp_port_free(port);
			goto err_reprs_clean;
		}

		nfp_info(app->cpp,
			 "VF%d Representor(%s) created with ID 0x%08x\n", i,
			 repr->name, port_id);
	}

	nfp_app_reprs_set(app, NFP_REPR_TYPE_VF, reprs);

	return 0;

err_reprs_clean:
	nfp_reprs_clean_and_free(app, reprs);
	return err;
}

static int
nfp_mbl_app_spawn_phy_reprs(struct nfp_app *app)
{
	struct nfp_eth_table *eth_tbl = app->pf->eth_tbl;
	struct nfp_mbl_dev_ctx *primary, *dev_ctx;
	struct nfp_reprs *reprs;
	int err, dev_index;
	unsigned int i;

	reprs = nfp_reprs_alloc(eth_tbl->max_index + 1);
	if (!reprs)
		return -ENOMEM;

	primary = NFP_MBL_PRIMARY_DEV_CTX(ctx);
	dev_ctx = app->priv;

	if (!primary)
		return -ENODEV;

	dev_index = NFP_MBL_DEV_INDEX(dev_ctx->type, dev_ctx->pcie_unit);
	for (i = 0; i < eth_tbl->count; i++) {
		unsigned int phys_port = eth_tbl->ports[i].index;
		struct net_device *repr;
		struct nfp_port *port;
		u32 port_id;

		repr = nfp_repr_alloc(app);
		if (!repr) {
			err = -ENOMEM;
			goto err_reprs_clean;
		}
		RCU_INIT_POINTER(reprs->reprs[phys_port], repr);

		port = nfp_port_alloc(app, NFP_PORT_PHYS_PORT, repr);
		if (IS_ERR(port)) {
			err = PTR_ERR(port);
			goto err_reprs_clean;
		}
		err = nfp_port_init_phy_port(app->pf, app, port, i);
		if (err) {
			nfp_port_free(port);
			goto err_reprs_clean;
		}

		SET_NETDEV_DEV(repr, &primary->nn->pdev->dev);
		nfp_net_get_mac_addr(app->pf, port);

		port_id = nfp_mbl_portid(dev_index, NFP_REPR_TYPE_PHYS_PORT,
					 phys_port);
		err = nfp_repr_init(app, repr, port_id, port,
				    primary->nn->dp.netdev);
		if (err) {
			nfp_port_free(port);
			goto err_reprs_clean;
		}

		nfp_info(app->cpp, "Phys Port %d Representor(%s) created with ID 0x%08x\n",
			 phys_port, repr->name, port_id);
	}

	nfp_app_reprs_set(app, NFP_REPR_TYPE_PHYS_PORT, reprs);

	return 0;

err_reprs_clean:
	nfp_reprs_clean_and_free(app, reprs);
	return err;
}

static int nfp_mbl_sriov_enable(struct nfp_app *app, int num_vfs)
{
	struct nfp_mbl_dev_ctx *dev_ctx = app->priv;
	int err;

	if (!ctx->ual_ops)
		return -EOPNOTSUPP;

	if (ctx->ual_ops->spawn_vf_reprs) {
		if (!dev_ctx->nn)
			return 0;

		err = nfp_mbl_app_spawn_vnic_reprs(app, num_vfs);
		if (err)
			return err;
	}

	if (ctx->ual_ops->sriov_enable) {
		err = ctx->ual_ops->sriov_enable(ctx->ual_cookie, dev_ctx,
						 num_vfs);
		if (err)
			goto err_destroy_reprs_vf;
	}

	return 0;

err_destroy_reprs_vf:
	nfp_reprs_clean_and_free_by_type(app, NFP_REPR_TYPE_VF);
	return err;
}

static void nfp_mbl_sriov_disable(struct nfp_app *app)
{
	struct nfp_mbl_dev_ctx *dev_ctx = app->priv;

	if (!dev_ctx->nn)
		return;

	if (ctx->ual_ops && ctx->ual_ops->sriov_disable)
		ctx->ual_ops->sriov_disable(ctx->ual_cookie, dev_ctx);

	nfp_reprs_clean_and_free_by_type(app, NFP_REPR_TYPE_VF);
}

static int nfp_mbl_app_vnic_alloc(struct nfp_app *app, struct nfp_net *nn,
				  unsigned int id)
{
	if (id > 0) {
		nfp_warn(app->cpp, "MBL doesn't support more than one data vNIC per PCIe\n");
		goto err_invalid_port;
	}

	eth_hw_addr_random(nn->dp.netdev);
	netif_keep_dst(nn->dp.netdev);

	return 0;

err_invalid_port:
	nn->port = nfp_port_alloc(app, NFP_PORT_INVALID, nn->dp.netdev);
	return PTR_ERR_OR_ZERO(nn->port);
}

static void nfp_mbl_app_vnic_clean(struct nfp_app *app, struct nfp_net *nn)
{
	struct nfp_mbl_dev_ctx *dev_ctx = app->priv;

	if (app->pf->num_vfs)
		nfp_reprs_clean_and_free_by_type(app, NFP_REPR_TYPE_VF);
	nfp_reprs_clean_and_free_by_type(app, NFP_REPR_TYPE_PHYS_PORT);

	dev_ctx->nn = NULL;
	ctx->init_count--;
	ctx->status = NFP_MBL_STATUS_UNBOUND;
}

static int nfp_mbl_app_vnic_init(struct nfp_app *app, struct nfp_net *nn)
{
	struct nfp_mbl_dev_ctx *dev_ctx = app->priv;
	int err;

	if (app->pf->num_vfs) {
		nfp_err(app->cpp, "SR-IOV VFs must be disabled before initializing the MBL\n");
		return -EOPNOTSUPP;
	}

	dev_ctx->nn = nn;

	/* We only spawn representors for PCIe #0 */
	if (dev_ctx->pcie_unit == 0) {
		err = nfp_mbl_app_spawn_phy_reprs(app);
		if (err)
			goto err_clear_nn;
	}

	return 0;

err_clear_nn:
	dev_ctx->nn = NULL;
	return err;
}

static int nfp_mbl_repr_init(struct nfp_app *app, struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_mbl_repr *repr_priv;

	repr_priv = vzalloc(sizeof(*repr_priv));
	if (!repr_priv)
		return -ENOMEM;

	repr->app_priv = repr_priv;

	return 0;
}

static void nfp_mbl_repr_clean(struct nfp_app *app, struct net_device *netdev)
{
	struct nfp_repr *repr = netdev_priv(netdev);

	vfree(repr->app_priv);
}

static int nfp_mbl_calc_device_count(void)
{
	/* multi-PCIe support not yet available */
	return 1;
}

static void nfp_mbl_app_init_complete(struct nfp_app *app)
{
	struct nfp_mbl_dev_ctx *dev_ctx = app->priv;
	int need = nfp_mbl_calc_device_count();

	/* The app is ready for the UAL when its vNICs have been initialized. */
	ctx->init_count++;

	/* This is a violation of probing order for the app. */
	if (WARN_ON(need < 0))
		return;

	if (dev_ctx->nn)
		nfp_info(app->cpp,
			 "registered device #%u.%u, data vNIC is %s\n",
			 dev_ctx->type, dev_ctx->pcie_unit,
			 dev_ctx->nn->dp.netdev->name);
	else
		nfp_info(app->cpp, "registered device #%u.%u\n",
			 dev_ctx->type, dev_ctx->pcie_unit);

	if (ctx->init_count >= need) {
		mutex_lock(&ctx->mbl_lock);

		ctx->status = NFP_MBL_STATUS_SUCCESS;

		/* No need to check the return code here, we can't really do
		 * anything about failures at this point. We definitely don't
		 * want to fail the probe if the UAL can't load. The UAL error
		 * handling can sort it out.
		 */
		nfp_mbl_try_init_ual();

		mutex_unlock(&ctx->mbl_lock);

		cancel_delayed_work_sync(&ctx->probe_dw);
	} else {
		nfp_info(app->cpp,
			 "waiting, only have %d of %d devices registered\n",
			 ctx->init_count, need);
	}
}

static void nfp_mbl_app_clean_begin(struct nfp_app *app)
{
	nfp_mbl_stop_ual();
}

static int nfp_mbl_app_init(struct nfp_app *app)
{
	const struct nfp_pf *pf = app->pf;
	struct nfp_mbl_dev_ctx *dev_ctx;
	enum nfp_mbl_dev_type type;
	int err, dev_index;
	u8 nfp_pcie;

	if (!ctx) {
		err = nfp_mbl_alloc_global_ctx();
		if (err)
			return err;
	}

	type = NFP_MBL_DEV_TYPE_MASTER_PF;
	nfp_pcie = nfp_cppcore_pcie_unit(app->pf->cpp);
	dev_index = NFP_MBL_DEV_INDEX(type, nfp_pcie);

	if (nfp_pcie == 0) {
		if (!pf->eth_tbl) {
			nfp_warn(app->cpp, "MBL requires eth table\n");
			err = -EINVAL;
			goto err_dealloc_dev_ctx;
		}

		if (!pf->mac_stats_bar) {
			nfp_warn(app->cpp, "MBL requires mac_stats BAR\n");
			err = -EINVAL;
			goto err_dealloc_dev_ctx;
		}
	}

	if (!pf->vf_cfg_bar) {
		nfp_warn(app->cpp, "MBL requires vf_cfg BAR\n");
		err = -EINVAL;
		goto err_dealloc_dev_ctx;
	}

	if (ctx->dev_ctx[dev_index]) {
		nfp_warn(app->cpp, "MBL already has device #%u.%u registered\n",
			 type, nfp_pcie);
		err = -EINVAL;
		goto err_dealloc_dev_ctx;
	}

	dev_ctx = vzalloc(sizeof(*dev_ctx));
	dev_ctx->app = app;
	dev_ctx->type = type;
	dev_ctx->pcie_unit = nfp_pcie;

	ctx->dev_ctx[dev_index] = dev_ctx;
	ctx->ref_count++;

	app->priv = dev_ctx;

	mutex_lock(&ctx->mbl_lock);
	if (ctx->status == NFP_MBL_STATUS_PROBE)
		queue_delayed_work(system_long_wq, &ctx->probe_dw,
				   NFP_MBL_PROBE_TIMEOUT * HZ);
	mutex_unlock(&ctx->mbl_lock);

	if (!timer_pending(&ctx->link_timer)) {
		mod_timer(&ctx->link_timer,
			  jiffies + NFP_MBL_LINK_TIMER * HZ / 1000);
	}

	return 0;

err_dealloc_dev_ctx:
	nfp_mbl_dealloc_ctx(dev_index);
	return err;
}

static void nfp_mbl_app_clean(struct nfp_app *app)
{
	struct nfp_mbl_dev_ctx *dev_ctx = app->priv;

	/* Note that the UAL has already been stopped at this point. */
	pr_info("Unregistering device #%u.%u\n", dev_ctx->type,
		dev_ctx->pcie_unit);

	nfp_mbl_dealloc_ctx(NFP_MBL_DEV_INDEX(dev_ctx->type,
					      dev_ctx->pcie_unit));

	vfree(app->priv);
	app->priv = NULL;
}

static int
nfp_mbl_check_mtu(struct nfp_app *app, struct net_device *netdev, int new_mtu)
{
	struct nfp_mbl_dev_ctx *priv = app->priv;

	if (nfp_netdev_is_nfp_repr(netdev)) {
		if (ctx->ual_ops && ctx->ual_ops->repr_change_mtu)
			return ctx->ual_ops->repr_change_mtu(ctx->ual_cookie,
							     netdev, new_mtu);
	} else {
		if (ctx->ual_ops && ctx->ual_ops->vnic_change_mtu)
			return ctx->ual_ops->vnic_change_mtu(ctx->ual_cookie,
							     priv, netdev,
							     new_mtu);
	}

	/* This cannot occur */
	return -EOPNOTSUPP;
}

static int
nfp_mbl_parse_meta(struct nfp_app *app, struct net_device *netdev,
		   struct nfp_meta_parsed *meta, char *data,
		   int meta_len)
{
	if (!ctx->ual_ops || !ctx->ual_ops->parse_meta)
		return -EOPNOTSUPP;

	return ctx->ual_ops->parse_meta(ctx->ual_cookie, netdev, meta, data,
					meta_len);
}

static void
nfp_mbl_skb_set_meta(struct nfp_app *app, struct sk_buff *skb,
		     struct nfp_meta_parsed *meta)
{
	if (!ctx->ual_ops || !ctx->ual_ops->skb_set_meta)
		return;

	ctx->ual_ops->skb_set_meta(ctx->ual_cookie, skb, meta);
}

static int
nfp_mbl_prep_tx_meta(struct nfp_app *app, struct sk_buff *skb)
{
	if (!ctx->ual_ops || !ctx->ual_ops->prep_tx_meta)
		return 0;

	return ctx->ual_ops->prep_tx_meta(ctx->ual_cookie, skb);
}

static void nfp_mbl_app_ctrl_msg_rx(struct nfp_app *app, struct sk_buff *skb)
{
	if (!ctx->ual_ops || !ctx->ual_ops->ctrl_msg_rx) {
		pr_warn("discarding cmsg without handler\n");
		dev_kfree_skb_any(skb);
		return;
	}

	ctx->ual_ops->ctrl_msg_rx(ctx->ual_cookie, skb);
}

static int
nfp_mbl_repr_vlan_rx_add_vid(struct nfp_app *app,
			     struct net_device *netdev, __be16 proto,
			     u16 vid)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_mbl_repr *repr_priv;
	u32 vport_id;
	int err;

	if (!ctx->ual_ops || !ctx->ual_ops->repr_vlan_rx_add_vid ||
	    !ctx->ual_ops->repr_get_vlan_portid)
		return 0;

	repr_priv = repr->app_priv;
	if (!repr->dst || repr->dst->type != METADATA_HW_PORT_MUX)
		return -EINVAL;

	err = ctx->ual_ops->repr_vlan_rx_add_vid(ctx->ual_cookie, netdev,
						 proto, vid);
	if (err)
		return err;

	vport_id = ctx->ual_ops->repr_get_vlan_portid(ctx->ual_cookie,
						      repr->netdev, proto, vid);

	repr_priv->vlan_dst[vid] = metadata_dst_alloc(0, METADATA_HW_PORT_MUX,
						      GFP_KERNEL);
	if (!repr_priv->vlan_dst[vid]) {
		err = -ENOMEM;
		goto err_kill_vid;
	}

	repr_priv->vlan_dst[vid]->u.port_info.port_id =
		(repr->dst->u.port_info.port_id & NFP_MBL_PORTID_MBL_MASK) |
		(vport_id & NFP_MBL_PORTID_UAL_MASK);

	/* Intentionally don't set a valid lower dev. This MUST always be
	 * overwritten for each packet to dynamically slave to the repr's
	 * lower dev.
	 */
	repr_priv->vlan_dst[vid]->u.port_info.lower_dev = NULL;

err_kill_vid:
	if (ctx->ual_ops->repr_vlan_rx_kill_vid)
		ctx->ual_ops->repr_vlan_rx_kill_vid(ctx->ual_cookie, netdev,
						    proto, vid);
	return err;
}

static int
nfp_mbl_repr_vlan_rx_kill_vid(struct nfp_app *app,
			      struct net_device *netdev, __be16 proto,
			      u16 vid)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_mbl_repr *repr_priv;

	if (!ctx->ual_ops || !ctx->ual_ops->repr_vlan_rx_kill_vid)
		return 0;

	repr_priv = repr->app_priv;
	dst_release((struct dst_entry *)repr_priv->vlan_dst[vid]);

	return ctx->ual_ops->repr_vlan_rx_kill_vid(ctx->ual_cookie, netdev,
						   proto, vid);
}

static int
nfp_mbl_repr_xmit(struct nfp_app *app, struct sk_buff *skb,
		  struct nfp_repr *repr)
{
	struct nfp_mbl_repr *repr_priv = repr->app_priv;
	u16 vid;

	if (!skb_vlan_tag_present(skb))
		return 0;

	vid = skb_vlan_tag_get(skb);

	skb_dst_drop(skb);
	dst_hold((struct dst_entry *)repr_priv->vlan_dst[vid]);
	skb_dst_set(skb, (struct dst_entry *)repr_priv->vlan_dst[vid]);
	skb->dev = repr->dst->u.port_info.lower_dev;

	return 0;
}

const struct nfp_app_type app_mbl = {
	.id		= NFP_APP_MBL,
	.name		= "mbl",
	.ctrl_has_meta	= true,
	.repr_link_from_eth = true,

	.init		= nfp_mbl_app_init,
	.clean		= nfp_mbl_app_clean,

	.init_complete	= nfp_mbl_app_init_complete,
	.clean_begin	= nfp_mbl_app_clean_begin,

	.vnic_alloc	= nfp_mbl_app_vnic_alloc,
	.vnic_init	= nfp_mbl_app_vnic_init,
	.vnic_clean	= nfp_mbl_app_vnic_clean,

	.repr_init	= nfp_mbl_repr_init,
	.repr_clean	= nfp_mbl_repr_clean,

	.repr_open	= nfp_mbl_app_repr_netdev_open,
	.repr_stop	= nfp_mbl_app_repr_netdev_stop,

	.ctrl_msg_rx	= nfp_mbl_app_ctrl_msg_rx,

	.sriov_enable	= nfp_mbl_sriov_enable,
	.sriov_disable	= nfp_mbl_sriov_disable,

	.eswitch_mode_get = eswitch_mode_get,
	.repr_get	= nfp_mbl_app_repr_get,
	.check_mtu	= nfp_mbl_check_mtu,

	.repr_xmit	= nfp_mbl_repr_xmit,
	.repr_vlan_rx_add_vid = nfp_mbl_repr_vlan_rx_add_vid,
	.repr_vlan_rx_kill_vid = nfp_mbl_repr_vlan_rx_kill_vid,

	.parse_meta	= nfp_mbl_parse_meta,
	.skb_set_meta	= nfp_mbl_skb_set_meta,
	.prep_tx_meta	= nfp_mbl_prep_tx_meta,
};
