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

#define NFP_MBL_PROBE_TIMEOUT	60

/* This is a global context data structure, shared by all NFP devices. */
static struct nfp_mbl_global_data *ctx;

static void nfp_mbl_probe_work(struct work_struct *work)
{
	if (ctx->ual_running)
		return;

	if (ctx->status != NFP_MBL_STATUS_SUCCESS)
		pr_warn("MBL timeout. Not all devices probed successfully.\n");

	/* If we hit this path, we have timed out. */
	ctx->status = NFP_MBL_STATUS_TIMEOUT;
	nfp_mbl_try_init_ual();
}

static int nfp_mbl_alloc_global_ctx(void)
{
	if (ctx)
		return -EEXIST;

	ctx = vzalloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	INIT_DELAYED_WORK(&ctx->probe_dw, nfp_mbl_probe_work);
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

	ctx->ual_running = true;
	return 0;
}

void nfp_mbl_stop_ual(void)
{
	ctx->ual_running = false;
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
	netif_tx_wake_all_queues(repr->netdev);

	/* Hardcode until we implement the link state monitoring. */
	netif_carrier_on(repr->netdev);
	return 0;
}

static int
nfp_mbl_app_repr_netdev_stop(struct nfp_app *app, struct nfp_repr *repr)
{
	netif_tx_disable(repr->netdev);

	/* Hardcode until we implement the link state monitoring. */
	netif_carrier_off(repr->netdev);
	return 0;
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
		ctx->status = NFP_MBL_STATUS_SUCCESS;

		/* No need to check the return code here, we can't really do
		 * anything about failures at this point. We definitely don't
		 * want to fail the probe if the UAL can't load. The UAL error
		 * handling can sort it out.
		 */
		nfp_mbl_try_init_ual();

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

	if (ctx->status == NFP_MBL_STATUS_PROBE)
		queue_delayed_work(system_long_wq, &ctx->probe_dw,
				   NFP_MBL_PROBE_TIMEOUT * HZ);

	nfp_mbl_calc_device_count();
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

const struct nfp_app_type app_mbl = {
	.id		= NFP_APP_MBL,
	.name		= "mbl",
	.ctrl_has_meta	= true,

	.init		= nfp_mbl_app_init,
	.clean		= nfp_mbl_app_clean,

	.init_complete	= nfp_mbl_app_init_complete,
	.clean_begin	= nfp_mbl_app_clean_begin,

	.vnic_alloc	= nfp_mbl_app_vnic_alloc,
	.vnic_init	= nfp_mbl_app_vnic_init,
	.vnic_clean	= nfp_mbl_app_vnic_clean,

	.repr_open	= nfp_mbl_app_repr_netdev_open,
	.repr_stop	= nfp_mbl_app_repr_netdev_stop,

	.eswitch_mode_get = eswitch_mode_get,
	.repr_get	= nfp_mbl_app_repr_get,
};
