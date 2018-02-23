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

#include "main.h"
#include "nfp_main.h"
#include "nfp_net_repr.h"
#include "nfp_port.h"
#include "nfp_ual.h"

/**
 * nfp_ual_register() - register an UAL ops structure
 * @ops:	reference to callback functions
 * @cookie:	opaque pointer passed to all callbacks
 *
 * MBL needs to be instantiated before the UAL can be registered, i.e.
 * at least one device needs to be bound to the driver.
 *
 * Return: negative ERRNO or 0 for success
 */
int nfp_ual_register(const struct nfp_ual_ops *ops, void *cookie)
{
	struct nfp_mbl_global_data *ctx;
	struct nfp_mbl_dev_ctx *dev_ctx;
	struct device *dev;
	int err;

	if (WARN_ON(!ops || !ops->name))
		return -EINVAL;

	ctx = nfp_mbl_get_global_ctx();
	if (!ctx)
		return -EAGAIN;

	if (ctx->ual_ops)
		return -EEXIST;

	mutex_lock(&ctx->mbl_lock);
	ctx->ual_cookie = cookie;
	ctx->ual_ops = ops;

	dev_ctx = ctx->dev_ctx[NFP_MBL_DEV_INDEX_PRIMARY];
	if (dev_ctx) {
		dev = &dev_ctx->app->pf->pdev->dev;
		dev_info(dev, "registered new UAL, %s\n", ctx->ual_ops->name);
	}

	err = nfp_mbl_try_init_ual();
	if (err)
		goto err_reset_ual;

	mutex_unlock(&ctx->mbl_lock);
	cancel_delayed_work_sync(&ctx->probe_dw);
	return 0;

err_reset_ual:
	ctx->ual_cookie = NULL;
	ctx->ual_ops = NULL;
	mutex_unlock(&ctx->mbl_lock);
	return err;
}

/**
 * nfp_ual_unregister() - unregister an UAL
 *
 * Return: opaque cookie UAL was registered with
 */
void *nfp_ual_unregister(void)
{
	struct nfp_mbl_global_data *ctx;
	struct nfp_mbl_dev_ctx *dev_ctx;
	struct device *dev;
	void *cookie;

	ctx = nfp_mbl_get_global_ctx();
	if (!ctx)
		return NULL;

	dev_ctx = ctx->dev_ctx[NFP_MBL_DEV_INDEX_PRIMARY];
	if (dev_ctx) {
		dev = &dev_ctx->app->pf->pdev->dev;
		dev_info(dev, "unregistered UAL, %s\n",
			 (ctx->ual_ops && ctx->ual_ops->name ?
				 ctx->ual_ops->name : "(none)"));
	}

	nfp_mbl_stop_ual();

	cookie = ctx->ual_cookie;
	ctx->ual_cookie = NULL;
	ctx->ual_ops = NULL;

	return cookie;
}

/**
 * nfp_ual_get_cookie() - provide UAL access to the ual_cookie field
 *
 * Return: UAL cookie or NULL
 */
void *nfp_ual_get_cookie(void)
{
	struct nfp_mbl_global_data *ctx = nfp_mbl_get_global_ctx();

	if (!ctx)
		return NULL;

	return ctx->ual_cookie;
}

/**
 * nfp_ual_set_port_id() - set the port ID for a representor
 * @repr:	representor pointer
 * @port_id:	new port ID, only allowed to specify UAL allocated space
 *
 * Return: negative ERRNO or 0 for success
 */
int nfp_ual_set_port_id(struct nfp_repr *repr, u32 port_id)
{
	u32 new_port_id, old_port_id;

	/* UAL must not touch the MBL reserved bits of the port ID. */
	if (port_id & NFP_MBL_PORTID_MBL_MASK)
		return -EINVAL;

	old_port_id = nfp_repr_get_port_id(repr->netdev);
	new_port_id = (port_id & NFP_MBL_PORTID_UAL_MASK) |
		(old_port_id & NFP_MBL_PORTID_MBL_MASK);

	pr_info("%s: modifying repr ID: 0x%08x -> 0x%08x\n",
		repr->netdev->name, old_port_id, new_port_id);

	nfp_repr_set_port_id(repr->netdev, new_port_id);

	return 0;
}

/*
 * nfp_ual_get_port_id() - get the port ID for a representor
 * @repr:	representor pointer
 *
 * Return: representor ID
 */
int nfp_ual_get_port_id(struct nfp_repr *repr)
{
	return nfp_repr_get_port_id(repr->netdev);
}

/**
 * nfp_ual_ctrl_msg_alloc() - transmit control message over primary PCIe
 *			      interface
 * @size:	size to allocate
 * @priority:	allocation mask
 *
 * Return: sk_buff pointer or NULL if error
 */
struct sk_buff *nfp_ual_ctrl_msg_alloc(unsigned int size, gfp_t priority)
{
	/* CMSGs always sent on PCIe 0 only and it must exist. */
	struct nfp_app *app = nfp_ual_get_app(NFP_MBL_DEV_INDEX_PRIMARY);

	return nfp_app_ctrl_msg_alloc(app, size, priority);
}

/**
 * nfp_ual_ctrl_tx() - transmit control message over primary PCIe interface
 * @skb:	reference to packet data
 *
 * Return: true if packet queued, or false if packet processed
 */
bool nfp_ual_ctrl_tx(struct sk_buff *skb)
{
	/* CMSGs always sent on PCIe 0 only and it must exist. */
	struct nfp_app *app = nfp_ual_get_app(NFP_MBL_DEV_INDEX_PRIMARY);

	return nfp_app_ctrl_tx(app, skb);
}

/**
 * nfp_ual_select_tx_dev() - select a transmit data vNIC for a representor
 * @repr:	representor pointer
 * @pcie_unit:	requested PCIe number for data vNIC selection, e.g. 0-3
 *
 * Return: negative ERRNO or 0 for success
 */
int nfp_ual_select_tx_dev(struct nfp_repr *repr, u8 pcie_unit)
{
	struct net_device *old_netdev, *pf_netdev;
	struct nfp_mbl_dev_ctx *dev_ctx;
	int dev_index;
	int err;

	ASSERT_RTNL();

	dev_index = NFP_MBL_DEV_INDEX(NFP_MBL_DEV_TYPE_MASTER_PF, pcie_unit);

	dev_ctx = nfp_ual_get_mbl_dev_ctx(dev_index);
	if (!dev_ctx)
		return -ENOENT;

	pf_netdev = dev_ctx->nn->dp.netdev;
	old_netdev = nfp_repr_get_lower_dev(repr->netdev);

	repr->netdev->max_mtu = pf_netdev->max_mtu;
	nfp_repr_set_lower_dev(repr->netdev, pf_netdev);

	err = dev_open(pf_netdev);
	if (err)
		goto err_revert_max_mtu;

	return 0;

err_revert_max_mtu:
	repr->netdev->max_mtu = old_netdev->max_mtu;
	nfp_repr_set_lower_dev(repr->netdev, old_netdev);
	return err;
}

/**
 * nfp_ual_get_pcie_unit_count() - return the number of PCIe units probed
 *
 * @bitmap:	if non NULL, return bitmap of probed PCIe units.
 *
 * Return: PCIe unit count (only for main NFP processor) or negative error
 */
int nfp_ual_get_pcie_unit_count(u8 *bitmap)
{
	struct nfp_mbl_global_data *ctx;
	int i, count, dev_index;
	u8 map;

	ctx = nfp_mbl_get_global_ctx();
	if (!ctx)
		return -ENOENT;

	count = 0;
	map = 0;

	for (i = 0; i < NFP_MBL_DEV_ID_MAX; i++) {
		dev_index = NFP_MBL_DEV_INDEX(NFP_MBL_DEV_TYPE_MASTER_PF, i);
		if (ctx->dev_ctx[dev_index]) {
			count++;
			map |= 1<<i;
		}
	}

	if (bitmap)
		*bitmap = map;

	return count;
}

/**
 * nfp_ual_get_mbl_dev_ctx() - obtain device app context pointer for index
 * @dev_index:	MBL device app index
 *
 * Return: device app context pointer or NULL
 */
struct nfp_mbl_dev_ctx *nfp_ual_get_mbl_dev_ctx(int dev_index)
{
	struct nfp_mbl_global_data *ctx;

	ctx = nfp_mbl_get_global_ctx();
	if (!ctx || dev_index >= NFP_MBL_DEV_INDEX_MAX)
		return NULL;

	return ctx->dev_ctx[dev_index];
}

/**
 * nfp_ual_get_reprs() - obtain set of representors, for specified device and
 *			 type
 * @dev_index:	MBL device app index
 * @type:	type of representors
 *
 * This function expects the PF lock to be held for the device specified.
 *
 * Return: set of representors
 */
struct nfp_reprs *nfp_ual_get_reprs(int dev_index, enum nfp_repr_type type)
{
	struct nfp_app *app = nfp_ual_get_app(dev_index);

	return rcu_dereference_protected(app->reprs[type],
					 lockdep_is_held(&app->pf->lock));
}

/**
 * nfp_ual_foreach_repr() - execute a provided callback for each representor
 *			    available on the system
 *
 * RTNL and RCU read lock held while callback is executed.
 *
 * @ctx:	if not NULL, device app context to filter on
 * @repr_cookie:	opaque reference to pass to callback function
 * @repr_cb:	callback, taking representor reference and opaque cookie as
 *		as parameters
 *
 * Return: void
 */
void nfp_ual_foreach_repr(struct nfp_mbl_dev_ctx *ctx, void *repr_cookie,
			  void (*repr_cb)(struct nfp_repr *repr, void *cookie))
{
	int i, j, dev_index, f_idx;
	struct net_device *netdev;
	struct nfp_reprs *reprs;
	struct nfp_app *app;

	f_idx = (ctx ? nfp_ual_get_mbl_dev_index_from_ctx(ctx) : -1);
	for (dev_index = 0; dev_index <= NFP_MBL_DEV_INDEX_MAX; dev_index++) {
		if (ctx && dev_index != f_idx)
			continue;

		app = nfp_ual_get_app(dev_index);
		if (!app)
			continue;

		rtnl_lock();
		rcu_read_lock();
		for (i = 0; i <= NFP_REPR_TYPE_MAX; i++) {
			reprs = nfp_ual_get_reprs(dev_index, i);
			for (j = 0; reprs && j < reprs->num_reprs; j++) {
				netdev = rcu_dereference(reprs->reprs[j]);
				if (netdev)
					repr_cb(netdev_priv(netdev),
						repr_cookie);
			}
		}
		rcu_read_unlock();
		rtnl_unlock();
	}
}

/**
 * nfp_ual_get_eth_port_from_repr() - obtain the associated eth_table_port entry
 *				      for the specified representor
 * @repr:	representor pointer
 *
 * Return: eth_table_port structure reference or NULL for VF ports
 */
struct nfp_eth_table_port *
nfp_ual_get_eth_port_from_repr(struct nfp_repr *repr)
{
	struct nfp_port *port = nfp_port_from_netdev(repr->netdev);

	return nfp_port_get_eth_port(port);
}
