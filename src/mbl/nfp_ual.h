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

#ifndef __NFP_UAL_H__
#define __NFP_UAL_H__ 1

#include <linux/netdevice.h>

#include "nfp_app.h"
#include "nfp_net_repr.h"

struct nfp_cpp;
struct nfp_meta_parsed;

/* Representor port ID
 * ----------------------------------------------------------------
 *    3                   2                   1
 *  1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |P|DevId|Ty |Index      |UAL defined                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define NFP_MBL_PORTID_MBL_MASK		GENMASK(31, 20)
#define NFP_MBL_PORTID_MBL_PRESENCE	BIT(31)
#define NFP_MBL_PORTID_MBL_DEV_MASK	GENMASK(30, 28)
#define NFP_MBL_PORTID_MBL_TYPE_MASK	GENMASK(27, 26)
#define NFP_MBL_PORTID_MBL_INDEX_MASK	GENMASK(25, 20)
#define NFP_MBL_PORTID_UAL_MASK		GENMASK(19, 0)

#define NFP_UAL_PORTID_UNSPEC		NFP_MBL_PORTID_UAL_MASK

static inline u32 nfp_mbl_portid(u8 dev_index, u8 type, u8 index)
{
	return NFP_MBL_PORTID_MBL_PRESENCE |
		FIELD_PREP(NFP_MBL_PORTID_MBL_DEV_MASK, dev_index) |
		FIELD_PREP(NFP_MBL_PORTID_MBL_TYPE_MASK, type) |
		FIELD_PREP(NFP_MBL_PORTID_MBL_INDEX_MASK, index) |
		NFP_UAL_PORTID_UNSPEC;
}

enum nfp_mbl_dev_type {
	NFP_MBL_DEV_TYPE_MASTER_PF,
	NFP_MBL_DEV_TYPE_NICMOD,

	__NFP_MBL_DEV_TYPE_MAX,
};

#define NFP_MBL_DEV_TYPE_MAX		(__NFP_MBL_DEV_TYPE_MAX - 1)

#define NFP_MBL_DEV_ID_MAX		4
#define NFP_MBL_DEV_INDEX(type, id) \
	((type) * NFP_MBL_DEV_ID_MAX + (id))
#define NFP_MBL_DEV_INDEX_MAX \
	NFP_MBL_DEV_INDEX(NFP_MBL_DEV_TYPE_MAX, NFP_MBL_DEV_ID_MAX)
#define NFP_MBL_DEV_INDEX_PRIMARY \
	NFP_MBL_DEV_INDEX(NFP_MBL_DEV_TYPE_MASTER_PF, 0)

/**
 * enum nfp_mbl_status_type - type of MBL device probe status
 * @NFP_MBL_STATUS_PROBE:	devices are still in progress of being probed
 * @NFP_MBL_STATUS_TIMEOUT:	some devices have not been successfully probed
 *				before the timeout was reached
 * @NFP_MBL_STATUS_UNBOUND:	some devices have been unbound from the driver
 *				after being probed successfully initially
 * @NFP_MBL_STATUS_SUCCESS:	all devices are probed and ready
 */
enum nfp_mbl_status_type {
	NFP_MBL_STATUS_PROBE,
	NFP_MBL_STATUS_TIMEOUT,
	NFP_MBL_STATUS_UNBOUND,
	NFP_MBL_STATUS_SUCCESS,
};

/**
 * struct nfp_mbl_repr - per repr priv data
 *
 * @ual_priv:		UAL per repr priv data
 * @dst:		repr destination per VID
 */
struct nfp_mbl_repr {
	void *ual_priv;
	struct metadata_dst *vlan_dst[VLAN_N_VID];
};

/**
 * struct nfp_mbl_dev_ctx - device app context
 * This structure is used as the per device app priv structure, i.e. app->priv
 *
 * @app:		Back pointer to app
 * @nn:			Pointer to data vNIC
 * @type:		Type of device %NFP_MBL_DEV_TYPE_*
 * @pcie_unit:		PCIe unit number, e.g. 0-3 for main NFP
 */
struct nfp_mbl_dev_ctx {
	struct nfp_app *app;
	struct nfp_net *nn;
	enum nfp_mbl_dev_type type;
	u8 pcie_unit;
};

/**
 * struct nfp_ual_ops - UAL operations
 * @name:	get UAL name
 *
 * callbacks:
 * @init:	perform UAL init
 * @clean:	clean UAL state
 * @repr_open:	representor netdev open callback
 * @repr_stop:	representor netdev stop callback
 * @vnic_change_mtu: MTU change on vNIC netdev has been requested (veto-only,
 *		change is not guaranteed to be committed)
 * @parse_meta:	parse and store packet metadata. All metadata validation is
 *		expected to occur here.
 * @skb_set_meta: set skb metadata parsed with @parse_meta
 * @prep_tx_meta: prepend TX metadata to skb
 * @ctrl_msg_rx: control message handler
 * @sriov_enable: app-specific sriov initialisation
 * @sriov_disable: app-specific sriov clean-up
 * @repr_vlan_rx_add_vid: called when a VLAN id is registered
 * @repr_vlan_rx_kill_vid: called when a VLAN id is unregistered
 * @repr_get_vlan_portid: return repr port ID for VLAN netdevice
 * @repr_change_mtu: MTU change on a netdev has been requested (veto-only,
 *		change is not guaranteed to be committed)
 */
struct nfp_ual_ops {
	const char *name;

	int (*init)(void *cookie, enum nfp_mbl_status_type status);
	void (*clean)(void *cookie);

	int (*repr_open)(void *cookie, struct nfp_repr *repr);
	int (*repr_stop)(void *cookie, struct nfp_repr *repr);

	int (*vnic_change_mtu)(void *cookie, struct nfp_mbl_dev_ctx *ctx,
			       struct net_device *netdev, int new_mtu);

	int (*parse_meta)(void *cookie, struct net_device *netdev,
			  struct nfp_meta_parsed *meta, char *data,
			  int meta_len);
	void (*skb_set_meta)(void *cookie, struct sk_buff *skb,
			     struct nfp_meta_parsed *meta);
	int (*prep_tx_meta)(void *cookie, struct sk_buff *skb);

	void (*ctrl_msg_rx)(void *cookie, struct sk_buff *skb);

	int (*sriov_enable)(void *cookie, struct nfp_mbl_dev_ctx *ctx,
			    int num_vfs);
	void (*sriov_disable)(void *cookie, struct nfp_mbl_dev_ctx *ctx);

	int (*repr_vlan_rx_add_vid)(void *cookie, struct net_device *netdev,
				    __be16 proto, u16 vid);
	int (*repr_vlan_rx_kill_vid)(void *cookie, struct net_device *netdev,
				     __be16 proto, u16 vid);
	u32 (*repr_get_vlan_portid)(void *cookie, struct net_device *netdev,
				    __be16 proto, u16 vid);

	int (*repr_change_mtu)(void *cookie, struct net_device *netdev,
			       int new_mtu);
};

int nfp_ual_register(const struct nfp_ual_ops *ops, void *cookie);
void *nfp_ual_unregister(void);
void *nfp_ual_get_cookie(void);

int nfp_ual_set_port_id(struct nfp_repr *repr, u32 port_id);
int nfp_ual_get_port_id(struct nfp_repr *repr);
int nfp_ual_select_tx_dev(struct nfp_repr *repr, u8 pcie_unit);

struct sk_buff *nfp_ual_ctrl_msg_alloc(unsigned int size, gfp_t priority);
bool nfp_ual_ctrl_tx(struct sk_buff *skb);

struct nfp_mbl_dev_ctx *nfp_ual_get_mbl_dev_ctx(int dev_index);
static inline struct nfp_mbl_dev_ctx *
nfp_ual_get_mbl_dev_ctx_from_netdev(struct net_device *netdev)
{
	struct nfp_app *app = nfp_app_from_netdev(netdev);

	if (!app)
		return NULL;

	return app->priv;
};

static inline struct nfp_cpp *nfp_ual_get_cpp(int dev_index)
{
	struct nfp_mbl_dev_ctx *dev_ctx = nfp_ual_get_mbl_dev_ctx(dev_index);

	if (!dev_ctx)
		return NULL;

	return dev_ctx->app->cpp;
};

static inline struct nfp_app *nfp_ual_get_app(int dev_index)
{
	struct nfp_mbl_dev_ctx *dev_ctx = nfp_ual_get_mbl_dev_ctx(dev_index);

	if (!dev_ctx)
		return NULL;

	return dev_ctx->app;
};

static inline int
nfp_ual_get_mbl_dev_index_from_ctx(struct nfp_mbl_dev_ctx *dev_ctx)
{
	if (!dev_ctx)
		return -ENOENT;

	return NFP_MBL_DEV_INDEX(dev_ctx->type, dev_ctx->pcie_unit);
}

struct nfp_reprs *nfp_ual_get_reprs(int dev_index, enum nfp_repr_type type);
void nfp_ual_foreach_repr(struct nfp_mbl_dev_ctx *ctx, void *repr_cookie,
			  void (*repr_cb)(struct nfp_repr *repr, void *cookie));

struct nfp_eth_table_port *
nfp_ual_get_eth_port_from_repr(struct nfp_repr *repr);

#endif
