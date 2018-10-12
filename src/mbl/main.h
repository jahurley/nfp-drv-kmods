// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2018 Netronome Systems, Inc. */

#ifndef __NFP_MBL_H__
#define __NFP_MBL_H__ 1

#include "nfpcore/nfp_cpp.h"
#include "nfp_app.h"
#include "nfp_net_compat.h"
#include "nfp_ual.h"

struct nfp_cpp;

#define NFP_MBL_PRIMARY_DEV_CTX(ctx) \
	((ctx)->dev_ctx[NFP_MBL_DEV_INDEX_PRIMARY])

#define nfp_mbl_err(dev_ctx, fmt, args...) \
	nfp_err((dev_ctx)->app->cpp, "MBL dev#%d.%d: " fmt, (dev_ctx)->type, \
		(dev_ctx)->pcie_unit, ## args)
#define nfp_mbl_warn(dev_ctx, fmt, args...) \
	nfp_warn((dev_ctx)->app->cpp, "MBL dev#%d.%d: " fmt, (dev_ctx)->type, \
		 (dev_ctx)->pcie_unit, ## args)
#define nfp_mbl_info(dev_ctx, fmt, args...) \
	nfp_info((dev_ctx)->app->cpp, "MBL dev#%d.%d: " fmt, (dev_ctx)->type, \
		 (dev_ctx)->pcie_unit, ## args)

/**
 * struct nfp_mbl_global_data - global context data
 * @dev_ctx:	array of device contexts
 * @ref_count:	number of device contexts stored
 * @status:	status flag
 * @probe_dw: delayed work to check probe timeout status
 * @link_timer: physical port link state timer
 * @init_count:	number of devices which are ready for UAL
 * @mbl_lock:	protect UAL initialization
 * @ual_ops:	store UAL callback structure
 * @ual_cookie:	UAL opaque callback pointer
 * @ual_running: track UAL status
 */
struct nfp_mbl_global_data {
	struct nfp_mbl_dev_ctx *dev_ctx[NFP_MBL_DEV_INDEX_MAX];
	int ref_count;
	enum nfp_mbl_status_type status;

	struct delayed_work probe_dw;
	struct timer_list link_timer;

	int init_count;

	struct mutex mbl_lock; /* protect UAL initialization */

	const struct nfp_ual_ops *ual_ops;
	void *ual_cookie;
	bool ual_running;
};

struct nfp_mbl_global_data *nfp_mbl_get_global_ctx(void);

int nfp_mbl_try_init_ual(void);
void nfp_mbl_stop_ual(void);

#endif
