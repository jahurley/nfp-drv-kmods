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

	cancel_delayed_work_sync(&ctx->probe_dw);
	return 0;

err_reset_ual:
	ctx->ual_cookie = NULL;
	ctx->ual_ops = NULL;
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
