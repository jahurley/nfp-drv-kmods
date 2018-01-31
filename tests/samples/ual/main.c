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
#include "nfp_app.h"
#include "nfp_main.h"
#include "nfp_ual.h"

#include "main.h"

#define UALT_NAME	"ualt_module"

static int ualt_init(void *cookie, enum nfp_mbl_status_type status)
{
	struct nfp_app *app;
	u64 version;
	int err;

	app = nfp_ual_get_app(NFP_MBL_DEV_INDEX_PRIMARY);
	version = nfp_rtsym_read_le(app->pf->rtbl, "_ualt_version", &err);
	if (err) {
		pr_warn("%s requires _ualt_version memory symbol\n", UALT_NAME);
		return err;
	}

	pr_info("starting %s version %02llx\n", UALT_NAME, version);
	if (status != NFP_MBL_STATUS_SUCCESS)
		pr_warn("%s: not all devices probed, degraded\n", UALT_NAME);

	return 0;
}

static void ualt_clean(void *cookie)
{
	pr_info("%s cleanup\n", UALT_NAME);
}

const struct nfp_ual_ops ops = {
	.name = UALT_NAME,

	.init = ualt_init,
	.clean = ualt_clean,
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
