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

#ifndef __NFP_UALT_H__
#define __NFP_UALT_H__ 1

#include "nfp_net_repr.h"
#include "nfp_ual.h"

enum ualt_cmsg_port_flag {
	UALT_PORT_FLAG_ADD =	0,
	UALT_PORT_FLAG_REMOVE =	1,
};

struct ualt_cookie {
	u32 label;
	u8 pcie_map;

	struct dentry *dir;
};

struct ualt_repr_meta {
	u8 rx_vnic;
	u8 tx_vnic;
};

static inline struct ualt_repr_meta *ualt_get_repr_meta(struct nfp_repr *repr)
{
	struct nfp_mbl_repr *mbl_repr = repr->app_priv;

	return (mbl_repr ? mbl_repr->ual_priv : NULL);
}

int ualt_cmsg_port(struct nfp_repr *repr, unsigned int port_id, u8 rx_vnic,
		   unsigned int flags);

#if defined(UALT_DEBUG_FS)

int ualt_debugfs_create(struct ualt_cookie *priv);
void ualt_debugfs_destroy(struct ualt_cookie *priv);
int ualt_debugfs_add_repr(struct ualt_cookie *priv, struct nfp_repr *repr);

#else

/* If we don't have debug FS available, just continue without the feature. */

static inline int ualt_debugfs_create(struct ualt_cookie *priv)
{
	return 0;
}

static inline void ualt_debugfs_destroy(struct ualt_cookie *priv)
{
}

static int
ualt_debugfs_add_repr(struct ualt_cookie *priv, struct nfp_repr *repr)
{
	return 0;
}

#endif

#endif
