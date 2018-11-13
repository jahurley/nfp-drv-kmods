// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2018 Netronome Systems, Inc. */

#ifndef __NFP_UALT_H__
#define __NFP_UALT_H__ 1

#include "nfp_net_repr.h"
#include "nfp_ual.h"

enum ualt_status_type {
	/* These status items comes directly from the nfp_ual.h */
	UALT_STATUS_PROBE = NFP_MBL_STATUS_PROBE,
	UALT_STATUS_TIMEOUT = NFP_MBL_STATUS_TIMEOUT,
	UALT_STATUS_UNBOUND = NFP_MBL_STATUS_UNBOUND,
	UALT_STATUS_SUCCESS = NFP_MBL_STATUS_SUCCESS,

	/* Now we add some of our own */
	UALT_STATUS_UNINITIALIZED = 100,
};

enum ualt_cmsg_port_flag {
	UALT_PORT_FLAG_ADD =	0,
	UALT_PORT_FLAG_REMOVE =	1,
};

struct ualt_cookie {
	u32 label;
	u8 pcie_map;
	u8 nicmod_map;

	bool tx_meta_enable;
	u64 tx_meta_data;
	u64 rx_meta_data;

	struct dentry *dir;
	struct dentry *vnics_file;
	struct dentry *repr_dir;
	enum ualt_status_type status;
};

struct ualt_repr_meta {
	u8 rx_vnic;
	u8 tx_vnic;
	u8 tx_override;
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
void ualt_debugfs_destroy_reprs(struct ualt_cookie *priv);

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
