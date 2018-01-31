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

 #ifndef __NFP_MBL_H__
 #define __NFP_MBL_H__ 1

#include "nfp_net_compat.h"
#include "nfp_ual.h"

#define NFP_MBL_PRIMARY_DEV_CTX(ctx) \
	((ctx)->dev_ctx[NFP_MBL_DEV_INDEX_PRIMARY])

/**
 * struct nfp_mbl_global_data - global context data
 * @dev_ctx:	array of device contexts
 * @ref_count:	number of device contexts stored
 * @status:	status flag
 * @probe_dw: delayed work to check probe timeout status
 * @init_count:	number of devices which are ready for UAL
 * @ual_running: track UAL status
 */
struct nfp_mbl_global_data {
	struct nfp_mbl_dev_ctx *dev_ctx[NFP_MBL_DEV_INDEX_MAX];
	int ref_count;
	enum nfp_mbl_status_type status;

	struct delayed_work probe_dw;

	int init_count;

	bool ual_running;
};

struct nfp_mbl_global_data *nfp_mbl_get_global_ctx(void);

int nfp_mbl_try_init_ual(void);
void nfp_mbl_stop_ual(void);

#endif
