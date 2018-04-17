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
#include <linux/debugfs.h>
#include <linux/kernel.h>

#include "nfp_net.h"
#include "main.h"

static int ualt_dfs_file_get(struct dentry *dentry, int *srcu_idx)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	return debugfs_file_get(dentry);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	return debugfs_use_file_start(dentry, srcu_idx);
#else
	return 0;
#endif
}

static void ualt_dfs_file_put(struct dentry *dentry, int srcu_idx)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	debugfs_file_put(dentry);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	debugfs_use_file_finish(srcu_idx);
#endif
}

static ssize_t
ualt_repr_vnic_read(struct file *file, char __user *buf, size_t size,
		    loff_t *ppos)
{
	struct nfp_repr *repr = file->private_data;
	struct ualt_repr_meta *meta;
	char value_str[5];
	int srcu_idx, err;
	ssize_t ret;

	memset(value_str, 0, sizeof(value_str));

	meta = ualt_get_repr_meta(repr);
	if (!meta)
		return -ENODEV;

	err = ualt_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (err)
		goto err_file_put;

	if (strcmp(file->f_path.dentry->d_name.name, "rx_vnic") == 0)
		ret = snprintf(value_str, sizeof(value_str), "%d\n",
			       meta->rx_vnic);
	else
		ret = snprintf(value_str, sizeof(value_str), "%d\n",
			       meta->tx_vnic);

	ret = simple_read_from_buffer(buf, size, ppos, value_str, ret);

	ualt_dfs_file_put(file->f_path.dentry, srcu_idx);

	return ret;

err_file_put:
	ualt_dfs_file_put(file->f_path.dentry, srcu_idx);
	return err;
}

static ssize_t
ualt_repr_vnic_write(struct file *file, const char __user *user_buf,
		     size_t count, loff_t *ppos)
{
	struct nfp_repr *repr = file->private_data;
	struct ualt_repr_meta *meta;
	struct ualt_cookie *priv;
	int srcu_idx, err;
	u8 value;

	priv = nfp_ual_get_cookie();
	if (!priv)
		return -ENODEV;

	meta = ualt_get_repr_meta(repr);
	if (!meta)
		return -ENODEV;

	err = ualt_dfs_file_get(file->f_path.dentry, &srcu_idx);
	if (err)
		goto err_file_put;

	err = kstrtou8_from_user(user_buf, count, 0, &value);
	if (err)
		goto err_file_put;

	ualt_dfs_file_put(file->f_path.dentry, srcu_idx);

	rtnl_lock();
	if (strcmp(file->f_path.dentry->d_name.name, "rx_vnic") == 0) {
		if (!((priv->pcie_map >> value) & 0x1)) {
			rtnl_unlock();
			return -EINVAL;
		}

		err = ualt_cmsg_port(repr, nfp_ual_get_port_id(repr), value,
				     UALT_PORT_FLAG_ADD);
		if (err) {
			rtnl_unlock();
			return err;
		}

		meta->rx_vnic = value;
	} else {
		err = nfp_ual_select_tx_dev(repr, value);
		if (err) {
			rtnl_unlock();
			return err;
		}

		meta->tx_vnic = value;
	}
	rtnl_unlock();

	return count;

err_file_put:
	ualt_dfs_file_put(file->f_path.dentry, srcu_idx);
	return err;
}

static const struct file_operations ualt_repr_vnic_ops = {
	.read = ualt_repr_vnic_read,
	.write = ualt_repr_vnic_write,
	.open = simple_open,
	.llseek = default_llseek,
};

int ualt_debugfs_add_repr(struct ualt_cookie *priv, struct nfp_repr *repr)
{
	struct dentry *dir;
	bool fail = false;

	dir = debugfs_create_dir(repr->netdev->name, priv->dir);
	if (!dir)
		return -ENODEV;

	fail |= !debugfs_create_file("rx_vnic", 0600, dir, repr,
				     &ualt_repr_vnic_ops);
	fail |= !debugfs_create_file("tx_vnic", 0600, dir, repr,
				     &ualt_repr_vnic_ops);

	return (fail ? -ENODEV : 0);
}

static ssize_t
ualt_vnics_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct nfp_mbl_dev_ctx *dev_ctx;
	ssize_t ret, bytes_left;
	char vnics_str[128];
	char *ptr;
	int i;

	memset(vnics_str, 0, sizeof(vnics_str));

	ptr = vnics_str;
	bytes_left = sizeof(vnics_str);
	for (i = 0; i < NFP_MBL_DEV_INDEX_MAX; i++) {
		dev_ctx = nfp_ual_get_mbl_dev_ctx(i);
		if (!dev_ctx || !dev_ctx->nn)
			continue;

		ret = snprintf(ptr, bytes_left, "%d %s\n", NFP_MBL_DEV_ID(i),
			       dev_ctx->nn->dp.netdev->name);
		if (ret < 0)
			return ret;
		bytes_left -= ret;
		ptr += ret;
	}

	ret = simple_read_from_buffer(buf, size, ppos, vnics_str,
				      strlen(vnics_str));
	return ret;
}

static const struct file_operations ualt_vnics_ops = {
	.read = ualt_vnics_read,
	.open = simple_open,
	.llseek = default_llseek,
};

int ualt_debugfs_create(struct ualt_cookie *priv)
{
	bool fail = false;

	priv->dir = debugfs_create_dir("ualt", NULL);
	if (!priv->dir)
		return -EBUSY;

	fail |= !debugfs_create_file("vnics", 0600, priv->dir, priv,
				     &ualt_vnics_ops);

	return (fail ? -ENODEV : 0);
}

void ualt_debugfs_destroy(struct ualt_cookie *priv)
{
	debugfs_remove_recursive(priv->dir);
}
