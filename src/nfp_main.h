/*
 * Copyright (C) 2015 Netronome Systems, Inc.
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

/*
 * nfp_main.h
 * Author: Jason McMullan <jason.mcmullan@netronome.com>
 */

#ifndef NFP_MAIN_H
#define NFP_MAIN_H

#include <linux/list.h>
#include <linux/types.h>
#include <linux/msi.h>

struct dentry;
struct pci_dev;
struct platform_device;

struct nfp_cpp;
struct nfp_cpp_area;

/**
 * struct nfp_pf - NFP PF-specific device structure
 * @pdev:		Backpointer to PCI device
 * @cpp:		Pointer to the CPP handle
 * @nfp_dev_cpp:	Pointer to the NFP Device handle
 * @nfp_net_vnic:	Handle for ARM VNIC device
 * @ctrl_area:		Pointer to the CPP area for the control BAR
 * @tx_area:		Pointer to the CPP area for the TX queues
 * @rx_area:		Pointer to the CPP area for the FL/RX queues
 * @irq_entries:	Array of MSI-X entries for all ports
 * @msix:		Single MSI-X entry for non-netdev mode event monitor
 * @num_vfs:		Number of SR-IOV VFs enabled
 * @fw_loaded:		Is the firmware loaded?
 * @nfp_fallback:	Is the driver used in fallback mode?
 * @ddir:		Per-device debugfs directory
 * @num_ports:		Number of adapter ports
 * @ports:		Linked list of port structures (struct nfp_net)
 */
struct nfp_pf {
	struct pci_dev *pdev;

	struct nfp_cpp *cpp;
	struct platform_device *nfp_dev_cpp;
	struct platform_device *nfp_net_vnic;

	struct nfp_cpp_area *ctrl_area;
	struct nfp_cpp_area *tx_area;
	struct nfp_cpp_area *rx_area;

	struct msix_entry *irq_entries;

	struct msix_entry msix;

	unsigned int num_vfs;

	bool fw_loaded;
	bool nfp_fallback;

	struct dentry *ddir;

	unsigned int num_ports;
	struct list_head ports;
};

extern bool nfp_dev_cpp;
extern bool nfp_net_vnic;

int nfp_pcie_sriov_configure(struct pci_dev *pdev, int num_vfs);
int nfp_pcie_sriov_disable(struct pci_dev *pdev);

int nfp_sriov_attr_add(struct device *dev);
void nfp_sriov_attr_remove(struct device *dev);

#endif /* NFP_MAIN_H */
