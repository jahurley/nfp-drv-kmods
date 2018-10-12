// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2017-2018 Netronome Systems, Inc. */

#include <linux/idr.h>
#include <net/xfrm.h>

#include "nfp_net.h"
#include "nfp_net_compat.h"
#include "nfp_net_ctrl.h"
#include "nfp_net_ipsec.h"
#include "nfp_net_repr.h"
#include "nfp_port.h"

/* The XFRM offload_handle is assumed to be non-zero when it is valid. However,
 * since we store the SAIDX value there, and zero is a valid value, we need to
 * mangle the offload_handle to ensure the XFRM core knows its valid.
 * We do this simply by adding/subtracting 1.
 */
#define NFP_NET_IPSEC_SAIDX_TO_HANDLE(_saidx) ((_saidx) + 1)
#define NFP_NET_IPSEC_HANDLE_TO_SAIDX(_handle) ((_handle) - 1)

#define NFP_NET_IPSEC_HANDLE_ERROR     (~0U)
#define NFP_NET_IPSEC_MAX_SA_CNT       (16 * 1024)

struct nfp_net_ipsec_sa_data {
	struct nfp_ipsec_cfg_add_sa nfp_sa;
	struct xfrm_state *x;
	int invalidated;
};

struct nfp_net_ipsec_data {
	struct ida ida_handle;
	struct nfp_net_ipsec_sa_data sa_entries[NFP_NET_IPSEC_MAX_SA_CNT];
	struct mutex lock;	/* protects SA entries */
};

static struct nfp_net *nfp_ipsec_get_nfp_net(struct net_device *netdev)
{
	struct net_device *lower_dev;
	struct nfp_repr *repr;

	if (!nfp_netdev_is_nfp_repr(netdev))
		return netdev_priv(netdev);

	repr = netdev_priv(netdev);
	lower_dev = repr->dst->u.port_info.lower_dev;

	if (!nfp_netdev_is_nfp_net(lower_dev))
		return NULL;

	return netdev_priv(lower_dev);
}

static u16 nfp_ipsec_get_index(struct net_device *netdev)
{
	struct nfp_port *port = nfp_port_from_netdev(netdev);

	if (port->type == NFP_PORT_PHYS_PORT ||
	    port->type == NFP_PORT_PHYS_PORT_EXP)
		return port->eth_id;

	return 0;
}

static void
nfp_ipsec_cfg_write_msg(struct net_device *netdev, int type, int saidx,
			struct nfp_ipsec_cfg_mssg *msg, int offset)
{
	struct nfp_net *nn = nfp_ipsec_get_nfp_net(netdev);
	int i;

	msg->cmd = type;
	msg->sa_idx = saidx;
	msg->rsp = 0;
	msg->stack_idx = nfp_ipsec_get_index(netdev);

	for (i = 0; i < sizeof(*msg); i += 4) {
		nn_writel(nn, offset + i,
			  *(u32 *)(((char *)msg) + i));
	}
}

/**
 * nfp_ipsec_cfg_cmd_issue() - issue an ipsec configuration cmd to the NFP
 * @nn:		NFP net device to reconfigure
 * @type:	Config message type
 * @saidx:	SA index to configure
 * @msg:	IPsec configuration message structure
 */
static int
nfp_ipsec_cfg_cmd_issue(struct net_device *netdev, int type, int saidx,
			struct nfp_ipsec_cfg_mssg *msg)
{
	struct nfp_net *nn = nfp_ipsec_get_nfp_net(netdev);
	int err, offset, i;
	u32 val;

	if (!nn)
		return -EOPNOTSUPP;

	offset = nn->tlv_caps.mbox_off + NFP_NET_CFG_IPSEC_CFG;
	nfp_ipsec_cfg_write_msg(netdev, type, saidx, msg, offset);
	err = nfp_net_reconfig_mbox(nn, NFP_NET_CFG_MBOX_CMD_IPSEC);
	if (err < 0)
		return err;

	/* for now we always read the whole message response back */
	for (i = 0; i < sizeof(*msg); i += 4) {
		val = nn_readl(nn, offset + i);
		*(u32 *)(((char *)msg) + i) = val;
	}

	switch (msg->rsp) {
	case NFP_IPSEC_CFG_MSSG_SA_INVALID_CMD:
		return -EINVAL;
	case NFP_IPSEC_CFG_MSSG_SA_VALID:
		return -EEXIST;
	case NFP_IPSEC_CFG_MSSG_FAILED:
	case NFP_IPSEC_CFG_MSSG_SA_HASH_ADD_FAILED:
	case NFP_IPSEC_CFG_MSSG_SA_HASH_DEL_FAILED:
		return -EIO;
	}

	return 0;
}

/**
 * nfp_ipsec_cfg_cmd_issue_async() - issue an ipsec configuration cmd to the NFP
 *			asynchronously
 * @nn:		NFP net device to reconfigure
 * @type:	Config message type
 * @saidx:	SA index to configure
 * @msg:	IPsec configuration message structure
 */
static int
nfp_ipsec_cfg_cmd_issue_async(struct net_device *netdev, int type, int saidx,
			      struct nfp_ipsec_cfg_mssg *msg)
{
	struct nfp_net *nn = nfp_ipsec_get_nfp_net(netdev);
	int offset;

	if (!nn)
		return -EOPNOTSUPP;

	offset = nn->tlv_caps.mbox_off + NFP_NET_CFG_IPSEC_CFG;
	nfp_ipsec_cfg_write_msg(netdev, type, saidx, msg, offset);
	nfp_net_reconfig_mbox_post(nn, NFP_NET_CFG_MBOX_CMD_IPSEC);

	return 0;
}

static struct nfp_net_ipsec_data *
nfp_ipsec_get_handle(struct net_device *netdev)
{
	struct nfp_repr *repr;
	struct nfp_net *nn;

	if (nfp_netdev_is_nfp_repr(netdev)) {
		repr = netdev_priv(netdev);
		return repr->ipsec_data;
	} else {
		nn = netdev_priv(netdev);
		return nn->ipsec_data;
	}
}

static int set_aes_keylen(struct nfp_ipsec_cfg_add_sa *cfg, int alg, int keylen)
{
	if (alg ==  SADB_X_EALG_NULL_AES_GMAC) {
		if (keylen == 128)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES128_NULL;
		else if (keylen == 192)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES192_NULL;
		else if (keylen == 256)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES256_NULL;
		else
			return -1;
	} else {
		if (keylen == 128)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES128;
		else if (keylen == 192)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES192;
		else if (keylen == 256)
			cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_AES256;
		else
			return -1;
	}
	return 0;
}

static int nfp_net_xfrm_add_state(struct xfrm_state *x)
{
	int i, key_len, trunc_len, err, saidx, saidx_base;
	struct nfp_net_ipsec_sa_data *sa_data;
	struct nfp_ipsec_cfg_add_sa *cfg;
	struct nfp_net_ipsec_data *ipd;
	struct nfp_ipsec_cfg_mssg msg;
	struct net_device *netdev;
	uint32_t *p;

	netdev = x->xso.dev;
	cfg = &msg.cfg_add_sa;
	ipd = nfp_ipsec_get_handle(netdev);

	/* XXX: Firmware doesn't currently accept sharing the same SAIDX for
	 * different ports, so we segregate them temporarily.
	 * The right thing to do here is allocate IDs up to
	 * NFP_NET_IPSEC_MAX_SA_CNT.
	 */
	saidx_base = nfp_ipsec_get_index(netdev) * 256;
	saidx = ida_simple_get(&ipd->ida_handle, saidx_base, saidx_base + 255,
			       GFP_KERNEL);
	if (saidx < 0)
		return saidx;

	mutex_lock(&ipd->lock);
	sa_data = &ipd->sa_entries[saidx];

	memset(&msg, 0, sizeof(msg));

	switch (x->props.mode) {
	case XFRM_MODE_TUNNEL:
		cfg->ctrl_word.mode = NFP_IPSEC_PROTMODE_TUNNEL;
		break;
	case XFRM_MODE_TRANSPORT:
		cfg->ctrl_word.mode = NFP_IPSEC_PROTMODE_TRANSPORT;
		break;
	default:
		dev_info(&netdev->dev, "Unsupported mode for xfrm offload\n");
		err = -ENOTSUPP;
		goto error;
	}

	switch (x->id.proto) {
	case IPPROTO_ESP:
		cfg->ctrl_word.proto = NFP_IPSEC_PROTOCOL_ESP;
		break;
	case IPPROTO_AH:
		cfg->ctrl_word.proto = NFP_IPSEC_PROTOCOL_AH;
		break;
	default:
		dev_info(&netdev->dev,
			 "Unsupported protocol for xfrm offload\n");
		err = -ENOTSUPP;
		goto error;
	}

	if (x->props.flags & XFRM_STATE_ESN)
		cfg->ctrl_word.ext_seq = 1;
	else
		cfg->ctrl_word.ext_seq = 0;

	/* XXX: use configurable replay window enable */
	cfg->ctrl_word.ena_arw = 0;
	/* XXX: use configurable replay width */
	cfg->ctrl_word.ext_arw = 0;

	cfg->spi = htonl(x->id.spi);

	/* Hash/Authentication */
	if (x->aalg)
		trunc_len = x->aalg->alg_trunc_len;
	else
		trunc_len = 0;

	switch (x->props.aalgo) {
	case SADB_AALG_NONE:
		cfg->ctrl_word.hash = NFP_IPSEC_HASH_NONE;
		trunc_len = -1;
		break;
	case SADB_AALG_MD5HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_MD5_96;
		else if (trunc_len == 128)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_MD5_128;
		else
			trunc_len = 0;
		break;
	case SADB_AALG_SHA1HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA1_96;
		else if (trunc_len == 80)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA1_80;
		else
			trunc_len = 0;
		break;
	case SADB_X_AALG_SHA2_256HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA256_96;
		else if (trunc_len == 128)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA256_128;
		else
			trunc_len = 0;
		break;
	case SADB_X_AALG_SHA2_384HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA384_96;
		else if (trunc_len == 192)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA384_192;
		else
			trunc_len = 0;
		break;
	case SADB_X_AALG_SHA2_512HMAC:
		if (trunc_len == 96)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA512_96;
		else if (trunc_len == 256)
			cfg->ctrl_word.hash = NFP_IPSEC_HASH_SHA512_256;
		else
			trunc_len = 0;
		break;
	default:
		dev_info(&netdev->dev,
			 "Unsupported authentication algorithm\n");
		err = -ENOTSUPP;
		goto error;
	}

	if (!trunc_len) {
		dev_info(&netdev->dev,
			 "Unsupported authentication algorithm trunc length\n");
		err = -ENOTSUPP;
		goto error;
	}

	if (x->aalg) {
		p = (uint32_t *)x->aalg->alg_key;
		key_len = (x->aalg->alg_key_len + 7) / 8;
		if (key_len > sizeof(cfg->auth_key)) {
			dev_info(&netdev->dev,
				 "Insufficient space for offloaded auth key\n");
			err = -EINVAL;
			goto error;
		}
		for (i = 0; i < key_len / 4; i++)
			cfg->auth_key[i] = htonl(*p++);
	}

	/* Encryption */
	switch (x->props.ealgo) {
	case SADB_EALG_NONE:
	case SADB_EALG_NULL:
		cfg->ctrl_word.cimode = NFP_IPSEC_CIMODE_CBC;
		cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_NULL;
		break;
	case SADB_EALG_3DESCBC:
		cfg->ctrl_word.cimode = NFP_IPSEC_CIMODE_CBC;
		cfg->ctrl_word.cipher = NFP_IPSEC_CIPHER_3DES;
		break;
	case SADB_X_EALG_AES_GCM_ICV16:
	case SADB_X_EALG_NULL_AES_GMAC:
		if (x->aead->alg_icv_len != 128) {
			dev_info(&netdev->dev,
				 "ICV must be 128bit with SADB_X_EALG_AES_GCM_ICV16\n");
			err = -EINVAL;
			goto error;
		}
		cfg->ctrl_word.cimode = NFP_IPSEC_CIMODE_CTR;
		cfg->ctrl_word.hash = NFP_IPSEC_HASH_GF128_128;
		if (!x->aead) {
			dev_info(&netdev->dev, "Invalid AES key data\n");
			err = -EINVAL;
			goto error;
		}
		/* aead->alg_key_len includes 32-bit salt */
		if (set_aes_keylen(cfg, x->props.ealgo,
				   x->aead->alg_key_len - 32)) {
			dev_info(&netdev->dev,
				 "Unsupported AES key length %d\n",
				 x->aead->alg_key_len);
			err = -ENOTSUPP;
			goto error;
		}
		break;
	case SADB_X_EALG_AESCBC:
		cfg->ctrl_word.cimode = NFP_IPSEC_CIMODE_CBC;
		if (!x->ealg) {
			dev_info(&netdev->dev, "Invalid AES key data\n");
			err = -EINVAL;
			goto error;
		}
		if (set_aes_keylen(cfg, x->props.ealgo,
				   x->ealg->alg_key_len) < 0) {
			dev_info(&netdev->dev,
				 "Unsupported AES key length %d\n",
				 x->ealg->alg_key_len);
			err = -ENOTSUPP;
			goto error;
		}
		break;
	default:
		dev_info(&netdev->dev,
			 "Unsupported encryption algorithm for offload\n");
		err = -ENOTSUPP;
		goto error;
	}

	if (x->aead) {
		int salt_len = 4;

		p = (uint32_t *)x->aead->alg_key;
		key_len = (x->aead->alg_key_len + 7) / 8;
		key_len -= salt_len;

		if (key_len > sizeof(cfg->ciph_key)) {
			dev_info(&netdev->dev,
				 "Insufficient space for offloaded key\n");
			err = -EINVAL;
			goto error;
		}

		for (i = 0; i < key_len / 4; i++)
			cfg->ciph_key[i] = htonl(*p++);

		/* load up the salt */
		for (i = 0; i < salt_len; i++)
			cfg->auth_key[i] = htonl(*p++);
	}

	if (x->ealg) {
		p = (uint32_t *)x->ealg->alg_key;
		key_len = (x->ealg->alg_key_len + 7) / 8;
		if (key_len > sizeof(cfg->ciph_key)) {
			dev_info(&netdev->dev,
				 "Insufficient space for offloaded key\n");
			err = -EINVAL;
			goto error;
		}
		for (i = 0; i < key_len / 4; i++)
			cfg->ciph_key[i] = htonl(*p++);
	}

	/* IP related info */
	switch (x->props.family) {
	case AF_INET:
		cfg->ipv6 = 0;
		cfg->src_ip[0] = htonl(x->props.saddr.a4);
		cfg->dst_ip[0] = htonl(x->id.daddr.a4);
		break;
	case AF_INET6:
		cfg->ipv6 = 1;
		for (i = 0; i < 4; i++) {
			cfg->src_ip[i] = htonl(x->props.saddr.a6[i]);
			cfg->dst_ip[i] = htonl(x->id.daddr.a6[i]);
		}
		break;
	default:
		dev_info(&netdev->dev, "Unsupported address family\n");
		err = -ENOTSUPP;
		goto error;
	}

	/* Maximum nic IPsec code could handle. Other limits may apply. */
	cfg->pmtu_limit = 0xffff;

	/* Not used */
	cfg->bypass_DSCP = 0;
	cfg->frag_check = 0;
	cfg->df_ctrl = 0;
	cfg->tfc_enable = 0;
	cfg->tfc_padding = 0;
	cfg->udp_enable = 0;
	cfg->natt_dst_port = 0;
	cfg->natt_src_port = 0;

	/* we rely on the host to enforce the lifetime */
	cfg->soft_lifetime_byte_count = 0;
	cfg->hard_lifetime_byte_count = 0;
	cfg->soft_lifetime_time_limit = 0;
	cfg->hard_lifetime_time_limit = 0;

	cfg->ctrl_word.encap_dsbl = 1;

	/* host will generate the sequence numbers so that
	 * if packets get fragmented in host, sequence
	 * numbers will stay in sync
	 */
	cfg->ctrl_word.gen_seq = 0;

	/* allocate saidx and commit the SA */
	sa_data->invalidated = 0;
	sa_data->x = x;
	x->xso.offload_handle = NFP_NET_IPSEC_SAIDX_TO_HANDLE(saidx);

	err = nfp_ipsec_cfg_cmd_issue(netdev, NFP_IPSEC_CFG_MSSG_ADD_SA, saidx,
				      &msg);
	if (err) {
		dev_err(&netdev->dev, "Failed to issue ipsec ADD config: %d\n",
			err);
		goto error;
	}

	mutex_unlock(&ipd->lock);
	return 0;

error:
	mutex_unlock(&ipd->lock);
	ida_simple_remove(&ipd->ida_handle, saidx);

	/* XXX: This is a workaround for a core XFRM problem. If the offload
	 * fails, the ref count of the netdev will become negative.
	 */
	x->xso.offload_handle = NFP_NET_IPSEC_HANDLE_ERROR;
	return 0;
}

static void
xfrm_invalidate(struct net_device *netdev, unsigned int saidx, int is_del)
{
	struct nfp_net_ipsec_sa_data *sa_data;
	struct nfp_net_ipsec_data *ipd;
	struct nfp_ipsec_cfg_mssg msg;
	int err;

	ipd = nfp_ipsec_get_handle(netdev);
	sa_data = &ipd->sa_entries[saidx];

	if (sa_data->invalidated && is_del) {
		netdev_warn(netdev, "unexpected invalidate state for offloaded saidx %d\n",
			    saidx);
		return;
	}

	if (is_del)
		err = nfp_ipsec_cfg_cmd_issue_async(netdev,
						    NFP_IPSEC_CFG_MSSG_INV_SA,
						    saidx, &msg);
	else
		err = nfp_ipsec_cfg_cmd_issue(netdev, NFP_IPSEC_CFG_MSSG_INV_SA,
					      saidx, &msg);

	if (err)
		netdev_warn(netdev,
			    "failed to invalidate SA in hardware\n");
	sa_data->invalidated = 1;
}

static void nfp_net_xfrm_del_state(struct xfrm_state *x)
{
	struct nfp_net_ipsec_data *ipd = nfp_ipsec_get_handle(x->xso.dev);

	if (x->xso.offload_handle == NFP_NET_IPSEC_HANDLE_ERROR)
		return;

	mutex_lock(&ipd->lock);
	xfrm_invalidate(x->xso.dev,
			NFP_NET_IPSEC_HANDLE_TO_SAIDX(x->xso.offload_handle),
			1);
	mutex_unlock(&ipd->lock);
}

static void nfp_net_xfrm_free_state(struct xfrm_state *x)
{
	struct nfp_net_ipsec_data *ipd;
	int saidx;

	if (x->xso.offload_handle == NFP_NET_IPSEC_HANDLE_ERROR)
		return;

	ipd = nfp_ipsec_get_handle(x->xso.dev);

	mutex_lock(&ipd->lock);

	saidx = NFP_NET_IPSEC_HANDLE_TO_SAIDX(x->xso.offload_handle);
	xfrm_invalidate(x->xso.dev, saidx, 0);
	ipd->sa_entries[saidx].x = NULL;

	mutex_unlock(&ipd->lock);

	ida_simple_remove(&ipd->ida_handle, saidx);
}

static bool nfp_net_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	if (x->xso.offload_handle == NFP_NET_IPSEC_HANDLE_ERROR) {
		pr_warn_ratelimited("xfrm offload failed, invalid handle\n");
		return false;
	}

	/* XXX: test for unsupported offloads */
	return true;
}

int nfp_net_ipsec_tx_prep(struct sk_buff *skb)
{
	struct xfrm_offload *xo;
	struct xfrm_state *x;
	unsigned char *md;

	xo = xfrm_offload(skb);
	if (!xo)
		return 0;

	/* Note that we don't error out here as we should have taken the
	 * opportunity to do so in nfp_net_ipsec_offload_ok.
	 */

	x = xfrm_input_state(skb);
	if (unlikely(!x || x->xso.offload_handle == NFP_NET_IPSEC_HANDLE_ERROR))
		return 0;

	if (unlikely(skb_cow_head(skb, 12))) {
		pr_warn_ratelimited("No space for xfrm offload\n");
		return -ENOMEM;
	}
	md = skb_push(skb, 12);

	put_unaligned_be32(NFP_NET_IPSEC_HANDLE_TO_SAIDX(x->xso.offload_handle),
			   md);
	put_unaligned_be32(xo->seq.low, md + 4);
	put_unaligned_be32(xo->seq.hi, md + 8);

	return 12;
}

int nfp_net_ipsec_rx(struct sk_buff *skb, unsigned int ipsec_saidx)
{
	struct nfp_net_ipsec_sa_data *sa_data;
	struct nfp_net_ipsec_data *ipd;
	struct xfrm_offload *xo;
	struct xfrm_state *x;
	int saidx;

	saidx = ipsec_saidx & ~NFP_IPSEC_SAIDX_RECEIVED;
	if (unlikely(saidx > NFP_NET_IPSEC_MAX_SA_CNT || saidx < 0)) {
		pr_warn_ratelimited("%s: invalid SAIDX from NIC (%d)\n",
				    skb->dev->name, saidx);
		return -EINVAL;
	}

	ipd = nfp_ipsec_get_handle(skb->dev);
	if (unlikely(!ipd)) {
		pr_warn_ratelimited("%s: no IPsec device handle\n",
				    skb->dev->name);
		return -EINVAL;
	}

	sa_data = &ipd->sa_entries[saidx];
	if (unlikely(!sa_data->x)) {
		pr_warn_ratelimited("%s: unused SAIDX from NIC (%d)\n",
				    skb->dev->name, saidx);
		return -ENOENT;
	}

	x = sa_data->x;
	xfrm_state_hold(x);

	WARN_ON(skb->sp);
	skb->sp = secpath_dup(skb->sp);
	if (unlikely(!skb->sp)) {
		pr_warn_ratelimited("%s: failed to alloc secpath for RX offload\n",
				    skb->dev->name);
		return -ENOMEM;
	}

	skb->sp->xvec[skb->sp->len++] = x;
	skb->sp->olen++;

	xo = xfrm_offload(skb);
	xo->flags = CRYPTO_DONE;
	xo->status = CRYPTO_SUCCESS;

	return 0;
}

const struct xfrmdev_ops nfp_net_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add = nfp_net_xfrm_add_state,
	.xdo_dev_state_delete = nfp_net_xfrm_del_state,
	.xdo_dev_state_free = nfp_net_xfrm_free_state,
	.xdo_dev_offload_ok = nfp_net_ipsec_offload_ok,
};

int nfp_net_ipsec_init(struct net_device *netdev)
{
	struct nfp_net_ipsec_data *ipd;
	struct nfp_repr *repr;
	struct nfp_net *nn;

	ipd = kzalloc(sizeof(*ipd), GFP_KERNEL);
	if (!ipd)
		return -ENOMEM;

	mutex_init(&ipd->lock);
	ida_init(&ipd->ida_handle);
	netdev->xfrmdev_ops = &nfp_net_ipsec_xfrmdev_ops;

	if (nfp_netdev_is_nfp_repr(netdev)) {
		repr = netdev_priv(netdev);
		repr->ipsec_data = ipd;
	} else {
		nn = netdev_priv(netdev);
		nn->ipsec_data = ipd;
	}

	return 0;
}

void nfp_net_ipsec_clean(struct net_device *netdev)
{
	struct nfp_net_ipsec_data *ipd = nfp_ipsec_get_handle(netdev);
	struct nfp_repr *repr;
	struct nfp_net *nn;

	if (!ipd)
		return;

	mutex_destroy(&ipd->lock);
	ida_destroy(&ipd->ida_handle);
	kfree(ipd);

	if (nfp_netdev_is_nfp_repr(netdev)) {
		repr = netdev_priv(netdev);
		repr->ipsec_data = NULL;
	} else {
		nn = netdev_priv(netdev);
		nn->ipsec_data = NULL;
	}
}
