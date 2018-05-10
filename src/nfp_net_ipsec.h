/*
 * Copyright (C) 2017-2018 Netronome Systems, Inc.
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

#ifndef __NFP_NET_IPSEC_H__
#define __NFP_NET_IPSEC_H__

/**
 * IPsec config message format, for messages sent
 * to the NFP via the 'Control BAR' in the PCIE
 * BAR mapped memory region.
 */

/**
 * IPsec config message cmd codes
 * %NFP_IPSEC_CFG_MSSG_ADD_SA:	add a new SA
 * %NFP_IPSEC_CFG_MSSG_INV_SA:	invalidate an existing SA
 * %NFP_IPSEC_CFG_MSSG_MODIFY_SA:	modify an existing SA
 * %NFP_IPSEC_CFG_MSSG_GET_SA_STATS:	report SA counters, flags, etc
 * %NFP_IPSEC_CFG_MSSG_GET_SEQ_NUMS:	allocate sequence numbers
 */
enum nfp_ipsec_cfg_mssg_cmd_codes {
	NFP_IPSEC_CFG_MSSG_ADD_SA,
	NFP_IPSEC_CFG_MSSG_INV_SA,
	NFP_IPSEC_CFG_MSSG_MODIFY_SA,
	NFP_IPSEC_CFG_MSSG_GET_SA_STATS,
	NFP_IPSEC_CFG_MSSG_GET_SEQ_NUMS,
	NFP_IPSEC_CFG_MSSG_LAST
};

/**
 * IPsec config message response codes
 */
enum nfp_ipsec_cfg_mssg_rsp_codes {
	NFP_IPSEC_CFG_MSSG_OK,
	NFP_IPSEC_CFG_MSSG_FAILED,
	NFP_IPSEC_CFG_MSSG_SA_VALID,
	NFP_IPSEC_CFG_MSSG_SA_HASH_ADD_FAILED,
	NFP_IPSEC_CFG_MSSG_SA_HASH_DEL_FAILED,
	NFP_IPSEC_CFG_MSSG_SA_INVALID_CMD
};

/* Protocol */
enum nfp_ipsec_sa_prot {
	NFP_IPSEC_PROTOCOL_AH = 0,
	NFP_IPSEC_PROTOCOL_ESP = 1
};

/* Mode */
enum nfp_ipsec_sa_mode {
	NFP_IPSEC_PROTMODE_TRANSPORT = 0,
	NFP_IPSEC_PROTMODE_TUNNEL = 1
};

/* Cipher types */
enum nfp_ipsec_sa_cipher {
	NFP_IPSEC_CIPHER_NULL,
	NFP_IPSEC_CIPHER_3DES,
	NFP_IPSEC_CIPHER_AES128,
	NFP_IPSEC_CIPHER_AES192,
	NFP_IPSEC_CIPHER_AES256,
	NFP_IPSEC_CIPHER_AES128_NULL,
	NFP_IPSEC_CIPHER_AES192_NULL,
	NFP_IPSEC_CIPHER_AES256_NULL,
	NFP_IPSEC_CIPHER_CHACHA20,
};

/* Cipher modes */
enum nfp_ipsec_sa_cipher_mode {
	NFP_IPSEC_CIMODE_ECB,
	NFP_IPSEC_CIMODE_CBC,
	NFP_IPSEC_CIMODE_CFB,
	NFP_IPSEC_CIMODE_OFB,
	NFP_IPSEC_CIMODE_CTR,
};

/* Hash types */
enum nfp_ipsec_sa_hash_type {
	NFP_IPSEC_HASH_NONE,
	NFP_IPSEC_HASH_MD5_96,
	NFP_IPSEC_HASH_SHA1_96,
	NFP_IPSEC_HASH_SHA256_96,
	NFP_IPSEC_HASH_SHA384_96,
	NFP_IPSEC_HASH_SHA512_96,
	NFP_IPSEC_HASH_MD5_128,
	NFP_IPSEC_HASH_SHA1_80,
	NFP_IPSEC_HASH_SHA256_128,
	NFP_IPSEC_HASH_SHA384_192,
	NFP_IPSEC_HASH_SHA512_256,
	NFP_IPSEC_HASH_GF128_128,
	NFP_IPSEC_HASH_POLY1305_128,
};

/**
 * For aes-gcm-esp use the following combination:
 *
 * NFP_IPSEC_PROTOCOL_ESP
 * NFP_IPSEC_CIPHER_AES_xxx (xxx is key size: 128,192, or 256 )
 * NFP_IPSEC_CIMODE_CTR
 * NFP_IPSEC_HASH_GF128_128
 *
 * provide the salt value instead of the auth key in the sa
 */
struct nfp_ipsec_cfg_mssg {
	u32 cmd:16;       /* One of nfp_ipsec_cfg_mssg_cmd_codes */
	u32 rsp:16;       /* One of nfp_ipsec_cfg_mssg_rsp_codes */
	u32 sa_idx:16;    /* SA table index */
	u32 stack_idx:16; /* IPSec stack index */

	union {
		/* IPSEC_CFG_MSSG_ADD_SA */
		struct nfp_ipsec_cfg_add_sa {
			u32 ciph_key[8];    /* Cipher Key */
			union {
				u32 auth_key[16];   /* Authentication Key */
				/* AES-GCM-ESP fields */
				struct nfp_ipsec_aesgcm {
					u32 salt;     /* initialized with sa */
					u32 iv[2];    /* firmware use only */
					s32 cntr;     /* firmware use only */
					u32 zeros[4]; /* init to 0 with sa */
					u32 len_a[2]; /* firmware use only */
					u32 len_c[2]; /* firmware use only */
					u32 spare0[4];
				} aesgcm_fields;
			};
			struct sa_ctrl_word {
				u32 hash   :4; /* nfp_ipsec_sa_hash_type */
				u32 cimode :4; /* nfp_ipsec_sa_cipher_mode */
				u32 cipher :4; /* nfp_ipsec_sa_cipher */
				u32 mode   :2; /* nfp_ipsec_sa_mode */
				u32 proto  :2; /* nfp_ipsec_sa_prot */
				u32 spare1 :1; /* Should be 0 */
				u32 ena_arw:1; /* Anti-Replay Window */
				u32 ext_seq:1; /* 64-bit Sequence Num */
				u32 ext_arw:1; /* 64b Anti-Replay Window */
				u32 spare2 :9; /* Must be set to 0 */
				u32 encap_dsbl:1;/* Encap/decap disable */
				u32 gen_seq:1; /* Firmware Generate Seq #'s */
				u32 spare8 :1; /* Must be set to 0 */
			} ctrl_word;
			u32 spi; /* SPI Value */

			u32 pmtu_limit :16; /* PMTU Limit */
			u32 spare3     :1;
			u32 frag_check :1; /* Stateful fragment checking flag */
			u32 bypass_DSCP:1; /* Bypass DSCP Flag */
			u32 df_ctrl    :2; /* DF Control bits */
			u32 ipv6       :1; /* Outbound IPv6 addr format */
			u32 udp_enable :1; /* Add/Remove UDP header for NAT */
			u32 tfc_enable :1; /* Traffic Flw Confidentiality */
			u32 spare4     :8;
			u32 soft_lifetime_byte_count;
			u32 hard_lifetime_byte_count;
			u32 src_ip[4]; /* Src IP addr */
			u32 dst_ip[4]; /* Dst IP addr */
			u32 natt_dst_port :16; /* NAT-T UDP Header dst port */
			u32 natt_src_port :16; /* NAT-T UDP Header src port */
			u32 soft_lifetime_time_limit;
			u32 hard_lifetime_time_limit;
			u32 sa_creation_time_lo_32; /* ucode fills this in */
			u32 sa_creation_time_hi_32; /* ucode fills this in */
			u32 reserved0   :16;
			u32 tfc_padding :16; /* Traffic Flow Confidential Pad */
		} cfg_add_sa;
		/* IPSEC_CFG_MSSG_INV_SA */
		struct nfp_ipsec_cfg_inv_sa {
			u32 spare6;
		} cfg_inv_sa;
		/* IPSEC_CFG_MSSG_GET_SA_STATS */
		struct nfp_ipsec_cfg_get_sa_stats {
			u32 seq_lo; /* Sequence Number (low 32bits) */
			u32 seq_high; /* Sequence Number (high 32bits)*/
			u32 arw_counter_lo;  /* Anti-replay wndw cntr */
			u32 arw_counter_high;/* Anti-replay wndw cntr */
			u32 arw_bitmap_lo;   /* Anti-replay wndw bitmap */
			u32 arw_bitmap_high; /* Anti-replay wndw bitmap */
			u32 reserved1:1;
			u32 soft_lifetime_byte_cnt_exceeded :1; /* Soft */
			u32 hard_lifetime_byte_cnt_exceeded :1; /* Hard */
			u32 soft_lifetime_time_limit_exceeded :1; /* Soft */
			u32 hard_lifetime_time_limit_exceeded :1; /* Hard */
			u32 spare7:27;
			u32 lifetime_byte_count;
			u32 pkt_count;
			u32 discards_auth; /* Auth failures */
			u32 discards_unsupported; /* Unsupported crypto mode */
			u32 discards_alignment; /* Alignment error */
			u32 discards_hard_bytelimit; /* Byte Count limit */
			u32 discards_seq_num_wrap; /* Sequ Number wrap */
			u32 discards_pmtu_limit_exceeded; /* PMTU Limit */
			u32 discards_arw_old_seq; /* Anti-Replay seq small */
			u32 discards_arw_replay; /* Anti-Replay seq rcvd */
			u32 discards_ctrl_word; /* Bad SA Control word */
			u32 discards_ip_hdr_len; /* Hdr offset from too high */
			u32 discards_eop_buf; /* No EOP buffer */
			u32 ipv4_id_counter; /* IPv4 ID field counter */
			u32 discards_isl_fail; /* Inbound SPD Lookup failure */
			u32 discards_ext_not_found; /* Ext header end */
			u32 discards_max_ext_hdrs; /* Max ext header */
			u32 discards_non_ext_hdrs; /* Non-extension headers */
			u32 discards_ext_hdr_too_big; /* Ext header chain */
			u32 discards_hard_timelimit; /* Time Limit limit */
		} cfg_get_stats;
		/* IPSEC_CFG_MSSG_GET_SEQ_NUMS */
		struct ipsec_cfg_get_seq_nums {
			u32 seq_nums; /* # sequence numbers to allocate */
			u32 seq_num_low; /* rtrn start seq num 31:00 */
			u32 seq_num_hi;  /* rtrn start seq num 63:32 */
		} cfg_get_seq_nums;

		u32 raw[62];
	};
};

#ifdef CONFIG_NFP_NET_IPSEC

int nfp_net_ipsec_init(struct net_device *netdev);
void nfp_net_ipsec_clean(struct net_device *netdev);

#else

static inline int nfp_net_ipsec_init(struct net_device *netdev)
{
	return 0;
}

static inline void nfp_net_ipsec_clean(struct net_device *netdev)
{
}

#endif

#endif /* __NFP_NET_IPSEC_H__ */
