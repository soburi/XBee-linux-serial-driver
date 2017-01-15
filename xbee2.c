#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/tty.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/seq_buf.h>
#include <linux/nl80211.h>
#include <net/mac802154.h>
#include <net/regulatory.h>

#include "modtest.h"


#define N_IEEE802154_XBEE 25
#define VERSION 1

#define XBEE_CHAR_NEWFRM 0x7e

enum {
	STATE_WAIT_START1,
	STATE_WAIT_START2,
	STATE_WAIT_COMMAND,
	STATE_WAIT_PARAM1,
	STATE_WAIT_PARAM2,
	STATE_WAIT_DATA
};

#define AT_DECL(x, y) ( x << 8 | y )

enum {
	XBEE_AT_VR = AT_DECL('V','R'),
	XBEE_AT_CH = AT_DECL('C','H'),
};

/*********************************************************************/

struct xb_device {
	struct work_struct work;
	struct tty_struct *tty;
	struct ieee802154_hw *dev;

	struct completion cmd_resp_done;
	uint8_t wait_frameid;

	struct workqueue_struct    *comm_workq;

    struct sk_buff_head recv_queue;
    struct sk_buff_head send_queue;
    struct sk_buff* recv_buf;

	uint8_t frameid;
	unsigned short firmware_version;

	DECL_MODTEST_STRUCT();
};

struct xbee_frame {
	struct list_head list;
	int ack;

	u16 len;
	u8 id;
	unsigned char *raw_data;
	u8 csum;

	/* parsed elements */
	u8 fid;
	u8 status;
	unsigned char cmd[2];
	u8 addr[IEEE802154_ADDR_LEN];
//	u8 saddr[IEEE802154_SHORT_ALEN];
    __le16 saddr;
	u8 flags;
	u8 rssi;
	unsigned char *data;
};

struct xb_frameheader {
	uint8_t start_delimiter; // 0x7e
	uint16_t length;
	uint8_t type;
} __attribute__((aligned(1), packed));

struct xb_at_frame {
	uint8_t start_delimiter; // 0x7e
	uint16_t length;
	uint8_t type;
	uint8_t id;
	uint16_t command;
} __attribute__((aligned(1), packed));

/* API frame types */
enum {
	XBEE_FRM_TX64	= 0x00,
	XBEE_FRM_TX16	= 0x01,
	XBEE_FRM_CMD	= 0x08,
	XBEE_FRM_CMDQ	= 0x09,
	XBEE_FRM_RCMD	= 0x17,
	XBEE_FRM_RX64	= 0x80,
	XBEE_FRM_RX16	= 0x81,
	XBEE_FRM_RX64IO	= 0x82,
	XBEE_FRM_RX16IO	= 0x83,
	XBEE_FRM_CMDR	= 0x88,
	XBEE_FRM_TXS	= 0x89,
	XBEE_FRM_STAT	= 0x8A,
	XBEE_FRM_RCMDR	= 0x97,
};

static unsigned char buffer_calc_checksum(const unsigned char* buf, const size_t len)
{
	int i=0;
	unsigned char checksum = 0;
	for(i=0; i<len; i++) {
		checksum += buf[i];
	}
	return 0xFF - checksum;
}

static int buffer_find_delimiter_unescaped(const unsigned char* buf, const size_t len)
{
	int i=0;
	for(i=0; i<len; i++) {
		if(buf[i] == 0x7E) return i;
	}
	return -1;
}

static int buffer_find_delimiter_escaped(const unsigned char* buf, const size_t len)
{
	int i=0;
	bool esc = false;
	for(i=0; i<len; i++) {
		if(buf[i] == 0x7D) {
			esc = true; continue;
		}
		else if(buf[i] == 0x5E && esc) {
			return i-1;
		}
		else if(buf[i] == 0x7E && !esc) {
			return i;
		}
		esc = false;
	}
	return -1;
}


static size_t buffer_unescape(unsigned char* buf, const size_t len)
{
	int i=0;
	int escape_count = 0;
	bool esc = false;

	for(i=0; i<len; i++) {
		if(buf[i] == 0x7D) {
			esc = true;
			escape_count++;
			continue;
		}
		if(esc) buf[i-escape_count] = (buf[i] ^ 0x20);
		else    buf[i-escape_count] =  buf[i];
		esc = false;
	}
	if(esc) {
		buf[i-escape_count] = 0x7D;
		escape_count--;
	}

	return len-escape_count;
}

static struct sk_buff* frame_new(size_t paylen, uint8_t type)
{
	struct sk_buff* new_skb = NULL;
	struct xb_frameheader* frm = NULL;
	unsigned char* tail = NULL;

	new_skb = alloc_skb(paylen+5, GFP_KERNEL); //delimiter, length, checksum
	tail = skb_put(new_skb, paylen+5);

	frm = (struct xb_frameheader*)tail;
	frm->start_delimiter  = XBEE_CHAR_NEWFRM;
	frm->length = htons(paylen+1);
	frm->type = type;
	return new_skb;
}

static const unsigned char frame_payload_length(struct sk_buff* frame)
{
	struct xb_frameheader* frm = (struct xb_frameheader*)frame->data;
	return htons(frm->length);
}

static const unsigned char* frame_payload_buffer(struct sk_buff* frame)
{
	return frame->data + 3;
}

static unsigned char frame_calc_checksum(struct sk_buff* frame)
{
	return buffer_calc_checksum(frame_payload_buffer(frame), frame_payload_length(frame) );
}

static int frame_verify(struct sk_buff* recv_buf)
{
	unsigned short length = 0;
	uint8_t checksum = 0;
	struct xb_frameheader* header = NULL;

	if(recv_buf->len < 1) return -EAGAIN;
	header = (struct xb_frameheader*)recv_buf->data;

	if(recv_buf->data[0] != XBEE_CHAR_NEWFRM) return -EINVAL;

	if(recv_buf->len < 3) return -EAGAIN;

	length = htons(header->length);
	if(recv_buf->len < length+4) return -EAGAIN;

	checksum = frame_calc_checksum(recv_buf);
	if(checksum!=recv_buf->data[length+3]) return -EINVAL;

    return length+4;
}

static int frame_put_received_data(struct sk_buff* recv_buf, const unsigned char* buf, const size_t len)
{
	int delimiter_pos = 0;
	unsigned char* tail = NULL;

	delimiter_pos = buffer_find_delimiter_escaped(buf, len);

	if(recv_buf->len == 0) {
		if(delimiter_pos == -1) {
			return 0;
		}
		tail = skb_put(recv_buf, len-delimiter_pos);
		memcpy(tail, buf+delimiter_pos, len-delimiter_pos);
		return len-delimiter_pos;
	}
	else {
		tail = skb_put(recv_buf, len);
		memcpy(tail, buf, len);
		return len;
	}
}

static int frame_enqueue_received(struct sk_buff_head *recv_queue, struct sk_buff* recv_buf)
{
	int frame_count = 0;
	int unesc_len = 0;
	int ret = 0;

	unesc_len = buffer_unescape(recv_buf->data, recv_buf->len);
	skb_trim(recv_buf, unesc_len);

	while ( (ret = frame_verify(recv_buf)) > 0) {
		int verified_len = ret;
		int remains = recv_buf->len - verified_len;
		unsigned char* append = NULL;
		struct sk_buff* newframe = NULL;

		newframe = alloc_skb(128, GFP_ATOMIC);

		append = skb_put(newframe, verified_len);
		memcpy(append, recv_buf->data, verified_len);
		skb_queue_tail(recv_queue, newframe);

		memmove(recv_buf->data, recv_buf->data+verified_len,  remains);
		skb_trim(recv_buf, remains);

		frame_count++;
	}

	if (ret == -EINVAL) {
		skb_trim(recv_buf, 0);
	}

	return frame_count;
}

static void frame_enqueue_send(struct sk_buff_head *send_queue, struct sk_buff* send_buf)
{
	skb_queue_tail(send_queue, send_buf);
}

static void frame_enqueue_send_at(struct sk_buff_head *send_queue, unsigned short atcmd, uint8_t id, char* buf, unsigned short buflen)
{
	struct sk_buff* newskb = NULL;
	struct xb_at_frame* atfrm = NULL;

	unsigned char checksum = 0;
	int datalen = 0;

	newskb = frame_new(buflen+3, XBEE_FRM_CMD);
	atfrm = (struct xb_at_frame*)newskb->data;

	atfrm->id = id;
	atfrm->command = htons(atcmd);

	datalen = htons(atfrm->length);

	memmove(newskb->data + sizeof(struct xb_at_frame), buf, buflen);

	checksum = frame_calc_checksum(newskb);
	newskb->data[datalen+3] = checksum;

	frame_enqueue_send(send_queue, newskb);
}

static void xb_enqueue_send_at(struct xb_device *xb, unsigned short atcmd, char* buf, unsigned short buflen)
{
	frame_enqueue_send_at(&xb->send_queue, atcmd, xb->frameid++, buf, buflen);
}

static bool xb_process_send(struct xb_device* xb)
{
	bool already_on_queue = false;

	already_on_queue = queue_work(xb->comm_workq, (struct work_struct*)xb);

	return already_on_queue;
}

static bool xb_process_sendrecv(struct xb_device* xb)
{
	int ret = 0;

	xb_process_send(xb);
	ret = wait_for_completion_interruptible_timeout(&xb->cmd_resp_done, 1000);

	if(ret > 0) {
		pr_debug("complete %d\n", ret);
	}
	else if(ret == -ERESTARTSYS) {
		pr_debug("interrupted %d\n", ret);
	}
	else {
		pr_debug("timeout %d\n", ret);
	}

	return ret;
}

static void frame_recv_rx64(struct xb_device *xbdev,
                    struct sk_buff *skb)
{
//    struct sk_buff *lskb;
	pr_debug("%s\n", __func__);
//    lskb = alloc_skb(skb->len, GFP_ATOMIC);
//    skb_put(lskb, skb->len);
//    skb_copy_to_linear_data(lskb, skb->data, skb->len);
//	ieee802154_rx_irqsafe(xbdev->dev, lskb, skb->len);
//	ieee802154_rx(xbdev->dev, skb, rssi);
}

static void frame_recv_stat(struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
}

static void frame_recv_atcmd(struct xb_device *xbdev, char frameid, unsigned short atcmd, char status, char* buf, unsigned long buflen)
{
	pr_debug("%s [%c%c] frameid=%d len=%lu\n", __func__, atcmd&0xFF, (atcmd>>8)&0xFF, frameid, buflen );
	switch(atcmd) {
#if 0
	/* Special commands */
	case XBEE_AT_AC: break;
	case XBEE_AT_FR: break;
	case XBEE_AT_RE: break;
	case XBEE_AT_WR: break;
	/* MAC/PHY Commands */
	case XBEE_AT_CH: break;
	case XBEE_AT_ID: break;
	case XBEE_AT_MT: break;
	case XBEE_AT_CA: break;
	case XBEE_AT_PL: break;
	case XBEE_AT_RR: break;
	case XBEE_AT_ED: break;
	case XBEE_AT_BC: break;
	case XBEE_AT_DB: break;
	case XBEE_AT_GD: break;
	case XBEE_AT_EA: break;
	case XBEE_AT_TR: break;
	case XBEE_AT_UA: break;
	case XBEE_AT_perH: break;
	case XBEE_AT_per8: break;
	/* Network commands */
	case XBEE_AT_CE: break;
	case XBEE_AT_BH: break;
	case XBEE_AT_NH: break;
	case XBEE_AT_DM: break;
	case XBEE_AT_NN: break;
	/* Addressing commands */
	case XBEE_AT_SH: break;
	case XBEE_AT_SL: break;
	case XBEE_AT_DH: break;
	case XBEE_AT_DL: break;
	case XBEE_AT_NI: break;
	case XBEE_AT_NT: break;
	case XBEE_AT_NO: break;
	case XBEE_AT_CI: break;
	case XBEE_AT_DE: break;
	case XBEE_AT_SE: break;
	/* Diagnostic - addressing commands */
	case XBEE_AT_Nquest: break;
	/* Addressing discovery/configuration commands */
	case XBEE_AT_AG: break;
	case XBEE_AT_DN: break;
	case XBEE_AT_ND: break;
	case XBEE_AT_FN: break;
	/* Security commands */
	case XBEE_AT_EE: break;
	case XBEE_AT_KY: break;
	/* Serial interfacing commands */
	case XBEE_AT_BD: break;
	case XBEE_AT_NB: break;
	case XBEE_AT_RO: break;
	case XBEE_AT_FT: break;
	case XBEE_AT_AP: break;
	case XBEE_AT_AO: break;
	/* I/O settings commands */
	/* I/O sampling commands */
	/* Sleep commands */
	case XBEE_AT_SM: break;
	case XBEE_AT_SO: break;
	case XBEE_AT_SN: break;
	case XBEE_AT_SP: break;
	case XBEE_AT_ST: break;
	case XBEE_AT_WH: break;
	/* Diagnostic - sleep status/timing commands */
	case XBEE_AT_SS: break;
	case XBEE_AT_OS: break;
	case XBEE_AT_OW: break;
	case XBEE_AT_MS: break;
	case XBEE_AT_SQ: break;
	/* Command mode options */
	case XBEE_AT_CC: break;
	case XBEE_AT_CT: break;
	case XBEE_AT_CN: break;
	case XBEE_AT_GT: break;
	case XBEE_AT_VL: break;
#endif
	case XBEE_AT_VR: xbdev->firmware_version = *((unsigned short*)buf); break;
#if 0
	case XBEE_AT_HV: break;
	case XBEE_AT_DD: break;
	case XBEE_AT_NP: break;
	case XBEE_AT_CK: break;
#endif
	}


}

static void frame_recv_cmdr(struct xb_device *xbdev, struct sk_buff *skb)
{
	char frameid = *(skb->data+3);
	unsigned short atcmd = *((unsigned short*)(skb->data+4));
	char status = *(skb->data+6);
	char* data = (skb->data)+7;
	unsigned long datalen = (skb->len)-8;

	pr_debug("%s\n", __func__);

	print_hex_dump_bytes("data: ", DUMP_PREFIX_NONE, data, datalen);
	frame_recv_atcmd(xbdev, frameid, atcmd, status, data, datalen);
}

static void frame_recv_rcmdr(struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
}
//static void frame_recv_txstat(struct sk_buff *skb)
//{
//	pr_debug("%s\n", __func__);
//}
static void frame_recv_rx16(struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
}
/**
 * xbee_recv_frame - ...
 *
 * @xbdev: ...
 * @frame: ...
 *
 * Verify the XBee frame, then take appropriate action depending on the
 * frame type.
 */
static void frame_recv_dispatch(struct xb_device *xbdev, struct sk_buff *skb)
{
	struct xb_frameheader* frm = (struct xb_frameheader*)skb->data;

	pr_debug("%s\n", __func__);

	switch (frm->type) {
	case XBEE_FRM_STAT:
		frame_recv_stat(skb);
		break;
	case XBEE_FRM_CMDR:
		frame_recv_cmdr(xbdev, skb);
		break;
	case XBEE_FRM_RCMDR:
		frame_recv_rcmdr(skb);
		break;
//	case XBEE_FRM_TXSTAT:
//		frame_recv_txstat(skb);
//		break;
	case XBEE_FRM_RX64:
		frame_recv_rx64(xbdev, skb);
		break;
	case XBEE_FRM_RX16:
		frame_recv_rx16(skb);
		break;
	case XBEE_FRM_RX64IO:
	case XBEE_FRM_RX16IO:
		printk(KERN_WARNING "received unimplemented frame type 0x%x", frm->type);
		//skb_free(skb);
		break;
	case XBEE_FRM_CMD:
	case XBEE_FRM_CMDQ:
	case XBEE_FRM_RCMD:
	case XBEE_FRM_TX64:
	case XBEE_FRM_TX16:
		printk(KERN_WARNING "received tx-only frame type 0x%x", frm->type);
		//skb_free(skb);
		break;
	default:
//		XBEE_WARN("received unknown frame type 0x%x", id);
	    pr_debug("%s received unknown frame type 0x%x\n", __func__,  frm->type);
//		kfree_skb(skb);
		break;
	}
}

static void comm_work_fn(struct work_struct *param)
{
	struct xb_device* xb = NULL;
	struct tty_struct *tty = NULL;

	xb = (struct xb_device*)param;
	tty = xb->tty;

	if( !skb_queue_empty(&xb->recv_queue) ) {
		struct sk_buff* skb = skb_dequeue(&xb->recv_queue);

		if(skb) {
			print_hex_dump_bytes("<<<< ", DUMP_PREFIX_NONE, skb->data, skb->len);
			complete(&xb->cmd_resp_done);
			frame_recv_dispatch(xb, skb);
		}
	}

	if( !skb_queue_empty(&xb->send_queue) ) {
		struct sk_buff* skb = skb_dequeue(&xb->send_queue);

		if(skb) {
			print_hex_dump_bytes(">>>> ", DUMP_PREFIX_NONE, skb->data, skb->len);
			tty->ops->write(tty,  skb->data, skb->len);
			tty_driver_flush_buffer(tty);
		}
	}

}

//static void cleanup(struct xb_device *xbdev)
//{
//	pr_debug("%s\n", __func__);
//}

/*
 * Callbacks from mac802154 to the driver. Must handle xmit(). 
 *
 * See net/mac802154/ieee802154_hw.c, include/net/mac802154.h,
 * and net/mac802154/mac802154.h from linux-wsn.
 */

/**
 * xbee_ieee802154_set_channel - Set radio for listening on specific channel.
 *
 * @dev: ...
 * @page: ...
 * @channel: ...
 */
static int xbee_ieee802154_set_channel(struct ieee802154_hw *dev,
				       u8 page, u8 channel)
{
	struct xb_device *xb = NULL;

	xb = dev->priv;

	xb_enqueue_send_at(xb, XBEE_AT_CH, &channel, 1);
	xb_process_sendrecv(xb);
    return 0;
}

/**
 * xbee_ieee802154_ed - Handler that 802.15.4 module calls for Energy Detection.
 *
 * @dev: ...
 * @level: ...
 */
static int xbee_ieee802154_ed(struct ieee802154_hw *dev, u8 *level)
{
	struct xb_device *xb = NULL;
	
	pr_debug("%s\n", __func__);

	xb = dev->priv;
	xb_enqueue_send_at(xb, 0x4544, NULL, 0);

    return 0;
}

static int xbee_ieee802154_set_csma_params(struct ieee802154_hw *dev, u8 min_be, u8 max_be, u8 retries)
{
	pr_debug("%s\n", __func__);
	return 0;
}

/**
 * xbee_ieee802154_set_frame_retries - Handler that 802.15.4 module calls to set frame retries.
 *
 * @dev: ...
 * @level: ...
 */
static int xbee_ieee802154_set_frame_retries(struct ieee802154_hw *dev, s8 retries)
{
	struct xb_device *xb = NULL;
	unsigned char u_retries = retries;

	pr_debug("%s\n", __func__);

	xb = dev->priv;
	xb_enqueue_send_at(xb, 0x5252, &u_retries, 1);

    return 0;
}

static int xbee_ieee802154_set_txpower(struct ieee802154_hw *dev, s32 mbm)
{
	struct xb_device *xb = dev->priv;
	s32 dbm;
	u8 pl, pm;

	pr_debug("%s mbm=%d\n", __func__, mbm);

	dbm  = MBM_TO_DBM(mbm);

	if(dbm <= -5) {
		pl=0; pm=0;
	} else if(dbm <= -2) {
		pl=0; pm=1;
	} else if(dbm <= -1) {
		pl=1; pm=0;
	} else if(dbm <= 1) {
		pl=2; pm=0;
	} else if(dbm <= 2) {
		pl=1; pm=1;
	} else if(dbm <= 3) {
		pl=3; pm=0;
	} else if(dbm <= 4) {
		pl=2; pm=1;
	} else if(dbm <= 5) {
		pl=4; pm=0;
	} else if(dbm <= 6) {
		pl=3; pm=1;
	} else {
		pl=4; pm=1;
	}

	xb_enqueue_send_at(xb, 0x504C, &pl, 1);
	xb_enqueue_send_at(xb, 0x504D, &pm, 1);

	return 0;
}

static int xbee_ieee802154_set_cca_mode(struct ieee802154_hw *dev, const struct wpan_phy_cca *cca)
{
	pr_debug("%s cca=%p\n", __func__, cca);
	return 0;
}

static int xbee_ieee802154_set_cca_ed_level(struct ieee802154_hw *dev, s32 mbm)
{
	struct xb_device *xb = dev->priv;
    u8 ca;

    pr_debug("%s mbm=%d\n", __func__, mbm);

    ca = MBM_TO_DBM(mbm);

    xb_enqueue_send_at(xb, 0x4341, &ca, 1);
	return 0;
}

/**
 * xbee_ieee802154_xmit - Handler that 802.15.4 module calls for each transmitted frame.
 *
 * @dev: ...
 * @skb: ...
 */
static int xbee_ieee802154_xmit(struct ieee802154_hw *dev, struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
    return 0;
}

static int xbee_ieee802154_filter(struct ieee802154_hw *dev,
					  struct ieee802154_hw_addr_filt *filt,
					    unsigned long changed)
{
	pr_debug("%s\n", __func__);

	/*
	if(changed & IEEE802154_AFILT_SADDR_CHANGED) {
		filt->short_addr;
	} else if(IEEE802154_AFILT_IEEEADDR_CHANGED) {
		filt->ieee_addr;
	} else if(IEEE802154_AFILT_PANID_CHANGED) {
		filt->pan_id;
	} else if(IEEE802154_AFILT_PANC_CHANGED) {
		filt->pan_coord;
	}
	*/

    return 0;
}

/**
 * xbee_ieee802154_start - For device initialisation before the first interface is attached.
 *
 * @dev: ...
 */
static int xbee_ieee802154_start(struct ieee802154_hw *dev)
{
	struct xb_device *zbdev;
	int ret = 0;
//	u8 channel = 11;

	pr_debug("%s\n", __func__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __func__);
		return -EINVAL;
	}

	//pr_debug("send 0x4348\n");
	//channel = 11;
	//frame_sendrecv_at(zbdev, 0x4348, &channel, 1);
	//pr_debug("end send 0x4348\n");

	//pr_debug("%s end (retval: %d)\n", __func__, ret);
	return ret;
}

/**
 * xbee_ieee802154_stop - For device cleanup after last interface is removed.
 *
 * @dev: ...
 */
static void xbee_ieee802154_stop(struct ieee802154_hw *dev){
	struct xb_device *zbdev = NULL;
	pr_debug("%s\n", __func__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __func__);
		return;
	}

	pr_debug("%s end\n", __func__);
}

/*****************************************************************************
 * Line discipline interface for IEEE 802.15.4 serial device
 *****************************************************************************/

/**
 * xbee_ieee802154_ops - ieee802154 MCPS ops.
 *
 * This is part of linux-wsn. It is similar to netdev_ops.
 */
static struct ieee802154_ops xbee_ieee802154_ops = {
	.owner				= THIS_MODULE,
	.start				= xbee_ieee802154_start,
	.stop				= xbee_ieee802154_stop,
	.xmit_sync			= xbee_ieee802154_xmit,
	.xmit_async			= NULL,
	.ed					= xbee_ieee802154_ed,
	.set_channel		= xbee_ieee802154_set_channel,
	.set_hw_addr_filt	= xbee_ieee802154_filter,
	.set_txpower		= xbee_ieee802154_set_txpower,
	.set_lbt			= NULL,
	.set_cca_mode		= xbee_ieee802154_set_cca_mode,
	.set_cca_ed_level	= xbee_ieee802154_set_cca_ed_level,
	.set_csma_params	= xbee_ieee802154_set_csma_params,
	.set_frame_retries	= xbee_ieee802154_set_frame_retries,
	.set_promiscuous_mode = NULL,
};

/*
 * See Documentation/tty.txt for details.
 */

/**
 * xbee_ldisc_open - Initialize line discipline and register with ieee802154.
 *
 * @tty: TTY info for line.
 *
 * Called from a process context to change the TTY line discipline.
 * Called from a process context 
 *
 * 
 */
static int xbee_ldisc_open(struct tty_struct *tty)
{

	struct ieee802154_hw *dev;
	struct xb_device *xbdev = tty->disc_data;
	int err;

	pr_debug("%s\n", __func__);

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/*
	 * TODO: The traditional method to check if another line discipline
	 * is still installed has been to check tty->disc_data for a non-NULL
	 * address, even though line disciplines are under no obligation
	 * to clear it upon uninstallation.
	 */

	if (tty->disc_data != NULL)
		return -EBUSY;

//	if (tty->ops->stop)
//		tty->ops->stop(tty);

	tty_driver_flush_buffer(tty);

	dev = ieee802154_alloc_hw(sizeof(*xbdev), &xbee_ieee802154_ops);
	if (!dev)
		return -ENOMEM;

	xbdev = dev->priv;
	xbdev->dev = dev;
	xbdev->recv_buf = alloc_skb(128, GFP_ATOMIC);
	
	skb_queue_head_init(&xbdev->recv_queue);
	skb_queue_head_init(&xbdev->send_queue);

//	mutex_init(&xbdev->mutex);
	init_completion(&xbdev->cmd_resp_done);
	//init_waitqueue_head(&xbdev->frame_waitq);
	xbdev->comm_workq = create_workqueue("comm_workq");
	INIT_WORK( (struct work_struct*)xbdev, comm_work_fn);

	INIT_MODTEST(xbdev);

	dev->extra_tx_headroom = 0;
	/* only 2.4 GHz band */
	dev->phy->flags = WPAN_PHY_FLAG_TXPOWER |
			          WPAN_PHY_FLAG_CCA_ED_LEVEL |
					  WPAN_PHY_FLAG_CCA_MODE;
	dev->phy->current_channel = 11;
	dev->phy->current_page = 0;
	dev->phy->supported.channels[0] = 0x7fff800;
	dev->phy->supported.cca_modes = BIT(NL802154_CCA_ENERGY);
	dev->phy->supported.cca_opts = NL802154_CCA_ENERGY;
	dev->phy->supported.iftypes = 0;
	dev->phy->supported.lbt = 0;
	dev->phy->supported.min_minbe = 0;
	dev->phy->supported.max_minbe = 3;
	dev->phy->supported.min_maxbe = 5; /* N/A */
	dev->phy->supported.max_maxbe = 5; /* N/A */
	dev->phy->supported.min_csma_backoffs = 0; /* N/A */
	dev->phy->supported.max_csma_backoffs = 0; /* N/A */
	dev->phy->supported.min_frame_retries = 0;
	dev->phy->supported.max_frame_retries = 6;
	dev->phy->supported.tx_powers_size = 0;
/*
	dev->phy->supported.cca_ed_levels_size = 41;
	dev->phy->supported.cca_ed_levels = {
		DBM_TO_MBM(-0x28), DBM_TO_MBM(-0x29), DBM_TO_MBM(-0x2A), DBM_TO_MBM(-0x2B),
		DBM_TO_MBM(-0x2C), DBM_TO_MBM(-0x2D), DBM_TO_MBM(-0x2E), DBM_TO_MBM(-0x2F),
		DBM_TO_MBM(-0x30), DBM_TO_MBM(-0x31), DBM_TO_MBM(-0x32), DBM_TO_MBM(-0x33),
		DBM_TO_MBM(-0x34), DBM_TO_MBM(-0x35), DBM_TO_MBM(-0x36), DBM_TO_MBM(-0x37),
		DBM_TO_MBM(-0x38), DBM_TO_MBM(-0x39), DBM_TO_MBM(-0x3A), DBM_TO_MBM(-0x3B),
		DBM_TO_MBM(-0x3C), DBM_TO_MBM(-0x3D), DBM_TO_MBM(-0x3E), DBM_TO_MBM(-0x3F),
		DBM_TO_MBM(-0x40), DBM_TO_MBM(-0x41), DBM_TO_MBM(-0x42), DBM_TO_MBM(-0x43),
		DBM_TO_MBM(-0x44), DBM_TO_MBM(-0x45), DBM_TO_MBM(-0x46), DBM_TO_MBM(-0x47),
		DBM_TO_MBM(-0x48), DBM_TO_MBM(-0x49), DBM_TO_MBM(-0x4A), DBM_TO_MBM(-0x4B),
		DBM_TO_MBM(-0x4C), DBM_TO_MBM(-0x4D), DBM_TO_MBM(-0x4E), DBM_TO_MBM(-0x4F),
		DBM_TO_MBM(-0x50), };
*/
/*
	dev->phy->transmit_power = 0;
	dev->phy->cca = 0;
	dev->phy->cca_ed_level = 0;
	dev->phy->symbol_duration = 0;
	dev->phy->lifs_period = 0;
	dev->phy->sifs_period = 0;
*/



	dev->flags = IEEE802154_HW_OMIT_CKSUM | IEEE802154_HW_AFILT;

	dev->parent = tty->dev;

	xbdev->tty = tty_kref_get(tty);

//    cleanup(xbdev);

	tty->disc_data = xbdev;
//	tty->receive_room = MAX_DATA_SIZE;
	tty->receive_room = 65536;

//	dev->ml_priv = &xbee_ieee802154_mlme_ops;

	if (tty->ldisc->ops->flush_buffer)
		tty->ldisc->ops->flush_buffer(tty);
	tty_driver_flush_buffer(tty);

	err = ieee802154_register_hw(dev);
	if (err) {
        printk(KERN_ERR "%s: device register failed\n", __func__);
		goto err;
	}

	RUN_MODTEST(xbdev);

	return 0;

err:
	tty->disc_data = NULL;
	tty_kref_put(tty);
	xbdev->tty = NULL;

	ieee802154_unregister_hw(xbdev->dev);
	ieee802154_free_hw(xbdev->dev);

	return err;
}

/**
 * xbee_ldisc_close - Close line discipline and unregister with ieee802154.
 *
 * @tty: TTY info for line.
 */
static void xbee_ldisc_close(struct tty_struct *tty){

	struct xb_device *zbdev;
	pr_debug("%s\n", __func__);
	zbdev = tty->disc_data;
	if (NULL == zbdev) {
		printk(KERN_WARNING "%s: match is not found\n", __func__);
		return;
	}

	tty->disc_data = NULL;
	tty_kref_put(tty);
	zbdev->tty = NULL;

	ieee802154_unregister_hw(zbdev->dev);

	tty_ldisc_flush(tty);
	tty_driver_flush_buffer(tty);

	ieee802154_free_hw(zbdev->dev);

}

/**
 * xbee_ldisc_ioctl - ...
 *
 * @tty: TTY info for line.
 * @file: ...
 * @cmd: ...
 * @arg: ...
 */
static int xbee_ldisc_ioctl(struct tty_struct *tty, struct file *file,
			    unsigned int cmd, unsigned long arg)
{
	pr_debug("%s\n", __func__);
	// TODO
    return 0;
}

/**
 * xbee_ldisc_hangup - Hang up line discipline.
 *
 * @tty: TTY info for line.
 *
 * "The line discipline should cease I/O to the tty.
 * No further calls into the ldisc code will occur."
 */
static int xbee_ldisc_hangup(struct tty_struct *tty)
{
	pr_debug("%s\n", __func__);
	xbee_ldisc_close(tty);
    return 0;
}

/**
 * xbee_ldisc_recv_buf - Receive serial bytes.
 *
 * @tty: TTY info for line.
 * @cp: ...
 * @fp: ...
 * @count: ...
 *
 * Directly called from flush_to_ldisc() which is called from
 * tty_flip_buffer_push(), either in IRQ context if low latency tty or from
 * a normal worker thread otherwise.
 */
static int xbee_ldisc_receive_buf2(struct tty_struct *tty,
				const unsigned char *buf,
				char *cflags, int count)
{
	int ret = 0;
	struct xb_device *xbdev = NULL;

	//print_hex_dump_bytes("<<<< ", DUMP_PREFIX_NONE, buf, count);
	
	if (!tty->disc_data) {
		printk(KERN_ERR "%s(): record for tty is not found\n", __func__);
		return 0;
	}

	xbdev = tty->disc_data;

	ret = frame_put_received_data(xbdev->recv_buf, buf, count);

	if(ret == 0) return count;

	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret > 0) {
		ret = queue_work(xbdev->comm_workq, (struct work_struct*)xbdev);
	}
	return count;
}

/*********************************************************************/

/**
 * xbee_ldisc - TTY line discipline ops.
 */
static struct tty_ldisc_ops xbee_ldisc_ops = {
	.owner			= THIS_MODULE,
	.magic			= TTY_LDISC_MAGIC,
 	.name			= "n_ieee802154_xbee",
	.num			= 0,
	.flags			= 0,
	.open			= xbee_ldisc_open,
	.close			= xbee_ldisc_close,
	.flush_buffer	= NULL,
	.read			= NULL,
	.write			= NULL,
	.ioctl			= xbee_ldisc_ioctl,
	.compat_ioctl	= NULL,
	.set_termios	= NULL,
	.poll			= NULL,
 	.hangup			= xbee_ldisc_hangup,
	.receive_buf	= NULL,
	.write_wakeup	= NULL,
	.dcd_change		= NULL,
	.receive_buf2	= xbee_ldisc_receive_buf2,
};

static int __init xbee_init(void)
{
	pr_debug("%s\n", __func__);
	printk(KERN_INFO "Initializing ZigBee TTY interface\n");

	if (tty_register_ldisc(N_IEEE802154_XBEE, &xbee_ldisc_ops) != 0) {
		printk(KERN_ERR "%s: line discipline register failed\n",
				__func__);
		return -EINVAL;
	}

	return 0;
}

static void __exit xbee_exit(void)
{
	pr_debug("%s\n", __func__);
	if (tty_unregister_ldisc(N_IEEE802154_XBEE) != 0) {
		printk(KERN_CRIT "failed to unregister ZigBee line discipline.\n");
	}
}

#include "xbee2_test.c"
DECL_TESTS_ARRAY();

module_init(xbee_init);
module_exit(xbee_exit);

MODULE_DESCRIPTION("Digi XBee IEEE 802.15.4 serial driver");
MODULE_ALIAS_LDISC(N_IEEE802154_XBEE);
MODULE_LICENSE("GPL");

