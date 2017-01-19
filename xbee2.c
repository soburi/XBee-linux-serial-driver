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
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <net/mac802154.h>
#include <net/cfg802154.h>
#include <net/regulatory.h>
#include <net/ieee802154_netdev.h>

#ifdef MODTEST_ENABLE
#include "modtest.h"
#endif

#define N_IEEE802154_XBEE 25

/*********************************************************************/

struct xb_device;
struct xb_work {
	struct work_struct work;
	struct xb_device* xb;
};

struct xb_device {
	struct ieee802154_hw hw;
	struct tty_struct *tty;

	struct completion cmd_resp_done;
	uint8_t wait_frameid;

	struct workqueue_struct    *comm_workq;

	struct sk_buff_head recv_queue;
	struct sk_buff_head send_queue;
	struct sk_buff* recv_buf;

	uint8_t frameid;
	unsigned short firmware_version;
	struct xb_work comm_work;

	struct wpan_phy* phy;

          //const struct ieee802154_ops *ops;

#ifdef MODTEST_ENABLE
	DECL_MODTEST_STRUCT();
#endif
};

struct xbee_sub_if_data {
	struct list_head list; /* the ieee802154_priv->slaves list */

	struct wpan_dev wpan_dev;

	struct xb_device* local;
	struct net_device *dev;

	unsigned long state;
	char name[IFNAMSIZ];

	/* protects sec from concurrent access by netlink. access by
	* encrypt/decrypt/header_create safe without additional protection.
	*/
	struct mutex sec_mtx;

	//struct mac802154_llsec sec;
};

static void mac802154_wpan_free(struct net_device *dev)
{
	struct xbee_sub_if_data *sdata = NULL;//IEEE802154_DEV_TO_SUB_IF(dev);

	//mac802154_llsec_destroy(&sdata->sec);

	free_netdev(dev);
}

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

struct xb_frame_header {
	uint8_t start_delimiter; // 0x7e
	uint16_t length;
	uint8_t type;
} __attribute__((aligned(1), packed));

struct xb_frame_header_id {
	uint8_t start_delimiter; // 0x7e
	uint16_t length;
	uint8_t type;
	uint8_t id;
} __attribute__((aligned(1), packed));

struct xb_frame_atcmd {
	struct xb_frame_header hd;
	uint8_t id;
	uint16_t command;
} __attribute__((aligned(1), packed));

struct xb_frame_atresp {
	struct xb_frame_header hd;
	uint8_t id;
	uint16_t command;
	uint8_t status;
} __attribute__((aligned(1), packed));

struct xb_frame_tx64 {
	struct xb_frame_header hd;
	uint8_t id;
	uint64_t destaddr;
	uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_tx16 {
	struct xb_frame_header hd;
	uint8_t id;
	uint16_t destaddr;
	uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_rx64 {
	struct xb_frame_header hd;
	uint64_t srcaddr;
	uint8_t rssi;
	uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_rx16 {
	struct xb_frame_header hd;
	uint16_t srcaddr;
	uint8_t rssi;
	uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_txstat {
	struct xb_frame_header hd;
	uint8_t id;
	uint8_t options;
} __attribute__((aligned(1), packed));

struct xb_frame_mstat {
	struct xb_frame_header hd;
	uint8_t status;
} __attribute__((aligned(1), packed));

struct xb_frame_rcmd {
	struct xb_frame_header hd;
	uint8_t id;
	uint64_t destaddr64;
	uint16_t destaddr16;
	uint16_t command;
} __attribute__((aligned(1), packed));

struct xb_frame_rcmdr {
	struct xb_frame_header hd;
	uint8_t id;
	uint64_t destaddr64;
	uint16_t destaddr16;
	uint16_t command;
	uint8_t status;
} __attribute__((aligned(1), packed));

/* API frame types */
enum {
	XBEE_FRM_TX64	= 0x00,
	XBEE_FRM_TX16	= 0x01,
	XBEE_FRM_ATCMD	= 0x08,
	XBEE_FRM_ATCMDQ	= 0x09,
	XBEE_FRM_RCMD	= 0x17,
	XBEE_FRM_RX64	= 0x80,
	XBEE_FRM_RX16	= 0x81,
	XBEE_FRM_RX64IO	= 0x82,
	XBEE_FRM_RX16IO	= 0x83,
	XBEE_FRM_ATCMDR	= 0x88,
	XBEE_FRM_TXSTAT	= 0x89,
	XBEE_FRM_MSTAT	= 0x8A,
	XBEE_FRM_RCMDR	= 0x97,
};

#define AT_DECL(x, y) ( x << 8 | y )

enum {
	XBEE_AT_CA = AT_DECL('C','A'),
	XBEE_AT_CH = AT_DECL('C','H'),
	XBEE_AT_ID = AT_DECL('I','D'),
	XBEE_AT_MY = AT_DECL('M','Y'),
	XBEE_AT_PL = AT_DECL('P','L'),
	XBEE_AT_RN = AT_DECL('R','N'),
	XBEE_AT_RR = AT_DECL('R','R'),
	XBEE_AT_VR = AT_DECL('V','R'),
};

enum {
	XBEE_DELIMITER = 0x7E,
	XBEE_ESCAPED_DELIMITER = 0x5E ,
	XBEE_ESCAPE = 0x7D ,
	XBEE_ESCMASK = 0x20 ,
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
/*
static int buffer_find_delimiter_unescaped(const unsigned char* buf, const size_t len)
{
	int i=0;
	for(i=0; i<len; i++) {
		if(buf[i] == XBEE_DELIMITER) return i;
	}
	return -1;
}
*/
static int buffer_find_delimiter_escaped(const unsigned char* buf, const size_t len)
{
	int i=0;
	bool esc = false;
	for(i=0; i<len; i++) {
		if(buf[i] == XBEE_ESCAPE) {
			esc = true; continue;
		}
		else if(buf[i] == XBEE_ESCAPED_DELIMITER && esc) {
			return i-1;
		}
		else if(buf[i] == XBEE_DELIMITER && !esc) {
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
		if(buf[i] == XBEE_ESCAPE) {
			esc = true;
			escape_count++;
			continue;
		}
		if(esc) buf[i-escape_count] = (buf[i] ^ XBEE_ESCMASK);
		else    buf[i-escape_count] =  buf[i];
		esc = false;
	}
	if(esc) {
		buf[i-escape_count] = XBEE_ESCAPE;
		escape_count--;
	}

	return len-escape_count;
}

static struct sk_buff* frame_new(size_t paylen, uint8_t type)
{
	struct sk_buff* new_skb = NULL;
	struct xb_frame_header* frm = NULL;
	unsigned char* tail = NULL;

	new_skb = dev_alloc_skb(paylen+5); //delimiter, length, checksum
	tail = skb_put(new_skb, paylen+5);

	frm = (struct xb_frame_header*)tail;
	frm->start_delimiter  = XBEE_DELIMITER;
	frm->length = htons(paylen+1);
	frm->type = type;
	return new_skb;
}

static const unsigned char frame_payload_length(struct sk_buff* frame)
{
	struct xb_frame_header* frm = (struct xb_frame_header*)frame->data;
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
	struct xb_frame_header* header = NULL;

	if(recv_buf->len < 1) return -EAGAIN;
	header = (struct xb_frame_header*)recv_buf->data;

	if(recv_buf->data[0] != XBEE_DELIMITER) return -EINVAL;

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

static struct sk_buff* frame_dequeue_by_id(struct sk_buff_head *recv_queue, uint8_t frameid)
{
	struct sk_buff* skb = NULL;
	skb = skb_peek(recv_queue);

	if(!skb) return NULL;

	skb_queue_walk(recv_queue, skb) {
		struct xb_frame_header_id* hd = (struct xb_frame_header_id*)skb->data;
		if( hd->type != XBEE_FRM_RX64 &&
			hd->type != XBEE_FRM_RX16 &&
			hd->type != XBEE_FRM_RX64IO &&
			hd->type != XBEE_FRM_RX16IO &&
			hd->type != XBEE_FRM_MSTAT) {

			if( hd->id == frameid) {
				skb_unlink(skb, recv_queue);
				return skb;
			}
		}
	}

	return NULL;
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

		newframe = dev_alloc_skb(128);

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
	struct xb_frame_atcmd* atfrm = NULL;

	unsigned char checksum = 0;
	int datalen = 0;

	newskb = frame_new(buflen+3, XBEE_FRM_ATCMD);
	atfrm = (struct xb_frame_atcmd*)newskb->data;

	atfrm->id = id;
	atfrm->command = htons(atcmd);

	datalen = htons(atfrm->hd.length);

	memmove(newskb->data + sizeof(struct xb_frame_atcmd), buf, buflen);

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

	already_on_queue = queue_work(xb->comm_workq, (struct work_struct*)&xb->comm_work.work);

	return already_on_queue;
}

static bool xb_process_sendrecv(struct xb_device* xb)
{
	int ret = 0;

	xb_process_send(xb);
	ret = wait_for_completion_interruptible_timeout(&xb->cmd_resp_done, 1000);

	if(ret > 0) {
		//pr_debug("complete %d\n", ret);
	}
	else if(ret == -ERESTARTSYS) {
		pr_debug("interrupted %d\n", ret);
	}
	else {
		pr_debug("timeout %d\n", ret);
	}

	return ret;
}

static void frame_recv_rx64(struct xb_device *xbdev, struct sk_buff *skb)
{
	struct xb_frame_rx64* rx64 = (struct xb_frame_rx64*)skb->data;
	pr_debug("RX64: addr=%016llx rssi=%d options=%x\n", rx64->srcaddr, rx64->rssi, rx64->options);
//	ieee802154_rx_irqsafe(xbdev->dev, lskb, skb->len);
//	ieee802154_rx(xbdev->dev, skb, rssi);
}

static void frame_recv_rx16(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_rx16* rx16 = (struct xb_frame_rx16*)skb->data;
	pr_debug("RX16: addr=%04x rssi=%d options=%x\n", rx16->srcaddr, rx16->rssi, rx16->options);
//	ieee802154_rx_irqsafe(xbdev->dev, lskb, skb->len);
//	ieee802154_rx(xbdev->dev, skb, rssi);
}

static void frame_recv_atcmdr(struct xb_device *xbdev, struct sk_buff *skb)
{
	// AT command response must handle call side.
	struct xb_frame_atresp* atresp = (struct xb_frame_atresp*)skb->data;
	pr_debug("AT_R: id=0x%02x cmd=%c%c status=%d\n", atresp->id, atresp->command&0xFF, (atresp->command & 0xFF00)>>8 , atresp->status);
}

static void frame_recv_mstat(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_mstat* mstat = (struct xb_frame_mstat*)skb->data;
	pr_debug("MSTA: status=%d\n", mstat->status);
}

static void frame_recv_txstat(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_txstat* txstat = (struct xb_frame_txstat*)skb->data;
	pr_debug("TXST: id->0x%02x options=%x\n", txstat->id, txstat->options);
}

static void frame_recv_rx64io(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_rx64* rx64 = (struct xb_frame_rx64*)skb->data;
	pr_debug("UNEXPECTED RX64IO: addr=%016llx rssi=%d options=%x\n", rx64->srcaddr, rx64->rssi, rx64->options);
}

static void frame_recv_rx16io(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_rx16* rx16 = (struct xb_frame_rx16*)skb->data;
	pr_debug("UNEXPECTED RX16IO: addr=%04x rssi=%d options=%x\n", rx16->srcaddr, rx16->rssi, rx16->options);
}

static void frame_recv_atcmd(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_atcmd* atcmd = (struct xb_frame_atcmd*)skb->data;
	pr_debug("UNEXPECTED ATCMD: id=0x%02x cmd=%c%c\n", atcmd->id, atcmd->command&0xFF, (atcmd->command & 0xFF00)>>8);
}

static void frame_recv_atcmdq(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_atcmd* atcmd = (struct xb_frame_atcmd*)skb->data;
	pr_debug("UNEXPECTED ATCMDQ: id=0x%02x cmd=%c%c\n", atcmd->id, atcmd->command&0xFF, (atcmd->command & 0xFF00)>>8);
}

static void frame_recv_rcmd(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_rcmd* ratcmd = (struct xb_frame_rcmd*)skb->data;
	pr_debug("UNEXPECTED RATCMD: id=0x%02x addr64=%016llx addr16=%04x cmd=%c%c\n", ratcmd->id, ratcmd->destaddr64, ratcmd->destaddr16, ratcmd->command&0xFF, (ratcmd->command & 0xFF00)>>8);
}

static void frame_recv_rcmdr(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_rcmdr* ratcmdr = (struct xb_frame_rcmdr*)skb->data;
	pr_debug("UNEXPECTED RATCMDR: id=0x%02x addr64=%016llx addr16=%04x cmd=%c%c status=%d\n", ratcmdr->id, ratcmdr->destaddr64, ratcmdr->destaddr16, ratcmdr->command&0xFF, (ratcmdr->command & 0xFF00)>>8, ratcmdr->status);
}

static void frame_recv_tx64(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_tx64* tx64 = (struct xb_frame_tx64*)skb->data;
	pr_debug("UNEXPECTED TX64: id=0x%02x addr=%llx options=%x\n", tx64->id, tx64->destaddr, tx64->options);
}
static void frame_recv_tx16(struct xb_device* xbdev, struct sk_buff *skb)
{
	struct xb_frame_tx16* tx16 = (struct xb_frame_tx16*)skb->data;
	pr_debug("UNEXPECTED TX16: id=0x%02x addr=%04x options=%x\n", tx16->id, tx16->destaddr, tx16->options);
}
static void frame_recv_default(struct xb_device* xbdev, struct sk_buff *skb) { pr_debug("%s\n", __func__); }

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
	struct xb_frame_header* frm = (struct xb_frame_header*)skb->data;

	switch (frm->type) {
	case XBEE_FRM_MSTAT:	frame_recv_mstat(xbdev, skb);	break;
	case XBEE_FRM_ATCMDR:	frame_recv_atcmdr(xbdev, skb);	break;
	case XBEE_FRM_RCMDR:	frame_recv_rcmdr(xbdev, skb);	break;
	case XBEE_FRM_RX64:		frame_recv_rx64(xbdev, skb);	break;
	case XBEE_FRM_RX16:		frame_recv_rx16(xbdev, skb);	break;
	case XBEE_FRM_RX64IO:   frame_recv_rx64io(xbdev, skb);	break;
	case XBEE_FRM_RX16IO:   frame_recv_rx16io(xbdev, skb);	break;
	case XBEE_FRM_ATCMD:	frame_recv_atcmd(xbdev, skb);	break;
	case XBEE_FRM_ATCMDQ:	frame_recv_atcmdq(xbdev, skb);	break;
	case XBEE_FRM_RCMD:		frame_recv_rcmd(xbdev, skb);	break;
	case XBEE_FRM_TX64:		frame_recv_tx64(xbdev, skb);	break;
	case XBEE_FRM_TX16:		frame_recv_tx16(xbdev, skb);	break;
	case XBEE_FRM_TXSTAT:	frame_recv_txstat(xbdev, skb);	break;
	default:				frame_recv_default(xbdev, skb);	break;
	}
}

static void comm_work_fn(struct work_struct *param)
{
	struct xb_work* xbw = (struct xb_work*)param;
	struct xb_device* xb = xbw->xb;
	struct tty_struct* tty = xb->tty;

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
			kfree_skb(skb);
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
static int xbee_ieee802154_set_channel(struct ieee802154_hw *hw,
				       u8 page, u8 channel)
{
	struct xb_device *xb = hw->priv;

	pr_debug("%s\n", __func__);

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
static int xbee_ieee802154_ed(struct ieee802154_hw *hw, u8 *level)
{
	struct xb_device *xb = hw->priv;

	pr_debug("%s\n", __func__);

	xb_enqueue_send_at(xb, 0x4544, NULL, 0);

    return 0;
}

static int xbee_ieee802154_set_csma_params(struct ieee802154_hw *hw, u8 min_be, u8 max_be, u8 retries)
{
	struct xb_device *xb = hw->priv;

	pr_debug("%s\n", __func__);

	xb_enqueue_send_at(xb, XBEE_AT_RN, &min_be, 1);
	xb_process_sendrecv(xb);
	xb_enqueue_send_at(xb, XBEE_AT_RR, &retries, 1);
	xb_process_sendrecv(xb);

	return 0;
}

/**
 * xbee_ieee802154_set_frame_retries - Handler that 802.15.4 module calls to set frame retries.
 *
 * @dev: ...
 * @level: ...
 */
static int xbee_ieee802154_set_frame_retries(struct ieee802154_hw *hw, s8 retries)
{
	struct xb_device *xb = NULL;

	pr_debug("%s\n", __func__);

	xb = hw->priv;
	//xb_enqueue_send_at(xb, XBEE_AT_RR, &u_retries, 1);

    return 0;
}

static int xbee_ieee802154_set_txpower(struct ieee802154_hw *hw, s32 dbm)
{
	struct xb_device *xb = hw->priv;
	u8 pl;

	pr_debug("%s mbm=%d\n", __func__, dbm);

	if(dbm >= 1000) {
		pl=0;
	} else if(dbm >= 600) {
		pl=1;
	} else if(dbm >= 400) {
		pl=2;
	} else if(dbm >= 200) {
		pl=3;
	} else {
		pl=4;
	}

	xb_enqueue_send_at(xb, XBEE_AT_PL, &pl, 1);

	return 0;
}

static int xbee_ieee802154_set_cca_mode(struct ieee802154_hw *hw, const struct wpan_phy_cca *cca)
{
	pr_debug("%s cca=%p\n", __func__, cca);

#if 0
	switch(cca->mode) {
	case NL802154_CCA_ENERGY:
	case NL802154_CCA_CARRIER:
	case NL802154_CCA_ENERGY_CARRIER:
	case NL802154_CCA_ALOHA:
	case NL802154_CCA_UWB_SHR:
	case NL802154_CCA_UWB_MULTIPLEXED:
	default:
	}

	switch(cca->opts) {
	case NL802154_CCA_OPT_ENERGY_CARRIER_AND:
	case NL802154_CCA_OPT_ENERGY_CARRIER_OR:
	default:
	}
#endif
	return 0;
}

static int xbee_ieee802154_set_cca_ed_level(struct ieee802154_hw *hw, s32 dbm)
{
	struct xb_device *xb = hw->priv;
	u8 ca;

	pr_debug("%s dbm=%d ca=%d\n", __func__, dbm, -dbm/100);

	ca = -dbm/100;

	xb_enqueue_send_at(xb, XBEE_AT_CA, &ca, 1);
	return 0;
}

/**
 * xbee_ieee802154_xmit - Handler that 802.15.4 module calls for each transmitted frame.
 *
 * @dev: ...
 * @skb: ...
 */
static int xbee_ieee802154_xmit(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
	print_hex_dump_bytes(" TX> ", DUMP_PREFIX_NONE, skb->data, skb->len);
    return 0;
}

static int xbee_ieee802154_filter(struct ieee802154_hw *hw,
					  struct ieee802154_hw_addr_filt *filt,
					    unsigned long changed)
{
	struct xb_device *xb = hw->priv;
	pr_debug("%s filt.pan_id=%0x filt.short=%0x filt.ieee=%0llx filt.pan_coord=%x changed=%lx\n", __func__, filt->pan_id, filt->short_addr, filt->ieee_addr, filt->pan_coord, changed);

	if(changed & IEEE802154_AFILT_SADDR_CHANGED) {
		unsigned short saddr = htons(filt->short_addr);
		xb_enqueue_send_at(xb, XBEE_AT_MY, (unsigned char*)&saddr, 2);
	} else if(IEEE802154_AFILT_IEEEADDR_CHANGED) {
		return -1; // 64bit address is readonly.
	} else if(IEEE802154_AFILT_PANID_CHANGED) {
		unsigned short panid = htons(filt->pan_id);
		xb_enqueue_send_at(xb, XBEE_AT_ID, (unsigned char*)&panid, 2);
	} else if(IEEE802154_AFILT_PANC_CHANGED) {
		//filt->pan_coord;
	}

    return 0;
}

/**
 * xbee_ieee802154_start - For device initialisation before the first interface is attached.
 *
 * @dev: ...
 */
static int xbee_ieee802154_start(struct ieee802154_hw *hw)
{
	struct xb_device *xbdev = hw->priv;
	int ret = 0;

	pr_debug("%s\n", __func__);

	if (NULL == xbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __func__);
		return -EINVAL;
	}

	return ret;
}

/**
 * xbee_ieee802154_stop - For device cleanup after last interface is removed.
 *
 * @dev: ...
 */
static void xbee_ieee802154_stop(struct ieee802154_hw *hw){
	struct xb_device *xbdev = hw->priv;
	pr_debug("%s\n", __func__);

	if (NULL == xbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __func__);
		return;
	}

	pr_debug("%s end\n", __func__);
}

static int xbee_mlme_assoc_req(struct net_device *dev, struct ieee802154_addr *addr, u8 channel, u8 page, u8 cap)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_mlme_assoc_resp(struct net_device *dev, struct ieee802154_addr *addr, __le16 short_addr, u8 status)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_mlme_disassoc_req(struct net_device *dev, struct ieee802154_addr *addr, u8 reason)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_mlme_start_req(struct net_device *dev, struct ieee802154_addr *addr, u8 channel, u8 page, u8 bcn_ord, u8 sf_ord, u8 pan_coord, u8 blx, u8 coord_realign)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_mlme_scan_req(struct net_device *dev, u8 type, u32 channels, u8 page, u8 duration)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_mlme_set_mac_params(struct net_device *dev, const struct ieee802154_mac_params *params)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static void xbee_mlme_get_mac_params(struct net_device *dev, struct ieee802154_mac_params *params)
{
	pr_debug("%s\n", __func__);
	return;
}

static int mac802154_header_create(struct sk_buff *skb,
				   struct net_device *dev,
				   unsigned short type,
				   const void *daddr,
				   const void *saddr,
				   unsigned len)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static int
mac802154_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	pr_debug("%s\n", __func__);
	return 0;
}


static int xbee_ndo_open(struct net_device *dev)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static int xbee_ndo_stop(struct net_device *dev)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static int
xbee_ndo_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static int xbee_ndo_set_mac_address(struct net_device *dev, void *p)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static int ieee802154_header_create(struct sk_buff *skb,
				    struct net_device *dev,
				    const struct ieee802154_addr *daddr,
				    const struct ieee802154_addr *saddr,
				    unsigned len)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static int mac802154_mlme_start_req(struct net_device *dev,
                                    struct ieee802154_addr *addr,
                                    u8 channel, u8 page,
                                    u8 bcn_ord, u8 sf_ord,
                                    u8 pan_coord, u8 blx,
                                    u8 coord_realign)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static int mac802154_set_mac_params(struct net_device *dev,
                                    const struct ieee802154_mac_params *params)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static void mac802154_get_mac_params(struct net_device *dev,
                                     struct ieee802154_mac_params *params)
{
	pr_debug("%s\n", __func__);
}

/**
 * xbee_ieee802154_ops - ieee802154 MCPS ops.
 *
 * This is part of linux-wsn. It is similar to netdev_ops.
 */
static struct ieee802154_ops xbee_ieee802154_ops = {
	.owner				= THIS_MODULE,
	.start				= xbee_ieee802154_start,
	.stop				= xbee_ieee802154_stop,
	.xmit_sync			= NULL,
	.xmit_async			= xbee_ieee802154_xmit,
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

static struct ieee802154_mlme_ops xbee_ieee802154_mlme_ops = {
	.assoc_req = xbee_mlme_assoc_req,
	.assoc_resp = xbee_mlme_assoc_resp,
	.disassoc_req = xbee_mlme_disassoc_req,
	.start_req = xbee_mlme_start_req,
	.scan_req = xbee_mlme_scan_req,
	.set_mac_params = xbee_mlme_set_mac_params,
	.get_mac_params = xbee_mlme_get_mac_params,
	.llsec = NULL,
};

static const struct wpan_dev_header_ops xbee_ieee802154_header_ops = {
	.create		= ieee802154_header_create,
};


static const struct header_ops xbee_mac802154_header_ops = {
	.create         = mac802154_header_create,
	.parse          = mac802154_header_parse,
};

static const struct net_device_ops xbee_mac802154_wpan_ops = {
        .ndo_open               = xbee_ndo_open,
        .ndo_stop               = xbee_ndo_stop,
//        .ndo_start_xmit         = ieee802154_subif_start_xmit,
        .ndo_do_ioctl           = xbee_ndo_do_ioctl,
        .ndo_set_mac_address    = xbee_ndo_set_mac_address,
};
/*
static const struct net_device_ops mac802154_monitor_ops = {
        .ndo_open               = mac802154_wpan_open,
        .ndo_stop               = mac802154_slave_close,
        .ndo_start_xmit         = ieee802154_monitor_start_xmit,
};
*/


struct ieee802154_mlme_ops mac802154_mlme_wpan = {
	.start_req = mac802154_mlme_start_req,
	
	//.llsec = &mac802154_llsec_ops,
	.set_mac_params = mac802154_set_mac_params,
	.get_mac_params = mac802154_get_mac_params,
};


/*
 * See Documentation/tty.txt for details.
 */


static void setup_dev(struct ieee802154_hw *hw)
{
	hw->extra_tx_headroom = 0;
	/* only 2.4 GHz band */
	hw->phy->flags = WPAN_PHY_FLAG_TXPOWER |
			          WPAN_PHY_FLAG_CCA_ED_LEVEL |
					  WPAN_PHY_FLAG_CCA_MODE;
	hw->phy->current_channel = 11;
	hw->phy->current_page = 0;
	hw->phy->supported.channels[0] = 0x7fff800;
	hw->phy->supported.cca_modes = BIT(NL802154_CCA_ENERGY);
	hw->phy->supported.cca_opts = NL802154_CCA_ENERGY;
	hw->phy->supported.iftypes = 0;
	hw->phy->supported.lbt = 0;
	hw->phy->supported.min_minbe = 0;
	hw->phy->supported.max_minbe = 3;
	hw->phy->supported.min_maxbe = 5; /* N/A */
	hw->phy->supported.max_maxbe = 5; /* N/A */
	hw->phy->supported.min_csma_backoffs = 0; /* N/A */
	hw->phy->supported.max_csma_backoffs = 0; /* N/A */
	hw->phy->supported.min_frame_retries = 0;
	hw->phy->supported.max_frame_retries = 0;
	hw->phy->supported.tx_powers_size = 0;

	hw->phy->supported.cca_ed_levels_size = 41;

	{
	static const s32 ed_levels [] = {
		-3600, -3700, -3800, -3900, -4000,
		-4100, -4200, -4300, -4400, -4500, -4600, -4700, -4800, -4900, -5000,
		-5100, -5200, -5300, -5400, -5500, -5600, -5700, -5800, -5900, -6000,
		-6100, -6200, -6300, -6400, -6500, -6600, -6700, -6800, -6900, -8000,
	};
	hw->phy->supported.cca_ed_levels = ed_levels;
	hw->phy->supported.cca_ed_levels_size = sizeof(ed_levels)/sizeof(ed_levels[0]);
	}

	{
	static const s32 tx_powers[] = {
		1000, 600, 400, 200, 0
	};
	hw->phy->supported.tx_powers = tx_powers;
	hw->phy->supported.tx_powers_size = sizeof(tx_powers)/sizeof(tx_powers[0]);
	}

/*
	hw->phy->transmit_power = 0;
	hw->phy->cca = 0;
	hw->phy->cca_ed_level = 0;
	hw->phy->symbol_duration = 0;
	hw->phy->lifs_period = 0;
	hw->phy->sifs_period = 0;
*/

	hw->flags = IEEE802154_HW_OMIT_CKSUM | IEEE802154_HW_AFILT;

}

const struct cfg802154_ops mac802154_config_ops = {
        .add_virtual_intf_deprecated = NULL,//ieee802154_add_iface_deprecated,
        .del_virtual_intf_deprecated = NULL,//ieee802154_del_iface_deprecated,
        .suspend = NULL,//ieee802154_suspend,
        .resume = NULL,//ieee802154_resume,
        .add_virtual_intf = NULL,//ieee802154_add_iface,
        .del_virtual_intf = NULL,//ieee802154_del_iface,
        .set_channel = NULL,//ieee802154_set_channel,
        .set_cca_mode = NULL,//ieee802154_set_cca_mode,
        .set_cca_ed_level = NULL,//ieee802154_set_cca_ed_level,
        .set_tx_power = NULL,//ieee802154_set_tx_power,
        .set_pan_id = NULL,//ieee802154_set_pan_id,
        .set_short_addr = NULL,//ieee802154_set_short_addr,
        .set_backoff_exponent = NULL,//ieee802154_set_backoff_exponent,
        .set_max_csma_backoffs = NULL,//ieee802154_set_max_csma_backoffs,
        .set_max_frame_retries = NULL,//ieee802154_set_max_frame_retries,
        .set_lbt_mode = NULL,//ieee802154_set_lbt_mode,
        .set_ackreq_default = NULL,//ieee802154_set_ackreq_default,
#ifdef CONFIG_IEEE802154_NL802154_EXPERIMENTAL
        .get_llsec_table = NULL,//ieee802154_get_llsec_table,
        .lock_llsec_table = NULL,//ieee802154_lock_llsec_table,
        .unlock_llsec_table = NULL,//ieee802154_unlock_llsec_table,
        /* TODO above */
        .set_llsec_params = NULL,//ieee802154_set_llsec_params,
        .get_llsec_params = NULL,//ieee802154_get_llsec_params,
        .add_llsec_key = NULL,//ieee802154_add_llsec_key,
        .del_llsec_key = NULL,//ieee802154_del_llsec_key,
        .add_seclevel = NULL,//ieee802154_add_seclevel,
        .del_seclevel = NULL,//ieee802154_del_seclevel,
        .add_device = NULL,//ieee802154_add_device,
        .del_device = NULL,//ieee802154_del_device,
        .add_devkey = NULL,//ieee802154_add_devkey,
        .del_devkey = NULL,//ieee802154_del_devkey,
#endif /* CONFIG_IEEE802154_NL802154_EXPERIMENTAL */
};

static void ieee802154_if_setup(struct net_device *dev);

static int if_add( struct xb_device* local );

struct ieee802154_hw *
xbee_alloc_hw(size_t priv_data_len)//, const struct ieee802154_ops *ops)
{
	struct xb_device* local;
	struct wpan_phy *phy;
	size_t priv_size;
	int ret;

	priv_size = ALIGN(sizeof(*local), NETDEV_ALIGN) + priv_data_len;

	pr_debug("wpan_phy_new\n");
	phy = wpan_phy_new(&mac802154_config_ops, priv_size);
	if (!phy) {
		pr_err("failure to allocate master IEEE802.15.4 device\n");
		return NULL;
	}

	//phy->privid = mac802154_wpan_phy_privid;

	pr_debug("wpan_phy_priv\n");
	local = wpan_phy_priv(phy);
	local->phy = phy;
	local->hw.phy = local->phy;
	local->hw.priv = (char *)local + ALIGN(sizeof(*local), NETDEV_ALIGN);
	//local->ops = ops;

	phy->supported.max_minbe = 8;
	phy->supported.min_maxbe = 3;
	phy->supported.max_maxbe = 8;
	phy->supported.min_frame_retries = 0;
	phy->supported.max_frame_retries = 7;
	phy->supported.max_csma_backoffs = 5;
	phy->supported.lbt = NL802154_SUPPORTED_BOOL_FALSE;

	/* always supported */
	phy->supported.iftypes = BIT(NL802154_IFTYPE_NODE);

	pr_debug("wpan_phy_set_dev\n");
	//wpan_phy_set_dev(local->phy, local->hw.parent);

	local->phy->lifs_period = IEEE802154_LIFS_PERIOD *
				local->phy->symbol_duration;
	local->phy->sifs_period = IEEE802154_SIFS_PERIOD *
				local->phy->symbol_duration;

	//ieee802154_setup_wpan_phy_pib(local->phy); set value only

	ret = wpan_phy_register(local->phy);

	rtnl_lock();

	if_add(local);

	rtnl_unlock();

}


/*****************************************************************************
 * Line discipline interface for IEEE 802.15.4 serial device
 *****************************************************************************/

static int if_add( struct xb_device* local ) {
	struct net_device *ndev = NULL;
	struct xbee_sub_if_data *sdata = NULL;
	int ret = -ENOMEM;
	__le64 extended_addr = cpu_to_le64(0x0000000000000000ULL);
	enum nl802154_iftype type;
	u8 tmp;
	struct wpan_dev *wpan_dev = NULL;//&sdata->wpan_dev;

	ASSERT_RTNL();

	pr_debug("alloc_netdev\n");
	ndev = alloc_netdev(sizeof(*sdata), "wpan%d",
			    NET_NAME_ENUM, ieee802154_if_setup);
	if (!ndev)
		return -ENOMEM;

	ndev->needed_headroom = local->hw.extra_tx_headroom +
				IEEE802154_MAX_HEADER_LEN;

	pr_debug("dev_alloc_name\n");
	ret = dev_alloc_name(ndev, ndev->name);
//	if (ret < 0)
//		goto err;

	ieee802154_le64_to_be64(ndev->perm_addr,
				&local->hw.phy->perm_extended_addr);
//	switch (type) {
//	case NL802154_IFTYPE_NODE:
		ndev->type = ARPHRD_IEEE802154;
		if (ieee802154_is_valid_extended_unicast_addr(extended_addr))
			ieee802154_le64_to_be64(ndev->dev_addr, &extended_addr);
		else
			memcpy(ndev->dev_addr, ndev->perm_addr,
			       IEEE802154_EXTENDED_ADDR_LEN);
//		break;
//	case NL802154_IFTYPE_MONITOR:
//		ndev->type = ARPHRD_IEEE802154_MONITOR;
//		break;
//	default:
//		ret = -EINVAL;
//		goto err;
//	}

	pr_debug("SET_NETDEV_DEV\n");
	/* TODO check this */
	SET_NETDEV_DEV(ndev, &local->phy->dev);
	pr_debug("netdev_priv\n");
	sdata = netdev_priv(ndev);
	ndev->ieee802154_ptr = &sdata->wpan_dev;
	pr_debug("memcpy\n");
	memcpy(sdata->name, ndev->name, IFNAMSIZ);
	sdata->dev = ndev;
	sdata->wpan_dev.wpan_phy = local->hw.phy;
	sdata->local = local;

	wpan_dev = &sdata->wpan_dev;
//	int ret;

	/* set some type-dependent values */
	sdata->wpan_dev.iftype = type;

	pr_debug("get_random_bytes\n");
	get_random_bytes(&tmp, sizeof(tmp));
	atomic_set(&wpan_dev->bsn, tmp);
	get_random_bytes(&tmp, sizeof(tmp));
	atomic_set(&wpan_dev->dsn, tmp);

	/* defaults per 802.15.4-2011 */
	wpan_dev->min_be = 3;
	wpan_dev->max_be = 5;
	wpan_dev->csma_retries = 4;
	wpan_dev->frame_retries = 3;

	wpan_dev->pan_id = cpu_to_le16(IEEE802154_PANID_BROADCAST);
	wpan_dev->short_addr = cpu_to_le16(IEEE802154_ADDR_BROADCAST);

//	switch (type) {
//	case NL802154_IFTYPE_NODE:
		ieee802154_be64_to_le64(&wpan_dev->extended_addr,
					sdata->dev->dev_addr);

		sdata->dev->header_ops = &xbee_mac802154_header_ops;
		sdata->dev->destructor = mac802154_wpan_free;
		sdata->dev->netdev_ops = &xbee_mac802154_wpan_ops;
		sdata->dev->ml_priv = &xbee_ieee802154_mlme_ops;
		wpan_dev->promiscuous_mode = false;
		wpan_dev->header_ops = &xbee_ieee802154_header_ops;

//		mutex_init(&sdata->sec_mtx);

		//mac802154_llsec_init(&sdata->sec);
		//ret = mac802154_wpan_update_llsec(sdata->dev);
//		if (ret < 0)
//			return ret;

//		break;
//	case NL802154_IFTYPE_MONITOR:
//		sdata->dev->destructor = free_netdev;
		//sdata->dev->netdev_ops = &mac802154_monitor_ops;
//		wpan_dev->promiscuous_mode = true;
//		break;
//	default:
//		BUG();
//	}

	return 0;
}



static void ieee802154_if_setup(struct net_device *dev)
{
	dev->addr_len		= IEEE802154_EXTENDED_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_EXTENDED_ADDR_LEN);

	/* Let hard_header_len set to IEEE802154_MIN_HEADER_LEN. AF_PACKET
	 * will not send frames without any payload, but ack frames
	 * has no payload, so substract one that we can send a 3 bytes
	 * frame. The xmit callback assumes at least a hard header where two
	 * bytes fc and sequence field are set.
	 */
	dev->hard_header_len	= IEEE802154_MIN_HEADER_LEN - 1;
	/* The auth_tag header is for security and places in private payload
	 * room of mac frame which stucks between payload and FCS field.
	 */
	dev->needed_tailroom	= IEEE802154_MAX_AUTH_TAG_LEN +
				  IEEE802154_FCS_LEN;
	/* The mtu size is the payload without mac header in this case.
	 * We have a dynamic length header with a minimum header length
	 * which is hard_header_len. In this case we let mtu to the size
	 * of maximum payload which is IEEE802154_MTU - IEEE802154_FCS_LEN -
	 * hard_header_len. The FCS which is set by hardware or ndo_start_xmit
	 * and the minimum mac header which can be evaluated inside driver
	 * layer. The rest of mac header will be part of payload if greater
	 * than hard_header_len.
	 */
	dev->mtu		= IEEE802154_MTU - IEEE802154_FCS_LEN -
				  dev->hard_header_len;
	dev->tx_queue_len	= 300;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
}





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
	struct xb_device *xbdev = tty->disc_data;
	struct ieee802154_hw *hw;

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

	xbdev = (struct xb_device*)xbee_alloc_hw(sizeof(struct xb_device));
	//err = register_netdevice(xbdev->local->phy->dev);
//	hw = ieee802154_alloc_hw(sizeof(struct xb_device), &xbee_ieee802154_ops);
	//if (!hw)
		return -ENOMEM;


//	xbdev = hw->priv;
//	xbdev->hw = hw;
	hw->parent = tty->dev;
	tty->disc_data = xbdev;

	xbdev->recv_buf = dev_alloc_skb(128);
	xbdev->frameid = 1; //TODO
	
	skb_queue_head_init(&xbdev->recv_queue);
	skb_queue_head_init(&xbdev->send_queue);

	init_completion(&xbdev->cmd_resp_done);
	xbdev->comm_workq = create_workqueue("comm_workq");
	INIT_WORK( (struct work_struct*)&xbdev->comm_work.work, comm_work_fn);

#ifdef MODTEST_ENABLE
	INIT_MODTEST(xbdev);
#endif

	xbdev->tty = tty_kref_get(tty);

//	tty->receive_room = MAX_DATA_SIZE;
	tty->receive_room = 65536;

	if (tty->ldisc->ops->flush_buffer)
		tty->ldisc->ops->flush_buffer(tty);
	tty_driver_flush_buffer(tty);

	setup_dev(hw);

	err = ieee802154_register_hw(hw);
	if (err) {
        printk(KERN_ERR "%s: device register failed\n", __func__);
		goto err;
	}

#ifdef MODTEST_ENABLE
	RUN_MODTEST(xbdev);
#endif

	return 0;

err:
	tty->disc_data = NULL;
	tty_kref_put(tty);
	xbdev->tty = NULL;

	//ieee802154_unregister_hw(xbdev->hw);
	//ieee802154_free_hw(xbdev->hw);

	return err;
}

/**
 * xbee_ldisc_close - Close line discipline and unregister with ieee802154.
 *
 * @tty: TTY info for line.
 */
static void xbee_ldisc_close(struct tty_struct *tty)
{
	struct xb_device *xbdev = tty->disc_data;

	pr_debug("%s\n", __func__);

	if (NULL == xbdev) {
		printk(KERN_WARNING "%s: match is not found\n", __func__);
		return;
	}

	tty->disc_data = NULL;
	tty_kref_put(tty);
	xbdev->tty = NULL;

	//ieee802154_unregister_hw(xbdev->hw);

	tty_ldisc_flush(tty);
	tty_driver_flush_buffer(tty);

	//ieee802154_free_hw(xbdev->hw);
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
	struct xb_device *xbdev = tty->disc_data;
	int ret = 0;

	//print_hex_dump_bytes("<<<< ", DUMP_PREFIX_NONE, buf, count);
	
	if (!tty->disc_data) {
		printk(KERN_ERR "%s(): record for tty is not found\n", __func__);
		return 0;
	}


	ret = frame_put_received_data(xbdev->recv_buf, buf, count);

	if(ret == 0) return count;

	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret > 0) {
		ret = queue_work(xbdev->comm_workq, (struct work_struct*)&xbdev->comm_work.work);
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

#ifdef MODTEST_ENABLE
#include "xbee2_test.c"
DECL_TESTS_ARRAY();
#endif

module_init(xbee_init);
module_exit(xbee_exit);

MODULE_DESCRIPTION("Digi XBee IEEE 802.15.4 serial driver");
MODULE_ALIAS_LDISC(N_IEEE802154_XBEE);
MODULE_LICENSE("GPL");

