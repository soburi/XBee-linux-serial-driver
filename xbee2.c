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
	//struct ieee802154_hw hw;
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

	struct net_device* dev;
	struct wpan_phy* phy;
	
	struct  device *parent;
	int     extra_tx_headroom;

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
	//struct xbee_sub_if_data *sdata = netdev_priv(dev);
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

// may not have to impl it.
static int xbee_wpan_dev_header_create(struct sk_buff *skb,
				    struct net_device *dev,
				    const struct ieee802154_addr *daddr,
				    const struct ieee802154_addr *saddr,
				    unsigned len)
{
	struct ieee802154_hdr hdr;
	struct xbee_sub_if_data *sdata = netdev_priv(dev);
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	struct ieee802154_mac_cb *cb = mac_cb(skb);
	int hlen;

	pr_debug("%s\n", __func__);

	if (!daddr)
		return -EINVAL;

	memset(&hdr.fc, 0, sizeof(hdr.fc));
	hdr.fc.type = cb->type;
	hdr.fc.security_enabled = cb->secen;
	hdr.fc.ack_request = cb->ackreq;
	hdr.seq = atomic_inc_return(&dev->ieee802154_ptr->dsn) & 0xFF;

	//if (mac802154_set_header_security(sdata, &hdr, cb) < 0)
	//	return -EINVAL;

	if (!saddr) {
		if (wpan_dev->short_addr == cpu_to_le16(IEEE802154_ADDR_BROADCAST) ||
		    wpan_dev->short_addr == cpu_to_le16(IEEE802154_ADDR_UNDEF) ||
		    wpan_dev->pan_id == cpu_to_le16(IEEE802154_PANID_BROADCAST)) {
			hdr.source.mode = IEEE802154_ADDR_LONG;
			hdr.source.extended_addr = wpan_dev->extended_addr;
		} else {
			hdr.source.mode = IEEE802154_ADDR_SHORT;
			hdr.source.short_addr = wpan_dev->short_addr;
		}

		hdr.source.pan_id = wpan_dev->pan_id;
	} else {
		hdr.source = *(const struct ieee802154_addr *)saddr;
	}

	hdr.dest = *(const struct ieee802154_addr *)daddr;

	hlen = ieee802154_hdr_push(skb, &hdr);
	if (hlen < 0)
		return -EINVAL;

	skb_reset_mac_header(skb);
	skb->mac_len = hlen;

	if (len > ieee802154_max_payload(&hdr))
		return -EMSGSIZE;

	return hlen;
}


static int xbee_header_create(struct sk_buff *skb,
				   struct net_device *dev,
				   unsigned short type,
				   const void *daddr,
				   const void *saddr,
				   unsigned len)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static int xbee_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	pr_debug("%s\n", __func__);
	return 0;
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
	pr_debug("%s(%p, type=%u, channels%x, page=%u, duration=%u\n", __func__, dev, type, channels, page, duration);
	return 0;
}
static int xbee_mlme_set_mac_params(struct net_device *dev, const struct ieee802154_mac_params *params)
{
	struct xbee_sub_if_data *sdata = netdev_priv(dev);
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;

	pr_debug("%s\n", __func__);

	wpan_dev->wpan_phy->transmit_power = params->transmit_power;
	wpan_dev->min_be = params->min_be;
	wpan_dev->max_be = params->max_be;
	wpan_dev->csma_retries = params->csma_retries;
	wpan_dev->frame_retries = params->frame_retries;
	wpan_dev->lbt = params->lbt;
	wpan_dev->wpan_phy->cca = params->cca;
	wpan_dev->wpan_phy->cca_ed_level = params->cca_ed_level;

	return 0;
}
static void xbee_mlme_get_mac_params(struct net_device *dev, struct ieee802154_mac_params *params)
{
	struct xbee_sub_if_data *sdata = netdev_priv(dev);
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;

	pr_debug("%s\n", __func__);

	params->transmit_power = wpan_dev->wpan_phy->transmit_power;
	params->min_be = wpan_dev->min_be;
	params->max_be = wpan_dev->max_be;
	params->csma_retries = wpan_dev->csma_retries;
	params->frame_retries = wpan_dev->frame_retries;
	params->lbt = wpan_dev->lbt;
	params->cca = wpan_dev->wpan_phy->cca;
	params->cca_ed_level = wpan_dev->wpan_phy->cca_ed_level;

	return;
}

static int xbee_ndo_open(struct net_device *dev)
{
	pr_debug("%s\n", __func__);
	ASSERT_RTNL();

	netif_start_queue(dev);
	return 0;
}

static int xbee_ndo_stop(struct net_device *dev)
{
	pr_debug("%s\n", __func__);
	netif_stop_queue(dev);
	return 0;
}
static netdev_tx_t xbee_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	pr_debug("%s\n", __func__);
	return NETDEV_TX_OK;
}

//same as mac802154
static int
xbee_ndo_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct xbee_sub_if_data *sdata = netdev_priv(dev);
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	struct sockaddr_ieee802154 *sa =
		(struct sockaddr_ieee802154 *)&ifr->ifr_addr;
	int err = -ENOIOCTLCMD;

	if (cmd != SIOCGIFADDR && cmd != SIOCSIFADDR)
		return err;

	rtnl_lock();

	switch (cmd) {
	case SIOCGIFADDR:
	{
		u16 pan_id, short_addr;

		pan_id = le16_to_cpu(wpan_dev->pan_id);
		short_addr = le16_to_cpu(wpan_dev->short_addr);
		if (pan_id == IEEE802154_PANID_BROADCAST ||
		    short_addr == IEEE802154_ADDR_BROADCAST) {
			err = -EADDRNOTAVAIL;
			break;
		}

		sa->family = AF_IEEE802154;
		sa->addr.addr_type = IEEE802154_ADDR_SHORT;
		sa->addr.pan_id = pan_id;
		sa->addr.short_addr = short_addr;

		err = 0;
		break;
	}
	case SIOCSIFADDR:
		if (netif_running(dev)) {
			rtnl_unlock();
			return -EBUSY;
		}

		dev_warn(&dev->dev,
			 "Using DEBUGing ioctl SIOCSIFADDR isn't recommended!\n");
		if (sa->family != AF_IEEE802154 ||
		    sa->addr.addr_type != IEEE802154_ADDR_SHORT ||
		    sa->addr.pan_id == IEEE802154_PANID_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_UNDEF) {
			err = -EINVAL;
			break;
		}

		wpan_dev->pan_id = cpu_to_le16(sa->addr.pan_id);
		wpan_dev->short_addr = cpu_to_le16(sa->addr.short_addr);

		//err = mac802154_wpan_update_llsec(dev);
		break;
	}

	rtnl_unlock();
	return err;
	return 0;
}

static int xbee_ndo_set_mac_address(struct net_device *dev, void *p)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static struct net_device* xbee_cfg802154_add_virtual_intf_deprecated(struct wpan_phy *wpan_phy,
                                                           const char *name,
                                                           unsigned char name_assign_type,
                                                           int type)
{
	pr_debug("%s\n", __func__);
	return NULL;
}
static void xbee_cfg802154_del_virtual_intf_deprecated(struct wpan_phy *wpan_phy,
                                               struct net_device *dev)
{
	pr_debug("%s\n", __func__);
}
static int xbee_cfg802154_suspend(struct wpan_phy *wpan_phy)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_cfg802154_resume(struct wpan_phy *wpan_phy)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_cfg802154_add_virtual_intf(struct wpan_phy *wpan_phy,
                                    const char *name,
                                    unsigned char name_assign_type,
                                    enum nl802154_iftype type,
                                    __le64 extended_addr)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_cfg802154_del_virtual_intf(struct wpan_phy *wpan_phy,
                                    struct wpan_dev *wpan_dev)
{
	pr_debug("%s\n", __func__);
	return 0;
}
/**
 * xbee_ieee802154_set_channel - Set radio for listening on specific channel.
 *
 * @dev: ...
 * @page: ...
 * @channel: ...
 */
static int xbee_cfg802154_set_channel(struct wpan_phy *wpan_phy, u8 page, u8 channel)
{
	struct xb_device *xb = wpan_phy_priv(wpan_phy);

	pr_debug("%s\n", __func__);

	xb_enqueue_send_at(xb, XBEE_AT_CH, &channel, 1);
	xb_process_sendrecv(xb);
	return 0;
}
static int xbee_cfg802154_set_cca_mode(struct wpan_phy *wpan_phy,
                                       const struct wpan_phy_cca *cca)
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
static int xbee_cfg802154_set_cca_ed_level(struct wpan_phy *wpan_phy, s32 ed_level)
{
	struct xb_device *xb = wpan_phy_priv(wpan_phy);
	u8 ca;

	pr_debug("%s ed_level=%d ca=%d\n", __func__, ed_level, -ed_level/100);

	ca = -ed_level/100;

	xb_enqueue_send_at(xb, XBEE_AT_CA, &ca, 1);
	return 0;
}
static int xbee_cfg802154_set_tx_power(struct wpan_phy *wpan_phy, s32 power)
{
	struct xb_device *xb = wpan_phy_priv(wpan_phy);
	u8 pl;

	pr_debug("%s mbm=%d\n", __func__, power);

	if(power >= 1000) {
		pl=0;
	} else if(power >= 600) {
		pl=1;
	} else if(power >= 400) {
		pl=2;
	} else if(power >= 200) {
		pl=3;
	} else {
		pl=4;
	}

	xb_enqueue_send_at(xb, XBEE_AT_PL, &pl, 1);

	return 0;
}

static int xbee_cfg802154_set_pan_id(struct wpan_phy *wpan_phy,
                              struct wpan_dev *wpan_dev, __le16 pan_id)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_cfg802154_set_short_addr(struct wpan_phy *wpan_phy,
                                  struct wpan_dev *wpan_dev, __le16 short_addr)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_cfg802154_set_backoff_exponent(struct wpan_phy *wpan_phy,
                                        struct wpan_dev *wpan_dev, u8 min_be,
                                        u8 max_be)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_cfg802154_set_max_csma_backoffs(struct wpan_phy *wpan_phy,
                                         struct wpan_dev *wpan_dev,
                                         u8 max_csma_backoffs)
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
static int xbee_cfg802154_set_max_frame_retries(struct wpan_phy *wpan_phy,
                                         struct wpan_dev *wpan_dev,
                                         s8 max_frame_retries)
{
	//struct xb_device *xb = wpan_phy_priv(wpan_phy);

	pr_debug("%s\n", __func__);

	//xb_enqueue_send_at(xb, XBEE_AT_RR, &u_retries, 1);

	return 0;
}
static int xbee_cfg802154_set_lbt_mode(struct wpan_phy *wpan_phy,
                                struct wpan_dev *wpan_dev, bool mode)
{
	pr_debug("%s\n", __func__);
	return 0;
}
static int xbee_cfg802154_set_ackreq_default(struct wpan_phy *wpan_phy,
                                      struct wpan_dev *wpan_dev, bool ackreq)
{
	pr_debug("%s\n", __func__);
	return 0;
}

static const struct wpan_dev_header_ops xbee_wpan_dev_header_ops = {
	.create			= xbee_wpan_dev_header_create, //**
};

static const struct header_ops xbee_header_ops = {
	.create			= xbee_header_create,
	.parse			= xbee_header_parse,
	.cache			= NULL, //(const struct neighbour *neigh, struct hh_cache *hh, __be16 type);
	.cache_update		= NULL, //(struct hh_cache *hh, const struct net_device *dev, const unsigned char *haddr);
	.validate		= NULL, //(const char *ll_header, unsigned int len);
};

static const struct net_device_ops xbee_net_device_ops = {
        .ndo_open               = xbee_ndo_open,		//**
        .ndo_stop               = xbee_ndo_stop,		//**
        .ndo_start_xmit         = xbee_ndo_start_xmit,		//**
        .ndo_do_ioctl           = xbee_ndo_do_ioctl,
        .ndo_set_mac_address    = xbee_ndo_set_mac_address,	// ?
};

static struct ieee802154_mlme_ops xbee_ieee802154_mlme_ops = {
	.assoc_req		= xbee_mlme_assoc_req,		//**
	.assoc_resp		= xbee_mlme_assoc_resp,
	.disassoc_req		= xbee_mlme_disassoc_req,
	.start_req		= xbee_mlme_start_req,
	.scan_req		= xbee_mlme_scan_req,		//**
	.set_mac_params		= xbee_mlme_set_mac_params,
	.get_mac_params		= xbee_mlme_get_mac_params,	//**
	.llsec			= NULL,
};

static const struct cfg802154_ops xbee_cfg802154_ops = {
	.add_virtual_intf_deprecated	= xbee_cfg802154_add_virtual_intf_deprecated,
	.del_virtual_intf_deprecated	= xbee_cfg802154_del_virtual_intf_deprecated,
	.suspend		= xbee_cfg802154_suspend,
	.resume			= xbee_cfg802154_resume,
	.add_virtual_intf	= xbee_cfg802154_add_virtual_intf,
	.del_virtual_intf	= xbee_cfg802154_del_virtual_intf,	//**
	.set_channel		= xbee_cfg802154_set_channel,		//**
	.set_cca_mode		= xbee_cfg802154_set_cca_mode,		//**
	.set_cca_ed_level	= xbee_cfg802154_set_cca_ed_level,	//**
	.set_tx_power		= xbee_cfg802154_set_tx_power,		//**
	.set_pan_id		= xbee_cfg802154_set_pan_id,		//**
	.set_short_addr		= xbee_cfg802154_set_short_addr,	//**
	.set_backoff_exponent	= xbee_cfg802154_set_backoff_exponent,	//**
	.set_max_csma_backoffs	= xbee_cfg802154_set_max_csma_backoffs,	//**
	.set_max_frame_retries	= xbee_cfg802154_set_max_frame_retries,	//**
	.set_lbt_mode		= xbee_cfg802154_set_lbt_mode,		//**
	.set_ackreq_default	= xbee_cfg802154_set_ackreq_default,	//**
#ifdef CONFIG_IEEE802154_NL802154_EXPERIMENTAL
	.get_llsec_table	= xbee_cfg802154_get_llsec_table,
	.lock_llsec_table	= xbee_cfg802154_lock_llsec_table,
	.unlock_llsec_table	= xbee_cfg802154_unlock_llsec_table,
	.set_llsec_params	= xbee_cfg802154_set_llsec_params,
	.get_llsec_params	= xbee_cfg802154_get_llsec_params,
	.add_llsec_key		= xbee_cfg802154_add_llsec_key,
	.del_llsec_key		= xbee_cfg802154_del_llsec_key,
	.add_seclevel		= xbee_cfg802154_add_seclevel,
	.del_seclevel		= xbee_cfg802154_del_seclevel,
	.add_device		= xbee_cfg802154_add_device,
	.del_device		= xbee_cfg802154_del_device,
	.add_devkey		= xbee_cfg802154_add_devkey,
	.del_devkey		= xbee_cfg802154_del_devkey,
#endif /* CONFIG_IEEE802154_NL802154_EXPERIMENTAL */
};


/*
 * See Documentation/tty.txt for details.
 */


static void ieee802154_if_setup(struct net_device *dev);

static struct xb_device *
xbee_alloc_device(size_t priv_data_len)
{
	struct xb_device* local = NULL;
	struct wpan_phy *phy = NULL;
	size_t priv_size;

	pr_debug("%s(%lu)\n",__func__, priv_data_len);

	priv_size = ALIGN(sizeof(*local), NETDEV_ALIGN) + priv_data_len;

	phy = wpan_phy_new(&xbee_cfg802154_ops, priv_size);
	if (!phy) {
		pr_err("failure to allocate master IEEE802.15.4 device\n");
		return NULL;
	}
	pr_debug("wpan_phy_priv\n");
	local = wpan_phy_priv(phy);
	local->phy = phy;
	local->dev = NULL;
	//local->hw.phy = local->phy;
	//local->hw.priv = (char *)local + ALIGN(sizeof(*local), NETDEV_ALIGN);
	//local->ops = ops;

	pr_debug("wpan_phy_set_dev\n");
	wpan_phy_set_dev(local->phy, local->parent);

	return local;

//free_phy:
//	wpan_phy_free(phy);
//	return NULL;
}

static struct net_device* xbee_alloc_netdev(struct xb_device* local)
{
	//struct wpan_phy *phy = local->phy;
	struct net_device *ndev = local->dev;
	struct xbee_sub_if_data *sdata = NULL;
	int ret = 0;
	
	ndev = alloc_netdev(sizeof(*sdata), "wpan%d",
			    NET_NAME_ENUM, ieee802154_if_setup);
	if (!ndev) {
		pr_err("failure to allocate netdev\n");
		return NULL;
	}

	ndev->needed_headroom = //local->extra_tx_headroom +
				IEEE802154_MAX_HEADER_LEN;

	ret = dev_alloc_name(ndev, ndev->name);
	if (ret < 0) {
		pr_err("failure to allocate device name\n");
		goto free_dev;
	}
	return ndev;

free_dev:
	free_netdev(ndev);
	return NULL;
}

static int xbee_register_netdev(struct net_device* dev)
{
	int ret;

	pr_debug("%s\n", __func__);
	rtnl_lock();

	ret = register_netdevice(dev);

	pr_debug("ret = %d\n", ret);

	rtnl_unlock();
	pr_debug("%d\n", __LINE__);

	return ret;
}

static int xbee_register_device(struct xb_device* local)
{
	int ret;
		
	pr_debug("%s\n", __func__);
	ret = wpan_phy_register(local->phy);
	pr_debug("ret = %d\n", ret);
	pr_debug("%d\n", __LINE__);
	return ret;
}

static void xbee_unregister_netdev(struct net_device* netdev)
{
	pr_debug("%s\n", __func__);
	if(!netdev) return;
	pr_debug("%d\n", __LINE__);
	rtnl_lock();
	unregister_netdevice(netdev);
	rtnl_unlock();
	pr_debug("%d\n", __LINE__);
}


static void xbee_unregister_device(struct xb_device* local)
{
	pr_debug("%s\n", __func__);
	wpan_phy_unregister(local->phy);
}

static void xbee_free(struct xb_device* local)
{
	free_netdev(local->dev);
	wpan_phy_free(local->phy);
}

static void xbee_setup(struct xb_device* local, struct net_device* ndev)
{
	__le64 extended_addr = cpu_to_le64(0x0000000000000000ULL);
	struct wpan_phy *phy = local->phy;
	struct xbee_sub_if_data *sdata = netdev_priv(ndev);//NULL;
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	//int ret = -ENOMEM;
	enum nl802154_iftype type = NL802154_IFTYPE_NODE;
	uint8_t tmp;

	/* TODO check this */
	SET_NETDEV_DEV(ndev, &phy->dev);
	sdata = netdev_priv(ndev);
	ndev->ieee802154_ptr = &sdata->wpan_dev;
	memcpy(sdata->name, ndev->name, IFNAMSIZ);
	sdata->dev = ndev;
	sdata->wpan_dev.wpan_phy = phy;//local->hw.phy;
	sdata->local = local;
	local->dev = ndev;


	phy->supported.max_minbe = 8;
	phy->supported.min_maxbe = 3;
	phy->supported.max_maxbe = 8;
	phy->supported.min_frame_retries = 0;
	phy->supported.max_frame_retries = 7;
	phy->supported.max_csma_backoffs = 5;
	phy->supported.lbt = NL802154_SUPPORTED_BOOL_FALSE;

	/* always supported */
	phy->supported.iftypes = BIT(NL802154_IFTYPE_NODE);


	phy->lifs_period = IEEE802154_LIFS_PERIOD *
				phy->symbol_duration;
	phy->sifs_period = IEEE802154_SIFS_PERIOD *
				phy->symbol_duration;

	local->extra_tx_headroom = 0;
	/* only 2.4 GHz band */
	phy->flags = WPAN_PHY_FLAG_TXPOWER |
			          WPAN_PHY_FLAG_CCA_ED_LEVEL |
					  WPAN_PHY_FLAG_CCA_MODE;
	phy->current_channel = 11;
	phy->current_page = 0;
	phy->supported.channels[0] = 0x7fff800;
	phy->supported.cca_modes = BIT(NL802154_CCA_ENERGY);
	phy->supported.cca_opts = NL802154_CCA_ENERGY;
	phy->supported.iftypes = 0;
	phy->supported.lbt = 0;
	phy->supported.min_minbe = 0;
	phy->supported.max_minbe = 3;
	phy->supported.min_maxbe = 5; /* N/A */
	phy->supported.max_maxbe = 5; /* N/A */
	phy->supported.min_csma_backoffs = 0; /* N/A */
	phy->supported.max_csma_backoffs = 0; /* N/A */
	phy->supported.min_frame_retries = 0;
	phy->supported.max_frame_retries = 0;
	phy->supported.tx_powers_size = 0;

	phy->supported.cca_ed_levels_size = 41;

	{
	static const s32 ed_levels [] = {
		-3600, -3700, -3800, -3900, -4000,
		-4100, -4200, -4300, -4400, -4500, -4600, -4700, -4800, -4900, -5000,
		-5100, -5200, -5300, -5400, -5500, -5600, -5700, -5800, -5900, -6000,
		-6100, -6200, -6300, -6400, -6500, -6600, -6700, -6800, -6900, -8000,
	};
	phy->supported.cca_ed_levels = ed_levels;
	phy->supported.cca_ed_levels_size = sizeof(ed_levels)/sizeof(ed_levels[0]);
	}

	{
	static const s32 tx_powers[] = {
		1000, 600, 400, 200, 0
	};
	phy->supported.tx_powers = tx_powers;
	phy->supported.tx_powers_size = sizeof(tx_powers)/sizeof(tx_powers[0]);
	}

/*
	phy->transmit_power = 0;
	phy->cca = 0;
	phy->cca_ed_level = 0;
	phy->symbol_duration = 0;
	phy->lifs_period = 0;
	phy->sifs_period = 0;
*/

	//local->flags = IEEE802154_HW_OMIT_CKSUM | IEEE802154_HW_AFILT;

//	ndev->needed_headroom = local->hw.extra_tx_headroom +
//				IEEE802154_MAX_HEADER_LEN;

//	ieee802154_le64_to_be64(ndev->perm_addr,
//				&local->hw.phy->perm_extended_addr);
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

	/* set some type-dependent values */
	sdata->wpan_dev.iftype = type;

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

	sdata->dev->header_ops = &xbee_header_ops;
		sdata->dev->destructor = mac802154_wpan_free;
		sdata->dev->netdev_ops = &xbee_net_device_ops;
		sdata->dev->ml_priv = &xbee_ieee802154_mlme_ops;
		wpan_dev->promiscuous_mode = false;
		wpan_dev->header_ops = &xbee_wpan_dev_header_ops;

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



















/*****************************************************************************
 * Line discipline interface for IEEE 802.15.4 serial device
 *****************************************************************************/

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
	struct net_device *ndev = NULL;
	//struct ieee802154_hw *hw;

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

	xbdev = (struct xb_device*)xbee_alloc_device(sizeof(struct xb_device));
//	hw = ieee802154_alloc_hw(sizeof(struct xb_device), &xbee_ieee802154_ops);
	if (!xbdev)
		return -ENOMEM;

//	xbdev = hw->priv;
//	xbdev->hw = hw;
	xbdev->parent = tty->dev;
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

	ndev = xbee_alloc_netdev(xbdev);
	xbee_setup(xbdev, ndev);
	err = xbee_register_device(xbdev);
	err = xbee_register_netdev(ndev);
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
	xbee_unregister_netdev(xbdev->dev);
	xbee_unregister_device(xbdev);
	//ieee802154_free_hw(xbdev->hw);
	//xbee_free(xbdev);

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
	xbee_unregister_netdev(xbdev->dev);
	xbee_unregister_device(xbdev);

	tty_ldisc_flush(tty);
	tty_driver_flush_buffer(tty);

	//ieee802154_free_hw(xbdev->hw);
	//xbee_free(xbdev);
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

