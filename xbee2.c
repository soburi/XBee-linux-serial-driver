#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/tty.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/seq_buf.h>
#include <linux/nl80211.h>
#include <net/mac802154.h>
#include <net/regulatory.h>

#define N_IEEE802154_XBEE 25
#define VERSION 1

#define XBEE_CHAR_NEWFRM 0x7e

#define ZIGBEE_EXPLICIT_RX_INDICATOR 0x91

enum {
	STATE_WAIT_START1,
	STATE_WAIT_START2,
	STATE_WAIT_COMMAND,
	STATE_WAIT_PARAM1,
	STATE_WAIT_PARAM2,
	STATE_WAIT_DATA
};

enum {
	XBEE_AT_VR = ('V' << 8 & 'R'),
};

/*********************************************************************/

struct xb_device {
	struct tty_struct *tty;
	struct ieee802154_hw *dev;

	/* locks the ldisc for the command */
	struct mutex		mutex;
	struct completion	cmd_resp_done;
	/* command completition */
    wait_queue_head_t frame_waitq;

    struct sk_buff *frame;
	unsigned char payload[128];
    struct seq_buf send_buf;
    int frame_esc;
    int frame_len;
//	struct list_head frame_pend;
	/* Command (rx) processing */
	int			state;
	char		frameid;

	unsigned short firmware_version;
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

/* API frame types */
enum {
	XBEE_FRM_TX64 = 0x00,
	XBEE_FRM_TX16 = 0x01,
	XBEE_FRM_CMD = 0x08,
	XBEE_FRM_CMDQ = 0x09,
	XBEE_FRM_RCMD = 0x17,
	XBEE_FRM_CMDR = 0x88,
	XBEE_FRM_STAT = 0x8A,
	XBEE_FRM_TXSTAT = 0x8B,
	XBEE_FRM_RX64 = 0x80,
	XBEE_FRM_RX16 = 0x81,
	XBEE_FRM_RX64IO = 0x82,
	XBEE_FRM_RX16IO = 0x83,
	XBEE_FRM_TXS = 0x89,
	XBEE_FRM_RCMDR = 0x97,
};

static int _seq_buf_putc(struct seq_buf* sb, unsigned char c)
{
	if( sb->len < sb->size ) {
		sb->buffer[sb->len++] = c;
		return 0;
	}
	else {
		seq_buf_set_overflow(sb);
		return -1;
	}

}

static int xbee_frame_append_send_buf(struct xb_device *xb, unsigned char c)
{
	return _seq_buf_putc(&xb->send_buf, c);
}

static void xbee_frame_sendrecv(struct xb_device *xb)
{
	int i=0;
	int ret = 0;
	unsigned char checksum = 0;
	struct tty_struct *tty = xb->tty;

	pr_debug("%s\n", __func__);

	for(i=3; i<xb->send_buf.len;i++) {
		checksum += xb->send_buf.buffer[i];
	}
	checksum = 0xFF - checksum;

	xbee_frame_append_send_buf(xb, checksum);

	print_hex_dump_bytes("send_buffer: ", DUMP_PREFIX_NONE, xb->send_buf.buffer, xb->send_buf.len);

	tty->ops->write(tty, xb->send_buf.buffer, xb->send_buf.len);
	tty_driver_flush_buffer(tty);

	ret = wait_for_completion_interruptible_timeout(&xb->cmd_resp_done, 100);
	if(!ret) {
			pr_debug("rett %d\n", ret);
	}
	else {
			pr_debug("retf %d\n", ret);
	}
}

static void xbee_frame_new_send_frame(struct xb_device *xb, unsigned short paylen, unsigned char type)
{
	seq_buf_clear(&xb->send_buf);
	xbee_frame_append_send_buf(xb, 0x7e);
	xbee_frame_append_send_buf(xb, (paylen+1)>>8&0xFF);
	xbee_frame_append_send_buf(xb, (paylen+1)&0xFF);
	xbee_frame_append_send_buf(xb, type);
	xbee_frame_append_send_buf(xb, 1); ///frameid
}

static void xbee_frame_sendrecv_at(struct xb_device *xb, unsigned short atcmd, char* buf, unsigned short buflen)
{
	int i=0;
	xbee_frame_new_send_frame(xb, buflen+3, 0x08);
	xbee_frame_append_send_buf(xb, atcmd>>8&0xFF);
	xbee_frame_append_send_buf(xb, atcmd&0xFF);

	for(i=0; i<buflen; i++) {
		xbee_frame_append_send_buf(xb, buf[i]);
	}

	pr_debug("send_command\n");
	xbee_frame_sendrecv(xb);
}

static void
cleanup(struct xb_device *zbdev)
{
	pr_debug("%s\n", __func__);
    zbdev->state = STATE_WAIT_START1;
    zbdev->frame = alloc_skb(SKB_MAX_ALLOC, GFP_KERNEL);
/*    zbdev->id = 0;
    zbdev->param1 = 0;
    zbdev->param2 = 0;
    zbdev->index = 0;
    zbdev->pending_id = 0;
    zbdev->pending_size = 0;

    if (zbdev->pending_data)
    {
        kfree(zbdev->pending_data);
        zbdev->pending_data = NULL;
    }
*/
}

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
	struct xb_device *xb = dev->priv;

	pr_debug("%s page=%u channel=%u\n", __func__, page, channel);

	xbee_frame_sendrecv_at(xb, 0x4348, &channel, 1);

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
	struct xb_device *xb = dev->priv;
	pr_debug("%s\n", __func__);

	xbee_frame_sendrecv_at(xb, 0x4544, NULL, 0);

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
	struct xb_device *xb = dev->priv;
	unsigned char u_retries = retries;

	pr_debug("%s\n", __func__);

	xbee_frame_sendrecv_at(xb, 0x5252, &u_retries, 1);

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

	xbee_frame_sendrecv_at(xb, 0x504C, &pl, 1);
	xbee_frame_sendrecv_at(xb, 0x504D, &pm, 1);

	return 0;
}

static int xbee_ieee802154_set_cca_mode(struct ieee802154_hw *dev, const struct wpan_phy_cca *cca)
{
	//cca->mode;
	//cca->opt;
	return 0;
}

static int xbee_ieee802154_set_cca_ed_level(struct ieee802154_hw *dev, s32 mbm)
{
   struct xb_device *xb = dev->priv;
    u8 ca;

    pr_debug("%s mbm=%d\n", __func__, mbm);

    ca = MBM_TO_DBM(mbm);

    xbee_frame_sendrecv_at(xb, 0x4341, &ca, 1);
	return 0;
}

/**
 * xbee_ieee802154_xmit - Handler that 802.15.4 module calls for each transmitted frame.
 *
 * @dev: ...
 * @skb: ...
 */
static int xbee_ieee802154_xmit(struct ieee802154_hw *dev,
				struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
    return 0;
}

static int xbee_ieee802154_filter(struct ieee802154_hw *dev,
					  struct ieee802154_hw_addr_filt *filt,
					    unsigned long changed)
{
	pr_debug("%s\n", __func__);
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

	pr_debug("%s\n", __func__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __func__);
		return -EINVAL;
	}

	pr_debug("%s end (retval: %d)\n", __func__, ret);
	return ret;
}

/**
 * xbee_ieee802154_stop - For device cleanup after last interface is removed.
 *
 * @dev: ...
 */
static void xbee_ieee802154_stop(struct ieee802154_hw *dev){
	struct xb_device *zbdev;
	pr_debug("%s\n", __func__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __func__);
		return;
	}

	pr_debug("%s end\n", __func__);
}

static int xbee_frm_xbee_verify(struct sk_buff *skb){
    int length;
	uint8_t checksum = 0;
    uint16_t i;

    if (skb->len > 2)
    {
        length = (*skb->data << 8) & 0xff00; // MSB
        length |= *(skb->data+1) & 0xff; // LSB
        if (skb->len == length+3){
			print_hex_dump_bytes("sk_buff: ", DUMP_PREFIX_NONE, skb->data, skb->len);
            for(i=0;i<length;++i) {
                checksum += *(skb->data+i+2);
            }
            checksum = 0xFF - checksum;
            if (checksum==*(skb->data+length+3-1))
                return 0;
        }
    }
    return 1;
}

static int xbee_frm_xbee_id(struct sk_buff *skb){
//	pr_debug("%s %x\n", __func__, *(skb->data+2));
    return *(skb->data+2);
}
static int xbee_frame_peak_done(struct xb_device *xbdev){
//	pr_debug("%s\n", __func__);
    return !xbee_frm_xbee_verify(xbdev->frame);
}
static void xbee_frame_recv_rx64(struct xb_device *xbdev,
                    struct sk_buff *skb)
{
    struct sk_buff *lskb;
	pr_debug("%s\n", __func__);
    lskb = alloc_skb(skb->len, GFP_ATOMIC);
    skb_put(lskb, skb->len);
    skb_copy_to_linear_data(lskb, skb->data, skb->len);
	ieee802154_rx_irqsafe(xbdev->dev, lskb, skb->len);
//	ieee802154_rx(xbdev->dev, skb, rssi);
}
static void xbee_frame_recv_stat(struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
}

static void xbee_frame_recv_atcmd(struct xb_device *xbdev, char frameid, unsigned short atcmd, char status, char* buf, unsigned long buflen)
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

static void xbee_frame_recv_cmdr(struct xb_device *xbdev, struct sk_buff *skb)
{
	char frameid = *(skb->data+3);
	unsigned short atcmd = *((unsigned short*)(skb->data+4));
	char status = *(skb->data+6);
	char* data = (skb->data)+7;
	unsigned long datalen = (skb->len)-8;

	pr_debug("%s\n", __func__);

	print_hex_dump_bytes("data: ", DUMP_PREFIX_NONE, data, datalen);
	xbee_frame_recv_atcmd(xbdev, frameid, atcmd, status, data, datalen);
}

static void xbee_frame_recv_rcmdr(struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
}
static void xbee_frame_recv_txstat(struct sk_buff *skb)
{
	pr_debug("%s\n", __func__);
}
static void xbee_frame_recv_rx16(struct sk_buff *skb)
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
static void xbee_frm_xbee_recv(struct xb_device *xbdev,
			       struct sk_buff *skb)
{
	u8 id;
    int err;

	pr_debug("%s\n", __func__);
#if 0
	/* verify length and checksum */
	err = xbee_frm_xbee_verify(skb);
	if (err) {
//		XBEE_WARN("dropping invalid frame 0x%x", err);
		printk(KERN_WARNING "%s: dropping invalid frame 0x%x\n", __func__, err);
		return;
	}
#endif
	id = xbee_frm_xbee_id(skb);
	switch (id) {
	case XBEE_FRM_STAT:
		xbee_frame_recv_stat(skb);
		break;
	case XBEE_FRM_CMDR:
		xbee_frame_recv_cmdr(xbdev, skb);
		break;
	case XBEE_FRM_RCMDR:
		xbee_frame_recv_rcmdr(skb);
		break;
	case XBEE_FRM_TXSTAT:
		xbee_frame_recv_txstat(skb);
		break;
	case XBEE_FRM_RX64:
		xbee_frame_recv_rx64(xbdev, skb);
		break;
	case XBEE_FRM_RX16:
		xbee_frame_recv_rx16(skb);
		break;
	case XBEE_FRM_RX64IO:
	case XBEE_FRM_RX16IO:
		printk(KERN_WARNING "received unimplemented frame type 0x%x", id);
		//skb_free(skb);
		break;
	case XBEE_FRM_CMD:
	case XBEE_FRM_CMDQ:
	case XBEE_FRM_RCMD:
	case XBEE_FRM_TX64:
	case XBEE_FRM_TX16:
		printk(KERN_WARNING "received tx-only frame type 0x%x", id);
		//skb_free(skb);
		break;
	default:
//		XBEE_WARN("received unknown frame type 0x%x", id);
	    pr_debug("%s received unknown frame type 0x%x\n", __func__, id);
//		kfree_skb(skb);
		break;
	}
}

static int xbee_frm_new(struct xb_device *xbdev,
			struct sk_buff **skb)
{
	struct sk_buff *new_skb;

	new_skb = alloc_skb(SKB_MAX_ALLOC, GFP_KERNEL);
	if (new_skb == NULL) {
//		XBEE_ERR("failed to allocate new skb");
        printk(KERN_ERR "%s: failed to allocate new skb\n", __func__);
		return 1;
	} else {
//        pr_debug("%s 1 skb %d\n", __func__, skb);
//        pr_debug("%s 1 *skb %d\n", __func__, *skb);
		*skb = xbdev->frame;
//        pr_debug("%s 2 skb %d\n", __func__, skb);
//        pr_debug("%s 2 *skb %d\n", __func__, *skb);
		xbdev->frame = new_skb;
////		*skb = old_skb;

		xbdev->frame_len = 0;
		return 0;
	}
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
	.owner		= THIS_MODULE,
	.xmit_sync	= xbee_ieee802154_xmit,
	.ed		= xbee_ieee802154_ed,
	.set_channel	= xbee_ieee802154_set_channel,
	.set_hw_addr_filt = xbee_ieee802154_filter,
	.set_txpower = xbee_ieee802154_set_txpower,
	.set_lbt = NULL,
	.set_cca_mode = xbee_ieee802154_set_cca_mode,
	.set_cca_ed_level = xbee_ieee802154_set_cca_ed_level,
	.set_csma_params = NULL,
	.set_frame_retries = xbee_ieee802154_set_frame_retries,
	.set_promiscuous_mode = NULL,
	.start		= xbee_ieee802154_start,
	.stop		= xbee_ieee802154_stop,
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
	seq_buf_init(&xbdev->send_buf, xbdev->payload, 128);

	mutex_init(&xbdev->mutex);
	init_completion(&xbdev->cmd_resp_done);
	init_waitqueue_head(&xbdev->frame_waitq);

	dev->extra_tx_headroom = 0;
	/* only 2.4 GHz band */
	dev->phy->current_channel = 11;
	dev->phy->current_page = 0;
	dev->phy->supported.channels[0] = 0x7fff800;
	dev->phy->supported.cca_modes = 0;
	dev->phy->supported.cca_opts = 0;
	dev->phy->supported.iftypes = 0;
	dev->phy->supported.lbt = 0;
	dev->phy->supported.min_minbe = 0;
	dev->phy->supported.max_minbe = 0;
	dev->phy->supported.min_maxbe = 0;
	dev->phy->supported.max_maxbe = 0;
	dev->phy->supported.min_csma_backoffs = 0;
	dev->phy->supported.max_csma_backoffs = 0;
	dev->phy->supported.min_frame_retries = 0;
	dev->phy->supported.max_frame_retries = 0;
	dev->phy->supported.tx_powers_size = 0;
	dev->phy->supported.cca_ed_levels_size = 0;
/*
	dev->phy->transmit_power = 0;
	dev->phy->cca = 0;
	dev->phy->cca_ed_level = 0;
	dev->phy->symbol_duration = 0;
	dev->phy->lifs_period = 0;
	dev->phy->sifs_period = 0;
*/



	dev->flags = IEEE802154_HW_OMIT_CKSUM;

	dev->parent = tty->dev;

	xbdev->tty = tty_kref_get(tty);

    cleanup(xbdev);

	tty->disc_data = xbdev;
//	tty->receive_room = MAX_DATA_SIZE;
	tty->receive_room = 65536;

//	dev->ml_priv = &xbee_ieee802154_mlme_ops;

	if (tty->ldisc->ops->flush_buffer)
		tty->ldisc->ops->flush_buffer(tty);
	tty_driver_flush_buffer(tty);

	err = ieee802154_register_hw(dev);
	if (err) {
//		XBEE_ERROR("%s: device register failed\n", __func__);
        printk(KERN_ERR "%s: device register failed\n", __func__);
		goto err;
	}

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
	mutex_destroy(&zbdev->mutex);

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
			    unsigned int cmd, unsigned long arg){
	pr_debug("%s\n", __func__);
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
static void xbee_ldisc_recv_buf(struct tty_struct *tty,
				const unsigned char *cp,
				char *fp, int count)
{
//	struct ieee802154_dev *dev;
	struct xb_device *xbdev;
	char c;
	int ret;
	struct sk_buff *skb;
	pr_debug("%s count=%d \n", __func__, count);

	/* Debug info */
//	printk(KERN_INFO "%s, received %d bytes\n", __func__,
//			count);
#ifdef DEBUG
//	print_hex_dump_bytes("ieee802154_tty_receive ", DUMP_PREFIX_NONE,
//			cp, count);
#endif

	/* Actual processing */
	xbdev = tty->disc_data;
	if (NULL == xbdev) {
		printk(KERN_ERR "%s(): record for tty is not found\n",
				__func__);
		return;
	}

	/* copy (i wish i could just lock and link them in an array) buffers */
	while (count--) {
		c = *cp++;
		/* escape this byte */
/*
		if (xbdev->frame_esc) {
			c ^= 0x20;
			xbdev->frame_esc = 0;
		}
*/
    
//    	pr_debug("char %x\n", c);

		switch (c) {
//		    case XBEE_CHAR_ESC: /* escape next byte */
//			    xbdev->frame_esc = 1;
//			    break;
		    case XBEE_CHAR_NEWFRM: /* new frame */
//			    XBEE_INFO("new frame");
                pr_debug("new frame\n");
			    /* switch to new frame buffer */
//                pr_debug("1 xbdev->frame->len %d\n", xbdev->frame->len);
//                pr_debug("1 xbdev->frame %d\n", xbdev->frame);
//                pr_debug("skb %d\n", skb);
//                pr_debug("&skb %d\n", &skb);
			    ret = xbee_frm_new(xbdev, &skb);
//                pr_debug("2 xbdev->frame->len %d\n", xbdev->frame->len);
//                pr_debug("2 &xbdev->frame %d\n", xbdev->frame);
//                pr_debug("skb %d\n", skb);
//                pr_debug("&skb %d\n", &skb);
//                pr_debug("skb->len %d\n", skb->len);
//			    if (unlikely(ret))
			    if (ret){
//				    XBEE_ERR("derp");
			    /* submit old frame buffer to stack */
                }
			    else {
				    xbee_frm_xbee_recv(xbdev, skb);
				    kfree_skb(skb);
			    }
			    /* reset overflow status */
//			    overflow = 0;
			    break;
		    default:
//                pr_debug("append to frame buffer\n");
			    /* check for frame buffer overflow */
//			    if (overflow || xbdev->frame_len == XBEE_FRAME_MAXLEN) {
//				    overflow = 1;
//				    continue;
//			    }
			    /* append to frame buffer */
                memcpy(skb_put(xbdev->frame, 1), &c, 1);
			    /* increase current frame buffer len */
			    xbdev->frame_len += 1;
//                pr_debug("xbdev->frame_len %d\n", xbdev->frame_len);
//                pr_debug("xbdev->frame->len %d\n", xbdev->frame->len);
			    break;
        }
    }
//	if (overflow)
//		XBEE_WARN("was buffer overflow");

	/* peak at frame to check if completed */

	if (xbee_frame_peak_done(xbdev)) {
		ret = xbee_frm_new(xbdev, &skb);
		if (ret){
//		if (unlikely(ret))
//			XBEE_ERR("derp");
        }
		else {
			xbee_frm_xbee_recv(xbdev, skb);
			kfree_skb(skb);
		}
	}
}

/*********************************************************************/

/**
 * xbee_ldisc - TTY line discipline ops.
 */
static struct tty_ldisc_ops xbee_ldisc_ops = {
	.owner		= THIS_MODULE,
	.magic		= TTY_LDISC_MAGIC,
 	.name		= "n_ieee802154_xbee",
//	.flags		= 0,
	.open		= xbee_ldisc_open,
	.close		= xbee_ldisc_close,
	.ioctl		= xbee_ldisc_ioctl,
 	.hangup		= xbee_ldisc_hangup,
	.receive_buf	= xbee_ldisc_recv_buf,
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
	if (tty_unregister_ldisc(N_IEEE802154_XBEE) != 0)
		printk(KERN_CRIT
			"failed to unregister ZigBee line discipline.\n");

}

module_init(xbee_init);
module_exit(xbee_exit);

MODULE_DESCRIPTION("Digi XBee IEEE 802.15.4 serial driver");
MODULE_ALIAS_LDISC(N_IEEE802154_XBEE);
//MODULE_LICENSE("Dual GPL/CC0");
MODULE_LICENSE("GPL");

