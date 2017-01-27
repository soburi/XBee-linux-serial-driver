#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define TEST_SETUP xbee_test_setup
static int xbee_test_setup(void* arg, int testno) {
	struct xb_device* xbdev = NULL;
	xbdev = (struct xb_device*)arg;
	skb_trim(xbdev->recv_buf, 0);
	skb_queue_purge(&xbdev->recv_queue);
	skb_queue_purge(&xbdev->send_queue);
	return 0;
}

#define TEST0 modtest_check
static struct modtest_result modtest_check(void* arg) {
	pr_debug("test %d\n", __LINE__);
	TEST_SUCCESS();
}

#define TEST1 buffer_calc_checksum_zero
static struct modtest_result buffer_calc_checksum_zero(void* arg) {
	const char buf[] = {};
	const int count = 0;
	int ret = 0;
	ret = buffer_calc_checksum(buf, count);

	FAIL_NOT_EQ(0xFF, ret);

	TEST_SUCCESS();
}

#define TEST2 buffer_calc_checksum_example
static struct modtest_result buffer_calc_checksum_example(void* arg) {
	const char buf[] = {0x23, 0x11};
	const int count = 2;
	int ret = 0;
	ret = buffer_calc_checksum(buf, count);
	
	FAIL_NOT_EQ(0xCB, ret);
	TEST_SUCCESS();
}

#if 0
#define TEST3 buffer_find_delimiter_exists
static struct modtest_result buffer_find_delimiter_exists(void* arg) {
	const char buf[] = {0x23, 0x7E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_unescaped(buf, count);
	FAIL_NOT_EQ(1, ret);
	TEST_SUCCESS();
}


#define TEST4 buffer_find_delimiter_non_exists
static struct modtest_result buffer_find_delimiter_non_exists(void* arg) {
	const char buf[] = {0x23, 0x70, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_unescaped(buf, count);
	FAIL_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}
#endif

#define TEST5 buffer_find_delimiter_escaped_exists
static struct modtest_result buffer_find_delimiter_escaped_exists(void* arg) {
	const char buf[] = {0x23, 0x7E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_NOT_EQ(1, ret);
	TEST_SUCCESS();
}


#define TEST6 buffer_find_delimiter_escaped_non_exists
static struct modtest_result buffer_find_delimiter_escaped_non_exists(void* arg) {
	const char buf[] = {0x23, 0x70, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}


#define TEST7 buffer_find_delimiter_escaped_exists_escape
static struct modtest_result buffer_find_delimiter_escaped_exists_escape(void* arg) {
	const char buf[] = {0x23, 0x7D, 0x5E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_NOT_EQ(1, ret);
	TEST_SUCCESS();
}

#define TEST8 buffer_find_delimiter_escaped_non_exists_escape
static struct modtest_result buffer_find_delimiter_escaped_non_exists_escape(void* arg) {
	const char buf[] = {0x23, 0x7D, 0x31, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}


#define TEST9 buffer_unescape_zero
static struct modtest_result buffer_unescape_zero(void* arg) {
	char buf[] = {};
	const int count = 0;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_NOT_EQ(0, ret);
	TEST_SUCCESS();
}

#define TEST10 buffer_unescape_example
static struct modtest_result buffer_unescape_example(void* arg) {
	char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB};
	char ans[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB};
	const int count = 7;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_NOT_EQ(6, ret);
	FAIL_NOT_EQ(0,  memcmp(buf, ans, 6));
	TEST_SUCCESS();
}

#define TEST11 buffer_unescape_end_escape
static struct modtest_result buffer_unescape_end_escape(void* arg) {
	char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0x7D};
	char ans[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0x7D};
	const int count = 7;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_NOT_EQ(6, ret);
	FAIL_NOT_EQ(0,  memcmp(buf, ans, 6));
	TEST_SUCCESS();
}

#define TEST12 frame_new_test
static struct modtest_result frame_new_test(void* arg) {
	struct sk_buff* skb = frame_new(9, 0x0F);
	struct xb_frameheader* frm = NULL;

	frm = (struct xb_frameheader*)skb->data;

	FAIL_NOT_EQ(0x7E, skb->data[0]);
	FAIL_NOT_EQ(0x00, skb->data[1]);
	FAIL_NOT_EQ(0x0a, skb->data[2]);
	FAIL_NOT_EQ(0x0F, skb->data[3]);
	TEST_SUCCESS();
}

#define TEST13 frame_calc_checksum_zero
static struct modtest_result frame_calc_checksum_zero(void* arg) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	const char buf[] = {0x7E, 0x00, 0x00 };
	const int count = 3;
	int ret = 0;
	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_calc_checksum(xbdev->recv_buf);

	FAIL_NOT_EQ(0xFF, ret);
	TEST_SUCCESS();
}

#define TEST14 frame_calc_checksum_example
static struct modtest_result frame_calc_checksum_example(void* arg) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	const char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB};
	const int count = 6;
	int ret = 0;
	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_calc_checksum(xbdev->recv_buf);

	FAIL_NOT_EQ(0xCB, ret);
	TEST_SUCCESS();
}

#define TEST15 frame_verify_zerobyte
static struct modtest_result frame_verify_zerobyte(void* arg) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;
	ret = frame_verify(xbdev->recv_buf);

	FAIL_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST16 frame_verify_non_startmark
static struct modtest_result frame_verify_non_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x11 };
	const int count = 1;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_NOT_EQ(-EINVAL, ret);
	TEST_SUCCESS();
}

#define TEST17 frame_verify_startmark
static struct modtest_result frame_verify_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e };
	const int count = 1;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST18 frame_verify_length_zero
static struct modtest_result frame_verify_length_zero(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00 };
	const int count = 3;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST19 frame_verify_length_zero_invalid
static struct modtest_result frame_verify_length_zero_invalid(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFE };
	const int count = 4;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_NOT_EQ(-EINVAL, ret);
	TEST_SUCCESS();
}


#define TEST20 frame_verify_length_zero_valid
static struct modtest_result frame_verify_length_zero_valid(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFF };
	const int count = 4;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_NOT_EQ(4, ret);
	TEST_SUCCESS();
}

#define TEST21 frame_verify_length_zero_valid_large
static struct modtest_result frame_verify_length_zero_valid_large(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFF, 0x01};
	const int count = 5;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_NOT_EQ(4, ret);
	TEST_SUCCESS();
}


#define TEST22 frame_verify_valid_example
static struct modtest_result frame_verify_valid_example(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_NOT_EQ(6, ret);

	TEST_SUCCESS();
}

#define TEST23 frame_enqueue_zerobyte
static struct modtest_result frame_enqueue_zerobyte(void* arg) {
	int ret = 0;
	//const char buf[] = {};
	//const int count = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	//unsigned char* tail = skb_put(xbdev->recv_buf, count);
	//memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	FAIL_NOT_EQ(0, ret);
	FAIL_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_NOT_EQ(0, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#define TEST24 frame_enqueue_non_startmark
static struct modtest_result frame_enqueue_non_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x11 };
	const int count = 1;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	FAIL_NOT_EQ(0, ret);
	FAIL_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_NOT_EQ(0, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#define TEST25 frame_enqueue_startmark
static struct modtest_result frame_enqueue_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e };
	const int count = 1;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	FAIL_NOT_EQ(0, ret);
	FAIL_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_NOT_EQ(1, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#define TEST26 frame_enqueue_startmark_len
static struct modtest_result frame_enqueue_startmark_len(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e , 0x00, 0x3 };
	const int count = 3;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	FAIL_NOT_EQ(0, ret);
	FAIL_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_NOT_EQ(3, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#define TEST27 frame_enqueue_valid_example
static struct modtest_result frame_enqueue_valid_example(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	FAIL_NOT_EQ(1, ret);
	FAIL_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));
	FAIL_NOT_EQ(0, xbdev->recv_buf->len);

	TEST_SUCCESS();
}


#define TEST28 frame_enqueue_valid_example_two
static struct modtest_result frame_enqueue_valid_example_two(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB,  0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 12;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	FAIL_NOT_EQ(2, ret);
	FAIL_NOT_EQ(2, skb_queue_len(&xbdev->recv_queue));
	FAIL_NOT_EQ(0, xbdev->recv_buf->len);

	TEST_SUCCESS();
}


#define TEST29 frame_enqueue_valid_partial
static struct modtest_result frame_enqueue_valid_partial(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB, 0x7E };
	const int count = 7;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	FAIL_NOT_EQ(1, ret);
	FAIL_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));
	FAIL_NOT_EQ(1, xbdev->recv_buf->len);

	TEST_SUCCESS();
}


#define TEST30 frame_enqueue_valid_invalid
static struct modtest_result frame_enqueue_valid_invalid(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB, 0x11 };
	const int count = 7;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	FAIL_NOT_EQ(1, ret);
	FAIL_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));
	FAIL_NOT_EQ(0, xbdev->recv_buf->len);

	TEST_SUCCESS();
}



#define TEST100 frame_dequeue_list_found
static struct modtest_result frame_dequeue_list_found(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04 ,0x08 ,0x01 ,0x49 ,0x44 ,0x69 };
	const int count = 8;
	struct sk_buff* dequeued = NULL;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);
	FAIL_NOT_EQ(1, ret);

	dequeued = frame_dequeue_by_id(&xbdev->recv_queue, 1);

	FAIL_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF(dequeued == NULL);

	TEST_SUCCESS();
}

#define TEST101 frame_dequeue_list_notfound
static struct modtest_result frame_dequeue_list_notfound(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04 ,0x08 ,0x01 ,0x49 ,0x44 ,0x69 };
	const int count = 8;
	struct sk_buff* dequeued = NULL;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);
	FAIL_NOT_EQ(1, ret);

	dequeued = frame_dequeue_by_id(&xbdev->recv_queue, 2);

	FAIL_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));
	FAIL_IF(dequeued != NULL);

	TEST_SUCCESS();
}


#define TEST102 frame_dequeue_list_no_id_frame
static struct modtest_result frame_dequeue_list_no_id_frame(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00 ,0x05 ,0x81 ,0xFF ,0xFE ,0x00 ,0x01 ,0x80 };
	const int count = 9;
	struct sk_buff* dequeued = NULL;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);
	FAIL_NOT_EQ(1, ret);

	dequeued = frame_dequeue_by_id(&xbdev->recv_queue, 0xFF);

	FAIL_IF(dequeued != NULL);
	FAIL_NOT_EQ(1, skb_queue_len(&xbdev->recv_queue));

	TEST_SUCCESS();
}


#define TEST103 frame_dequeue_empty_queue
static struct modtest_result frame_dequeue_empty_queue(void* arg) {
	//int ret = 0;
	//const char buf[] = { 0x7E, 0x00 ,0x05 ,0x81 ,0xFF ,0xFE ,0x00 ,0x01 ,0x80 };
	//const int count = 9;
	struct sk_buff* dequeued = NULL;

	struct xb_device* xbdev = (struct xb_device*)arg;

	//unsigned char* tail = skb_put(xbdev->recv_buf, count);
	//memcpy(tail, buf, count);
	//ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);
	//FAIL_NOT_EQ(1, ret);

	FAIL_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));

	dequeued = frame_dequeue_by_id(&xbdev->recv_queue, 0xFF);

	FAIL_IF(dequeued != NULL);
	FAIL_NOT_EQ(0, skb_queue_len(&xbdev->recv_queue));

	TEST_SUCCESS();
}







#define TEST31 frame_enqueue_send_vr
static struct modtest_result frame_enqueue_send_vr(void* arg) {
	//int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x56, 0x52, 0x4E };
	const int count = 8;

	struct xb_device* xbdev = (struct xb_device*)arg;
	struct sk_buff* send_buf = alloc_skb(128, GFP_KERNEL);

	unsigned char* tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	//FAIL_NOT_EQ(1, ret);

	FAIL_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));
	FAIL_NOT_EQ(0, xbdev->recv_buf->len);
	TEST_SUCCESS();
}

#if 0
#define TEST32 xb_process_sendrecv_vr
static struct modtest_result xb_process_sendrecv_vr(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x56, 0x52, 0x4E };
	const int count = 8;

	struct xb_device* xbdev = (struct xb_device*)arg;
	struct sk_buff* send_buf = alloc_skb(128, GFP_KERNEL);

	unsigned char* tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	xb_sendrecv(xbdev);

	//FAIL_NOT_EQ(1, ret);
	FAIL_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));
	FAIL_NOT_EQ(0, xbdev->recv_buf->len);

	TEST_SUCCESS();
}
#endif

#if 0

#define TEST32 xbee_ieee802154_set_channel_test
static struct modtest_result xbee_ieee802154_set_channel_test(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x43, 0x41, 0x72 };
	const int count = 8;
	struct sk_buff* send_buf = NULL;
	unsigned char* tail = NULL;
	struct xb_device* xbdev = NULL;

	xbdev = (struct xb_device*)arg;
	xbee_cfg802154_set_channel(xbdev->phy, 0, 13);

	send_buf = alloc_skb(128, GFP_KERNEL);
	tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	ret = xb_sendrecv(xbdev, xbdev->frameid);

	FAIL_IF_ERROR(ret);

	//FAIL_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));
	//FAIL_NOT_EQ(0, xbdev->recv_buf->len);
	// TODO inspect received data

	TEST_SUCCESS();
}


#define TEST33 xbee_ieee802154_set_tx_power_test
static struct modtest_result xbee_ieee802154_set_tx_power_test(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x50, 0x4C, 0x5A };
	const int count = 8;
	struct sk_buff* send_buf = NULL;
	unsigned char* tail = NULL;
	struct xb_device* xbdev = NULL;

	xbdev = (struct xb_device*)arg;
	xbee_cfg802154_set_tx_power(xbdev->phy, 4);

	send_buf = alloc_skb(128, GFP_KERNEL);
	tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	ret = xb_sendrecv(xbdev, xbdev->frameid);

	FAIL_IF_ERROR(ret);

	//FAIL_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));

	//FAIL_NOT_EQ(0, xbdev->recv_buf->len);

	// TODO inspect received data

	TEST_SUCCESS();
}



#define TEST34 xbee_ieee802154_set_cca_ed_level_test
static struct modtest_result xbee_ieee802154_set_cca_ed_level_test(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x43, 0x41, 0x72 };
	const int count = 8;
	struct sk_buff* send_buf = NULL;
	unsigned char* tail = NULL;
	struct xb_device* xbdev = NULL;

	xbdev = (struct xb_device*)arg;
	xbee_cfg802154_set_cca_ed_level(xbdev->phy, 0x25);

	send_buf = alloc_skb(128, GFP_KERNEL);
	tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	ret = xb_sendrecv(xbdev, xbdev->frameid);

	FAIL_IF_ERROR(ret);

	//FAIL_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));

	//FAIL_NOT_EQ(0, xbdev->recv_buf->len);

	// TODO inspect received data

	TEST_SUCCESS();
}


#define TEST35 xbee_ieee802154_set_csma_params_test
static struct modtest_result xbee_ieee802154_set_csma_params_test(void* arg) {
	int ret = 0;
	const char buf[] =  { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x52, 0x4E, 0x56 };
	const int count = 8;
	const char buf2[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x52, 0x52, 0x52 };
	const int count2 = 8;
	struct sk_buff* send_buf = NULL;
	unsigned char* tail = NULL;
	struct xb_device* xbdev = NULL;
	struct xbee_sub_if_data *sdata = netdev_priv(xbdev->dev);
	xbdev = (struct xb_device*)arg;
	xbee_cfg802154_set_backoff_exponent(xbdev->phy, &sdata->wpan_dev, 2, 5);

	send_buf = alloc_skb(128, GFP_KERNEL);
	tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	send_buf = alloc_skb(128, GFP_KERNEL);
	tail = skb_put(send_buf, count);
	memcpy(tail, buf2, count2);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	ret = xb_sendrecv(xbdev, xbdev->frameid);

	FAIL_IF_ERROR(ret);

	//FAIL_NOT_EQ(1, skb_queue_len(&xbdev->send_queue));

	//FAIL_NOT_EQ(0, xbdev->recv_buf->len);

	// TODO inspect received data

	TEST_SUCCESS();
}
#endif

#include "gen_modtest.h"

#endif //MODTEST_ENABLE
