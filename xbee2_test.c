#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define TEST_SETUP xbee_test_setup
int xbee_test_setup(void* arg, int testno) {
	struct xb_device* xbdev = NULL;
	xbdev = (struct xb_device*)arg;
	skb_trim(xbdev->recv_buf, 0);
	skb_queue_purge(&xbdev->recv_queue);
	skb_queue_purge(&xbdev->send_queue);
	return 0;
}

#define TEST0 modtest_check
int modtest_check(void* arg) {
	return 0;
}

#define TEST1 buffer_calc_checksum_zero
int buffer_calc_checksum_zero(void* arg) {
	const char buf[] = {};
	const int count = 0;
	int ret = 0;
	ret = buffer_calc_checksum(buf, count);
	if(ret != 0xFF) return -1;
	return 0;
}

#define TEST2 buffer_calc_checksum_example
int buffer_calc_checksum_example(void* arg) {
	const char buf[] = {0x23, 0x11};
	const int count = 2;
	int ret = 0;
	ret = buffer_calc_checksum(buf, count);
	if(ret != 0xCB) return -1;
	return 0;
}

#define TEST3 buffer_find_delimiter_exists
int buffer_find_delimiter_exists(void* arg) {
	const char buf[] = {0x23, 0x7E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_unescaped(buf, count);
	if(ret != 1) return -1;
	return 0;
}


#define TEST4 buffer_find_delimiter_non_exists
int buffer_find_delimiter_non_exists(void* arg) {
	const char buf[] = {0x23, 0x70, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_unescaped(buf, count);
	if(ret != -1) return -1;
	return 0;
}

#define TEST5 buffer_find_delimiter_escaped_exists
int buffer_find_delimiter_escaped_exists(void* arg) {
	const char buf[] = {0x23, 0x7E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);
	if(ret != 1) return -1;
	return 0;
}


#define TEST6 buffer_find_delimiter_escaped_non_exists
int buffer_find_delimiter_escaped_non_exists(void* arg) {
	const char buf[] = {0x23, 0x70, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);
	if(ret != -1) return -1;
	return 0;
}


#define TEST7 buffer_find_delimiter_escaped_exists_escape
int buffer_find_delimiter_escaped_exists_escape(void* arg) {
	const char buf[] = {0x23, 0x7D, 0x5E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);
	if(ret != 1) return -1;
	return 0;
}

#define TEST8 buffer_find_delimiter_escaped_non_exists_escape
int buffer_find_delimiter_escaped_non_exists_escape(void* arg) {
	const char buf[] = {0x23, 0x7D, 0x31, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);
	if(ret != -1) return -1;
	return 0;
}


#define TEST9 buffer_unescape_zero
int buffer_unescape_zero(void* arg) {
	char buf[] = {};
	const int count = 0;
	int ret = 0;
	ret = buffer_unescape(buf, count);
	if(ret != 0) return -1;
	return 0;
}

#define TEST10 buffer_unescape_example
int buffer_unescape_example(void* arg) {
	char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB};
	char ans[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB};
	const int count = 7;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	if(ret != 6) return -1;
	if( memcmp(buf, ans, 6) != 0) return -1;
	return 0;
}

#define TEST11 buffer_unescape_end_escape
int buffer_unescape_end_escape(void* arg) {
	char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0x7D};
	char ans[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0x7D};
	const int count = 7;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	if(ret != 6) return -1;
	if( memcmp(buf, ans, 6) != 0) return -1;
	return 0;
}

#define TEST12 frame_new_test
int frame_new_test(void* arg) {
	struct sk_buff* skb = frame_new(9, 0x0F);
	struct xb_frameheader* frm = NULL;

	frm = (struct xb_frameheader*)skb->data;

	if(skb->data[0] != 0x7E) return -1;
	if(skb->data[1] != 0x00) return -1;
	if(skb->data[2] != 0x0a) return -1;
	if(skb->data[3] != 0x0F) return -1;

	return 0;
}

#define TEST13 frame_calc_checksum_zero
int frame_calc_checksum_zero(void* arg) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	const char buf[] = {0x7E, 0x00, 0x00 };
	const int count = 3;
	int ret = 0;
	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_calc_checksum(xbdev->recv_buf);
	if(ret != 0xFF) return -1;
	return 0;
}

#define TEST14 frame_calc_checksum_example
int frame_calc_checksum_example(void* arg) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	const char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB};
	const int count = 6;
	int ret = 0;
	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_calc_checksum(xbdev->recv_buf);
	if(ret != 0xCB) return -1;
	return 0;
}

#define TEST15 frame_verify_zerobyte
int frame_verify_zerobyte(void* arg) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;
	ret = frame_verify(xbdev->recv_buf);

	if(ret != -EAGAIN) return -1;

	return 0;
}

#define TEST16 frame_verify_non_startmark
int frame_verify_non_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x11 };
	const int count = 1;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	if(ret != -EINVAL) return -1;

	return 0;
}

#define TEST17 frame_verify_startmark
int frame_verify_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e };
	const int count = 1;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	if(ret != -EAGAIN) return -1;

	return 0;
}

#define TEST18 frame_verify_length_zero
int frame_verify_length_zero(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00 };
	const int count = 3;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	if(ret != -EAGAIN) return -1;

	return 0;
}

#define TEST19 frame_verify_length_zero_invalid
int frame_verify_length_zero_invalid(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFE };
	const int count = 4;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	if(ret != -EINVAL) return -1;

	return 0;
}


#define TEST20 frame_verify_length_zero_valid
int frame_verify_length_zero_valid(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFF };
	const int count = 4;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	if(ret != 4) return -1;

	return 0;
}

#define TEST21 frame_verify_length_zero_valid_large
int frame_verify_length_zero_valid_large(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFF, 0x01};
	const int count = 5;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	if(ret != 4) return -1;

	return 0;
}


#define TEST22 frame_verify_valid_example
int frame_verify_valid_example(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	if(ret != 6) return -1;

	return 0;
}

#define TEST23 frame_enqueue_zerobyte
int frame_enqueue_zerobyte(void* arg) {
	int ret = 0;
	const char buf[] = {};
	const int count = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret != 0) return -1;

	if(skb_queue_len(&xbdev->recv_queue) != 0) return -1;

	if(xbdev->recv_buf->len != 0) return -1;
	return 0;
}

#define TEST24 frame_enqueue_non_startmark
int frame_enqueue_non_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x11 };
	const int count = 1;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret != 0) return -1;

	if(skb_queue_len(&xbdev->recv_queue) != 0) return -1;

	if(xbdev->recv_buf->len != 0) return -1;
	return 0;
}

#define TEST25 frame_enqueue_startmark
int frame_enqueue_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e };
	const int count = 1;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret != 0) return -1;

	if(skb_queue_len(&xbdev->recv_queue) != 0) return -1;

	if(xbdev->recv_buf->len != 1) return -1;
	return 0;
}

#define TEST26 frame_enqueue_startmark_len
int frame_enqueue_startmark_len(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e , 0x00, 0x3 };
	const int count = 3;
	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret != 0) return -1;

	if(skb_queue_len(&xbdev->recv_queue) != 0) return -1;

	if(xbdev->recv_buf->len != 3) return -1;
	return 0;
}

#define TEST27 frame_enqueue_valid_example
int frame_enqueue_valid_example(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret != 1) return -1;

	if(skb_queue_len(&xbdev->recv_queue) != 1) return -1;

	if(xbdev->recv_buf->len != 0) return -1;

	return 0;
}


#define TEST28 frame_enqueue_valid_example_two
int frame_enqueue_valid_example_two(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB,  0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 12;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret != 2) return -1;

	if(skb_queue_len(&xbdev->recv_queue) != 2) return -1;

	if(xbdev->recv_buf->len != 0) return -1;

	return 0;
}


#define TEST29 frame_enqueue_valid_partial
int frame_enqueue_valid_partial(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB, 0x7E };
	const int count = 7;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret != 1) return -1;

	if(skb_queue_len(&xbdev->recv_queue) != 1) return -1;

	if(xbdev->recv_buf->len != 1) return -1;

	return 0;
}


#define TEST30 frame_enqueue_valid_invalid
int frame_enqueue_valid_invalid(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB, 0x11 };
	const int count = 7;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_enqueue_received(&xbdev->recv_queue, xbdev->recv_buf);

	if(ret != 1) return -1;

	if(skb_queue_len(&xbdev->recv_queue) != 1) return -1;

	if(xbdev->recv_buf->len != 0) return -1;

	return 0;
}

#define TEST31 frame_enqueue_send_vr
int frame_enqueue_send_vr(void* arg) {
	//int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x56, 0x52, 0x4E };
	const int count = 8;

	struct xb_device* xbdev = (struct xb_device*)arg;
	struct sk_buff* send_buf = alloc_skb(128, GFP_KERNEL);

	unsigned char* tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	//if(ret != 1) return -1;

	if(skb_queue_len(&xbdev->send_queue) != 1) return -1;

	if(xbdev->recv_buf->len != 0) return -1;

	return 0;
}

#if 0
#define TEST32 xb_process_sendrecv_vr
int xb_process_sendrecv_vr(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x56, 0x52, 0x4E };
	const int count = 8;

	struct xb_device* xbdev = (struct xb_device*)arg;
	struct sk_buff* send_buf = alloc_skb(128, GFP_KERNEL);

	unsigned char* tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	xb_process_sendrecv(xbdev);

	//if(ret != 1) return -1;

	if(skb_queue_len(&xbdev->send_queue) != 1) return -1;

	if(xbdev->recv_buf->len != 0) return -1;

	return 0;
}
#endif

#define TEST32 xbee_ieee802154_set_channel_test
int xbee_ieee802154_set_channel_test(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x04, 0x08, 0x01, 0x43, 0x41, 0x72 };
	const int count = 8;
	struct sk_buff* send_buf = NULL;
	unsigned char* tail = NULL;
	struct xb_device* xbdev = NULL;

	xbdev = (struct xb_device*)arg;
	xbee_ieee802154_set_channel((struct ieee802154_hw*)xbdev->dev, 0, 13);

	send_buf = alloc_skb(128, GFP_KERNEL);
	tail = skb_put(send_buf, count);
	memcpy(tail, buf, count);
	frame_enqueue_send(&xbdev->send_queue, send_buf);

	ret = xb_process_sendrecv(xbdev);

	//if(ret != 1) return -1;

	//if(skb_queue_len(&xbdev->send_queue) != 1) return -1;

	//if(xbdev->recv_buf->len != 0) return -1;

	// TODO inspect received data

	return 0;
}


#include "gen_modtest.h"

#endif //MODTEST_ENABLE
