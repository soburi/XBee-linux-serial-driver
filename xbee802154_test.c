#include "modtest.h"

#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define TEST_SETUP xbee_test_setup
static int xbee_test_setup(void* arg, int testno) {
	return 0;
}

#define TEST0 modtest_fail_check
void modtest_fail_check(void* arg, struct modtest_result* result) {
	TEST_FAIL();
}
#define TEST2 buffer_calc_checksum_zero
void buffer_calc_checksum_zero(void* arg, struct modtest_result* result) {
	const char buf[] = {};
	const int count = 0;
	int ret = 0;
	ret = buffer_calc_checksum(buf, count);

	FAIL_IF_NOT_EQ(0xFF, ret);

	TEST_SUCCESS();
}

#define TEST3 buffer_calc_checksum_example
void buffer_calc_checksum_example(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x11};
	const int count = 2;
	int ret = 0;
	ret = buffer_calc_checksum(buf, count);
	
	FAIL_IF_NOT_EQ(0xCB, ret);
	TEST_SUCCESS();
}

#define TEST4 buffer_escaped_len_exampe
void buffer_escaped_len_exampe(void* arg, struct modtest_result* result) {
	const char buf[] =    { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const char escbuf[] = { 0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB };

	size_t esclen = buffer_escaped_len(buf, sizeof(buf) );

	FAIL_IF_NOT_EQ(sizeof(escbuf), esclen);

	TEST_SUCCESS();
}

#define TEST5 buffer_escape_exampe
void buffer_escape_exampe(void* arg, struct modtest_result* result) {
	char buf[] =		{ 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB, 0x00 };
	const char escbuf[] =	{ 0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB };
	size_t esclen = 0;
	int err;

	//pr_debug("bufsize %lu", sizeof(buf) );

	esclen = buffer_escaped_len(buf, 5);
	err = buffer_escape(buf, 5, esclen);

	print_hex_dump_bytes("buf: ", DUMP_PREFIX_NONE, buf, 6);
	print_hex_dump_bytes("esc: ", DUMP_PREFIX_NONE, escbuf, 6);

	FAIL_IF_ERROR(err);
	FAIL_IF_NOT_EQ(0, memcmp(escbuf, buf, esclen) );

	TEST_SUCCESS();
}

#define TEST205 frame_escape_exampe
void frame_escape_exampe(void* arg, struct modtest_result* result) {
	char buf[] =		{ 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const char escbuf[] =	{ 0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB };
	struct sk_buff* skb = NULL;

	//pr_debug("bufsize %lu", sizeof(buf) );
	
	skb = dev_alloc_skb(sizeof(buf) );
	skb_put(skb, sizeof(buf) );
	memcpy(skb->data, buf, sizeof(buf) );

	print_hex_dump_bytes("skb: ", DUMP_PREFIX_NONE, skb->data, skb->len);
	frame_escape(skb);
	print_hex_dump_bytes("skb: ", DUMP_PREFIX_NONE, skb->data, skb->len);
	print_hex_dump_bytes("esc: ", DUMP_PREFIX_NONE, escbuf, sizeof(escbuf));

	//FAIL_IF_ERROR(err);
	FAIL_IF_NOT_EQ(sizeof(escbuf), skb->len);
	FAIL_IF_NOT_EQ(0, memcmp(escbuf, skb->data, sizeof(escbuf)) );

	TEST_SUCCESS();
}


#if 0
#define TEST6 buffer_find_delimiter_exists
void buffer_find_delimiter_exists(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x7E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_unescaped(buf, count);
	FAIL_IF_NOT_EQ(1, ret);
	TEST_SUCCESS();
}


#define TEST7 buffer_find_delimiter_non_exists
void buffer_find_delimiter_non_exists(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x70, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_unescaped(buf, count);
	FAIL_IF_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}
#endif

#define TEST8 buffer_find_delimiter_escaped_exists
void buffer_find_delimiter_escaped_exists(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x7E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_IF_NOT_EQ(1, ret);
	TEST_SUCCESS();
}


#define TEST9 buffer_find_delimiter_escaped_non_exists
void buffer_find_delimiter_escaped_non_exists(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x70, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_IF_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}


#define TEST10 buffer_find_delimiter_escaped_exists_escape
void buffer_find_delimiter_escaped_exists_escape(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x7D, 0x5E, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_IF_NOT_EQ(1, ret);
	TEST_SUCCESS();
}

#define TEST11 buffer_find_delimiter_escaped_non_exists_escape
void buffer_find_delimiter_escaped_non_exists_escape(void* arg, struct modtest_result* result) {
	const char buf[] = {0x23, 0x7D, 0x31, 0x11};
	const int count = 3;
	int ret = 0;
	ret = buffer_find_delimiter_escaped(buf, count);

	FAIL_IF_NOT_EQ(-1, ret);
	TEST_SUCCESS();
}


#define TEST12 buffer_unescape_zero
void buffer_unescape_zero(void* arg, struct modtest_result* result) {
	char buf[] = {};
	const int count = 0;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_IF_NOT_EQ(0, ret);
	TEST_SUCCESS();
}

#define TEST13 buffer_unescape_example
void buffer_unescape_example(void* arg, struct modtest_result* result) {
	char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0xCB};
	char ans[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB};
	const int count = 7;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_IF_NOT_EQ(6, ret);
	FAIL_IF_NOT_EQ(0,  memcmp(buf, ans, 6));
	TEST_SUCCESS();
}

#define TEST14 buffer_unescape_end_escape
void buffer_unescape_end_escape(void* arg, struct modtest_result* result) {
	char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x7D, 0x31, 0x7D};
	char ans[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0x7D};
	const int count = 7;
	int ret = 0;
	ret = buffer_unescape(buf, count);

	FAIL_IF_NOT_EQ(6, ret);
	FAIL_IF_NOT_EQ(0,  memcmp(buf, ans, 6));
	TEST_SUCCESS();
}

#define TEST15 frame_alloc_test
void frame_alloc_test(void* arg, struct modtest_result* result) {
	struct sk_buff* skb = frame_alloc(9, 0x0F, true);
	struct xb_frameheader* frm = NULL;

	frm = (struct xb_frameheader*)skb->data;

	FAIL_IF_NOT_EQ(0x7E, skb->data[0]);
	FAIL_IF_NOT_EQ(0x00, skb->data[1]);
	FAIL_IF_NOT_EQ(0x0a, skb->data[2]);
	FAIL_IF_NOT_EQ(0x0F, skb->data[3]);
	TEST_SUCCESS();
}

#define TEST16 frame_calc_checksum_zero
void frame_calc_checksum_zero(void* arg, struct modtest_result* result) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	const char buf[] = {0x7E, 0x00, 0x00 };
	const int count = 3;
	int ret = 0;
	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_calc_checksum(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(0xFF, ret);
	TEST_SUCCESS();
}

#define TEST17 frame_calc_checksum_example
void frame_calc_checksum_example(void* arg, struct modtest_result* result) {
	struct xb_device* xbdev = (struct xb_device*)arg;
	const char buf[] = {0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB};
	const int count = 6;
	int ret = 0;
	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);
	ret = frame_calc_checksum(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(0xCB, ret);
	TEST_SUCCESS();
}

#define TEST18 frame_verify_zerobyte
void frame_verify_zerobyte(void* arg, struct modtest_result* result) {
	int ret = 0;
	struct xb_device* xbdev = (struct xb_device*)arg;
	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST19 frame_verify_non_startmark
void frame_verify_non_startmark(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x11 };
	const int count = 1;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EINVAL, ret);
	TEST_SUCCESS();
}

#define TEST20 frame_verify_startmark
void frame_verify_startmark(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e };
	const int count = 1;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST21 frame_verify_length_zero
void frame_verify_length_zero(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00 };
	const int count = 3;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EAGAIN, ret);
	TEST_SUCCESS();
}

#define TEST22 frame_verify_length_zero_invalid
void frame_verify_length_zero_invalid(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFE };
	const int count = 4;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(-EINVAL, ret);
	TEST_SUCCESS();
}


#define TEST23 frame_verify_length_zero_valid
void frame_verify_length_zero_valid(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFF };
	const int count = 4;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(4, ret);
	TEST_SUCCESS();
}

#define TEST24 frame_verify_length_zero_valid_large
void frame_verify_length_zero_valid_large(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7e, 0x00, 0x00, 0xFF, 0x01};
	const int count = 5;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(4, ret);
	TEST_SUCCESS();
}


#define TEST25 frame_verify_valid_example
void frame_verify_valid_example(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x23, 0x11, 0xCB };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(6, ret);

	TEST_SUCCESS();
}

#define TEST125 frame_verify_modem_status
void frame_verify_modem_status(void* arg, struct modtest_result* result) {
	int ret = 0;
	const char buf[] = { 0x7E, 0x00, 0x02, 0x8A, 0x01, 0x74 };
	const int count = 6;

	struct xb_device* xbdev = (struct xb_device*)arg;

	unsigned char* tail = skb_put(xbdev->recv_buf, count);
	memcpy(tail, buf, count);

	ret = frame_verify(xbdev->recv_buf);

	FAIL_IF_NOT_EQ(6, ret);

	TEST_SUCCESS();
}



#include "gen_modtest.h"

DECL_TESTS_ARRAY();

#endif //MODTEST_ENABLE