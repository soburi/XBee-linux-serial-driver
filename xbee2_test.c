#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define TEST_SETUP xbee_test_setup
int xbee_test_setup(void* arg, int testno) {
	struct xb_device* xbdev = NULL;
	xbdev = (struct xb_device*)arg;
	skb_trim(xbdev->recv_buf, xbdev->recv_buf->len);
	return 0;
}

#define TEST0 modtest_check
int modtest_check(void* arg) {
	return 0;
}

#define TEST1 frame_enqueue_zerobyte
int frame_enqueue_zerobyte(void* arg) {
	int ret = 0;
	const char buf[] = {};
	struct xb_device* xbdev = (struct xb_device*)arg;
	ret = frame_enqueue(xbdev, buf, 0);
	if(ret != 0) return -1;

	if(xbdev->recv_buf->len != 0) return -1;
	return 0;
}

#define TEST2 frame_enqueue_non_startmark
int frame_enqueue_non_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x11 };
	struct xb_device* xbdev = (struct xb_device*)arg;
	ret = frame_enqueue(xbdev, buf, 1);
	if(ret != 0) return -1;

	if(xbdev->recv_buf->len != 0) return -1;
	return 0;
}

#define TEST3 frame_enqueue_startmark
int frame_enqueue_startmark(void* arg) {
	int ret = 0;
	const char buf[] = { 0x7e };
	struct xb_device* xbdev = (struct xb_device*)arg;
	ret = frame_enqueue(xbdev, buf, 1);
	if(ret != 0) return -1;

	if(xbdev->recv_buf->len != 1) return -1;
	return 0;
}

#include "gen_modtest.h"

#endif //MODTEST_ENABLE
