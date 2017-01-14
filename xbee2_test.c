#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define TEST1 modtest_check
int modtest_check(void* arg) {
	return 0;
}

#define TEST2 frame_enqueue_zerobyte
int frame_enqueue_zerobyte(void* arg) {
	int ret = 0;
	const char buf[] = {};
	struct xb_device* xbdev = (struct xb_device*)arg;
	ret = frame_enqueue(xbdev, buf, 0);
	if(ret != 0) return -1;

	if(xbdev->recv_buf->len != 0) return -1;
	return 0;
}

#include "gen_modtest.h"

#endif //MODTEST_ENABLE
