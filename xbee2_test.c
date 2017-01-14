#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define TEST1 modtest_check
int modtest_check(void* arg) {
	return 0;
}

#include "gen_modtest.h"

#endif //MODTEST_ENABLE
