#ifndef MODTEST_H
#define MODTEST_H

struct modtest_result {
	uint32_t testno;
	int err;
	unsigned int line;
	char* msg;
};

typedef struct modtest_result (*fp_modtest)(void* data);
typedef int (*fp_setup_teardown)(void* arg, int testnum);

extern const size_t modtest_tests_num;
extern const fp_setup_teardown modtest_setup;
extern const fp_modtest modtest_tests[];
extern const fp_setup_teardown modtest_teardown;

#define DECL_TESTS_ARRAY() \
	const fp_setup_teardown modtest_setup    = MODTEST_SETUP; \
	const fp_setup_teardown modtest_teardown = MODTEST_TEARDOWN; \
	const fp_modtest modtest_tests[] = MODTEST_TESTS; \
	const size_t modtest_tests_num = sizeof(modtest_tests)/sizeof(fp_modtest);

#define RETURN_RESULT(err, line, msg) { struct modtest_result _rslt_ = {0, err,line,msg}; return _rslt_; }

#define PR_EXPECTED(expected, val) \
	{    if(sizeof(val) < 2) { pr_debug("expected:%02x(%d), result: %02x(%d)\n", (uint8_t)expected,(int8_t)expected,  (uint8_t)val, (int8_t)val); } \
	else if(sizeof(val) < 4) { pr_debug("expected:%04x(%d), result: %04x(%d)\n", (uint16_t)expected,(int16_t)expected,  (uint16_t)val, (int16_t)val); } \
	else if(sizeof(val) < 8) { pr_debug("expected:%08x(%d), result: %08x(%d)\n", (uint32_t)expected,(int32_t)expected,  (uint32_t)val, (int32_t)val); } \
	else /* size == 8 */ { pr_debug("expected:%016llx(%lld), result: %016llx(%lld)\n", (uint64_t)expected,(int64_t)expected,  (uint64_t)val, (int64_t)val); } }

#define FAIL_IF_NOT_EQ(expected, val) if(expected != val) { PR_EXPECTED(expected,val); RETURN_RESULT(-1, __LINE__, ""); }
#define FAIL_IF_ERROR(err) if((err) < 0) RETURN_RESULT(err, __LINE__, "") 
#define FAIL_IF_NOT_ERROR(err) if(!((err) < 0)) RETURN_RESULT(err, __LINE__, "")
#define FAIL_IF_NULL(obj) if((!obj)) RETURN_RESULT(-1, __LINE__, "")
#define FAIL_IF(cond) if((cond)) RETURN_RESULT(-1, __LINE__, "")
#define TEST_IS_NULL(obj) { return (((obj)) == NULL) ? 0 : -1; }
#define TEST_FAIL() RETURN_RESULT(-1, __LINE__, "")
#define TEST_ERROR(err) RETURN_RESULT(err, __LINE__, "")
#define TEST_SUCCESS() RETURN_RESULT(0, __LINE__, "")



#if defined(MODTEST_ENABLE) && MODTEST_ENABLE
static int setup_teardown_default(void* arg, int testnum) { return 0; }

static void modtest_test(int testno, void* data, struct modtest_result* result)
{
	modtest_setup(data, testno);
	*result = modtest_tests[testno](data);
	result->testno = testno;
	modtest_teardown(data, testno);
}
#endif



#endif


