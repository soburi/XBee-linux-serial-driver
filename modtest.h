#ifndef MODTEST_H
#define MODTEST_H


struct modtest_result {
	int err;
	unsigned int line;
	char* msg;
};

typedef struct modtest_result (*fp_modtest)(void* data);
typedef int (*fp_setup_teardown)(void* arg, int testnum);

struct modtest {
	struct delayed_work work;
	struct workqueue_struct *workq;
	size_t test_num;
	size_t null_test_count;
	size_t test_count;
	size_t test_success;
	const fp_modtest* tests;
	fp_setup_teardown setup;
	fp_setup_teardown teardown;
	void* data;
	void* arg;
};

extern const size_t modtest_tests_num;
extern const fp_setup_teardown modtest_setup;
extern const fp_modtest modtest_tests[];
extern const fp_setup_teardown modtest_teardown;

static void modtest_work_fn(struct work_struct *param)
{
	int err = 0;
	struct modtest_result result = {0};
	struct modtest * mt = NULL;
	mt = (struct modtest*)param;

	if(mt->test_count < mt->test_num) {
		int delay = 0;
		if(mt->tests[mt->test_count] != NULL) {
			mt->setup(mt->data, mt->test_count);
			result = mt->tests[mt->test_count](mt->data);
			mt->teardown(mt->data, mt->test_count);

			if(result.err < 0)
				pr_debug("TEST%lu: line=%u err=%d -- %s\n", mt->test_count, result.line, result.err, result.msg);
			else
				mt->test_success++;

			delay = 100;
		}
		else {
			mt->null_test_count++;
			delay = 0;
		}

		mt->test_count++;
		err = queue_delayed_work(mt->workq, &mt->work, msecs_to_jiffies(delay) );
	}
	else {
		pr_debug("Finish test: %lu/%lu\n", mt->test_success, mt->test_num - mt->null_test_count);
	}
}

static int setup_teardown_default(void* arg, int testnum) { return 0; }

#if defined(MODTEST_ENABLE) && MODTEST_ENABLE

#define DECL_MODTEST_STRUCT() struct modtest _modtest_

#define INIT_MODTEST(parent) { \
	parent->_modtest_.workq = create_workqueue("_modtest_"); \
	INIT_DELAYED_WORK( (struct delayed_work*)&parent->_modtest_, modtest_work_fn); \
	parent->_modtest_.data = parent; \
	parent->_modtest_.test_num = modtest_tests_num; \
	parent->_modtest_.setup = modtest_setup; \
	parent->_modtest_.tests = modtest_tests; \
	parent->_modtest_.teardown = modtest_teardown ; \
	parent->_modtest_.test_success = 0; \
	parent->_modtest_.test_count = 0; \
	parent->_modtest_.null_test_count = 0; \
}

#define DECL_TESTS_ARRAY() \
	const fp_setup_teardown modtest_setup    = MODTEST_SETUP; \
	const fp_setup_teardown modtest_teardown = MODTEST_TEARDOWN; \
	const fp_modtest modtest_tests[] = MODTEST_TESTS; \
	const size_t modtest_tests_num = sizeof(modtest_tests)/sizeof(fp_modtest);

#define RUN_MODTEST(parent) \
	queue_work(parent->_modtest_.workq, (struct work_struct*)&xb->_modtest_)

#define ALL_MODTESTS {}

#define RETURN_RESULT(err, line, msg) { struct modtest_result _rslt_ = {err,line,msg}; return _rslt_; }

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

#else

#define DECL_MODTEST_STRUCT()
#define INIT_MODTEST(parent)
#define RUN_MODTEST(parent)

#endif /* MODTEST_ENABLE */

#endif


