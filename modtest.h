#ifndef MODTEST_H
#define MODTEST_H


struct modtest_result {
	int err;
	int line;
	char* msg;
};

//typedef struct modtest_result (*fp_modtest)(void* data);
typedef int (*fp_modtest)(void* data);
typedef int (*fp_setup_teardown)(void* arg, int testnum);

struct modtest {
	struct work_struct work;
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
		if(mt->tests[mt->test_count] != NULL) {
			mt->setup(mt->data, mt->test_count);
			//result = mt->tests[mt->test_count](mt->data);
			err = mt->tests[mt->test_count](mt->data);
			mt->teardown(mt->data, mt->test_count);

			if(err < 0)
				pr_debug("TEST%lu: error=%d\n", mt->test_count, err);
			//if(result->err < 0)
			//	pr_debug("TEST%lu: line=%05d err=%d -- %s\n", mt->test_count, result->err, result->line, result->msg);
			else
				mt->test_success++;
		}
		else {
			mt->null_test_count++;
		}

		mt->test_count++;
		err = queue_work(mt->workq, &mt->work);
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
	INIT_WORK( (struct work_struct*)&parent->_modtest_, modtest_work_fn); \
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
	queue_work(parent->_modtest_.workq, (struct work_struct*)&xbdev->_modtest_)

#define ALL_MODTESTS {}

#define TEST_IS_TRUE(cond) { return ((cond)) ? 0 : -1; }
#define TEST_IS_NULL(obj) { return (((obj)) == NULL) ? 0 : -1; }
#define TEST_FAIL() { return -1; }
#define TEST_ERROR(err) { return err; }
#define TEST_SUCCESS() { return 0; }

#else

#define DECL_MODTEST_STRUCT()
#define INIT_MODTEST(parent)
#define RUN_MODTEST(parent)

#endif /* MODTEST_ENABLE */

#endif


