#include <stdio.h>

#include <check.h>

#include "check_wrapper_calls.h"

xUnitTest chech_test_wrapper;


typedef struct {
  uint64_t  a;
  int64_t  b;
  int       failure;
} math_tests;

START_TEST(TestUint64ToInt64)
{
    int result;
    int64_t r;
    uint64_t maxUint64 = 0xFFFFFFFFFFFFFFFF;
    int64_t maxInt64 = 0x7FFFFFFFFFFFFFFF;

    math_tests tests[] = {
        {0, 0, 0},
        {1, 1, 0},
        {maxInt64, maxInt64, 0},
        {maxUint64, 0, 1},
        //This is reset to zero in C, and it doesn't fail
        //{maxUint64 + 1, 0, 1},
    };
    int tests_count = sizeof(tests) / sizeof(math_tests);
    for(int i = 0; i < tests_count; i++) {
//         result = SKY_coin_Uint64ToInt64(tests[i].a, &r);
        if (tests[i].failure) {
//           cr_assert(result == SKY_ErrUint64OverflowsInt64, "Failed test # %d", i + 1);
        } else {
			ck_assert_msg(result == 0, "Failed test # %d", i + 1);
			chech_test_wrapper.assert_msg(result == 0 + 1, "Failed test # %d", i + 1);
//           cr_assert(result == SKY_OK, "Failed test # %d", i + 1);
//           cr_assert( tests[i].b == r );
        }
    }
}
END_TEST

// define test suite and cases
Suite *test_suite(void)
{
    Suite *s = suite_create("hw_skycoin_crypto");
    TCase *tc;

    tc = tcase_create("checksums");
    tcase_add_test(tc, TestUint64ToInt64);
    suite_add_tcase(s, tc);

    return s;
}


// run suite
int main(void)
{
	chech_test_wrapper = create_test_framework_wrapper();
    int number_failed;
    Suite *s = test_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    if (number_failed == 0) {
        printf("PASSED ALL TESTS\n");
    }
    return number_failed;
}
