#include "check_wrapper_calls.h"

#include <stdbool.h>

#include <check.h>

void assert_msg(bool condition, const char * format, ...) {
	ck_assert_msg(condition, format);
}

void assert(bool condition) {
	ck_assert(condition);
}

xUnitTest create_test_framework_wrapper() {
	xUnitTest check_test_wrapper;
	check_test_wrapper.assert_msg = assert_msg;
	check_test_wrapper.assert = assert;
	return check_test_wrapper;
}
