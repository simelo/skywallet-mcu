#include "check_wrapper_calls.h"

#include <stdbool.h>

#include "check.h"

void assert_msg(bool condition, const char * format, ...) {
	ck_assert_msg(condition, format);
}

xUnitTest create_test_framework_wrapper() {
	xUnitTest chech_test_wrapper;
	chech_test_wrapper.assert_msg = assert_msg;
	return chech_test_wrapper;
}
