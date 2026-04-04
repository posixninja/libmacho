/**
 * tests/test_framework.h - Minimal test assertion framework for libmacho.
 *
 * Usage:
 *   static void test_something(void) {
 *       TEST_ASSERT(1 == 1, "one equals one");
 *       TEST_ASSERT_EQ(x, y, "x equals y");
 *   }
 *   int main(void) {
 *       RUN_TEST(test_something);
 *       return test_report();
 *   }
 */
#ifndef TEST_FRAMEWORK_H_
#define TEST_FRAMEWORK_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int _pass_count = 0;
static int _fail_count = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (cond) { \
            printf("  PASS: %s\n", msg); \
            _pass_count++; \
        } else { \
            printf("  FAIL: %s [%s:%d]\n", msg, __FILE__, __LINE__); \
            _fail_count++; \
        } \
    } while (0)

#define TEST_ASSERT_NULL(ptr, msg)     TEST_ASSERT((ptr) == NULL, msg)
#define TEST_ASSERT_NOT_NULL(ptr, msg) TEST_ASSERT((ptr) != NULL, msg)
#define TEST_ASSERT_EQ(a, b, msg)      TEST_ASSERT((a) == (b), msg)
#define TEST_ASSERT_STREQ(a, b, msg)   TEST_ASSERT(strcmp((a), (b)) == 0, msg)

#define RUN_TEST(name) \
    do { \
        printf("\n[TEST] %s\n", #name); \
        name(); \
    } while (0)

static int test_report(void)
{
    printf("\n=== Results: %d passed, %d failed ===\n",
           _pass_count, _fail_count);
    return _fail_count > 0 ? 1 : 0;
}

#endif /* TEST_FRAMEWORK_H_ */
