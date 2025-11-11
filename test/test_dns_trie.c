#include "munit.h"


static MunitResult test_foo(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/foo", test_foo, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/trie", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
