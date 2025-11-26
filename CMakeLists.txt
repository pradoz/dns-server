cmake_minimum_required(VERSION 3.10)
project(dns_server C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")

include_directories(include)

# library sources (without main)
set(LIB_SOURCES
  src/dns_trie.c
  src/dns_records.c
  src/dns_parser.c
  src/dns_error.c
  src/dns_resolver.c
  src/dns_server.c
  src/dns_zone_file.c
  src/dns_recursive.c
  src/dns_cache.c
)

# main executable sources
set(MAIN_SOURCES
  src/main.c
)

# create library
add_library(dns_lib STATIC ${LIB_SOURCES})

# main executable
add_executable(dns_server ${MAIN_SOURCES})
target_link_libraries(dns_server dns_lib pthread)

enable_testing()

# test executables
add_executable(test_dns_trie test/test_dns_trie.c test/munit/munit.c)
target_link_libraries(test_dns_trie dns_lib)
target_include_directories(test_dns_trie PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_trie COMMAND test_dns_trie)

add_executable(test_dns_records test/test_dns_records.c test/munit/munit.c)
target_link_libraries(test_dns_records dns_lib)
target_include_directories(test_dns_records PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_records COMMAND test_dns_records)

add_executable(test_dns_parser test/test_dns_parser.c test/munit/munit.c)
target_link_libraries(test_dns_parser dns_lib)
target_include_directories(test_dns_parser PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_parser COMMAND test_dns_parser)

add_executable(test_dns_resolver test/test_dns_resolver.c test/munit/munit.c)
target_link_libraries(test_dns_resolver dns_lib)
target_include_directories(test_dns_resolver PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_resolver COMMAND test_dns_resolver)

add_executable(test_dns_server test/test_dns_server.c test/munit/munit.c)
target_link_libraries(test_dns_server dns_lib)
target_include_directories(test_dns_server PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_server COMMAND test_dns_server)

add_executable(test_dns_zone_file test/test_dns_zone_file.c test/munit/munit.c)
target_link_libraries(test_dns_zone_file dns_lib)
target_include_directories(test_dns_zone_file PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_zone_file COMMAND test_dns_zone_file)

add_executable(test_dns_recursive test/test_dns_recursive.c test/munit/munit.c)
target_link_libraries(test_dns_recursive dns_lib)
target_include_directories(test_dns_recursive PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_recursive COMMAND test_dns_recursive)

add_executable(test_dns_bugs test/test_dns_bugs.c test/munit/munit.c)
target_link_libraries(test_dns_bugs dns_lib)
target_include_directories(test_dns_bugs PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_bugs COMMAND test_dns_bugs)

add_executable(test_dns_cache test/test_dns_cache.c test/munit/munit.c)
target_link_libraries(test_dns_cache dns_lib)
target_include_directories(test_dns_cache PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/test/munit
)
add_test(NAME test_dns_cache COMMAND test_dns_cache)
