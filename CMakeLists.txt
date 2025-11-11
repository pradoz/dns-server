cmake_minimum_required(VERSION 3.10)
project(dns_server C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")

include_directories(include)

set(SOURCES
    src/dns_trie.c
    src/dns_records.c
    src/dns_parser.c
    src/dns_server.c
)

# main executable
add_executable(dns_server ${SOURCES})
target_link_libraries(dns_server pthread)

enable_testing()

# test library
set(LIB_SOURCES
    src/dns_trie.c
    src/dns_records.c
    src/dns_parser.c
)

add_library(dns_lib STATIC ${LIB_SOURCES})

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
