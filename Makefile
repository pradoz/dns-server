BUILD_DIR = build

TESTS = test_dns_trie test_dns_records test_dns_parser

.PHONY: all build test test-verbose example clean run

all: build

build:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && $(MAKE)

define run_ctest
	@cd $(BUILD_DIR) && ctest -R $(subst -,_,$(1)) $(2)
endef

test-%: build
	$(call run_ctest,$*,--output-on-failure)

test-%-verbose: build
	$(call run_ctest,$*,-V)

test: build $(addprefix test-,$(subst test_,,$(TESTS)))

test-verbose: build $(addprefix test-,$(addsuffix -verbose,$(subst test_,,$(TESTS))))

run: build
	@$(BUILD_DIR)/dns_server

clean:
	@rm -rf $(BUILD_DIR)
	@rm -rf test/CMakeFiles test/cmake_install.cmake test/CTestTestfile.cmake test/Makefile

