BUILD_DIR = build

TESTS = test_dns_trie test_dns_records test_dns_parser test_dns_resolver test_dns_server test_dns_zone_file test_dns_recursive test_dns_bugs test_dns_cache test_dns_log

.PHONY: all build test test-verbose example clean run

all: build

build:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && $(MAKE)

define run_ctest
	@./$(BUILD_DIR)/$(addprefix test_,$(subst -,_,$(1)))
endef

define run_ctest_verbose
	@cd $(BUILD_DIR) && ctest -R $(subst -,_,$(1)) $(2)
endef

test-%: build
	$(call run_ctest,$*,--output-on-failure)

test-%-verbose: build
	$(call run_ctest_verbose,$*,-V)

test: build $(addprefix test-,$(subst test_,,$(TESTS)))

test-verbose: build $(addprefix test-,$(addsuffix -verbose,$(subst test_,,$(TESTS))))

run: build
	@$(BUILD_DIR)/dns_server

clean:
	@rm -rf $(BUILD_DIR)
