-include Makefile.local # for optional local options

DOC_SOURCE::= src/openid_connect.cr

# The shards command to use
SHARDS ?= shards
# The crystal command to use
CRYSTAL ?= crystal

BIN ::= bin

SRC_SOURCES ::= $(shell find src -name '*.cr' 2>/dev/null)
LIB_SOURCES ::= $(shell find lib -name '*.cr' 2>/dev/null)
SPEC_SOURCES ::= $(shell find spec -name '*.cr' 2>/dev/null)
EXAMPLE_SOURCES ::= $(shell find examples -name '*.cr' 2>/dev/null)
EXAMPLES ::= $(subst examples/,$(BIN)/,$(subst .cr,,$(EXAMPLE_SOURCES)))

.PHONY: test
test: ## Run the test suite
test: lib build_examples
	$(CRYSTAL) spec

.PHONY: build_examples
build_examples: $(EXAMPLES)

$(BIN)/%: examples/%.cr $(SRC_SOURCES) lib
	@mkdir -p $(BIN)
	$(CRYSTAL) build $< -o $@

.PHONY: format
format: ## Apply source code formatting
format: $(SRC_SOURCES) $(SPEC_SOURCES) $(EXAMPLE_SOURCES)
	$(CRYSTAL) tool format src spec examples

docs: ## Generate API docs
docs: $(SRC_SOURCES) lib
	$(CRYSTAL) docs -o docs $(DOC_SOURCE)

lib: shard.lock
	$(SHARDS) install

shard.lock: shard.yml
	$(SHARDS) update

.PHONY: clean
clean: ## Remove application binary
clean:
	@rm -f $(BUILD_TARGET) $(EXAMPLES)

.PHONY: help
help: ## Show this help
	@echo
	@printf '\033[34mtargets:\033[0m\n'
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) |\
		sort |\
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo
	@printf '\033[34moptional variables:\033[0m\n'
	@grep -hE '^[a-zA-Z_-]+ \?=.*?## .*$$' $(MAKEFILE_LIST) |\
		sort |\
		awk 'BEGIN {FS = " \\?=.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo
	@printf '\033[34mrecipes:\033[0m\n'
	@grep -hE '^##.*$$' $(MAKEFILE_LIST) |\
		awk 'BEGIN {FS = "## "}; /^## [a-zA-Z_-]/ {printf "  \033[36m%s\033[0m\n", $$2}; /^##  / {printf "  %s\n", $$2}'
