CODESIGN := codesign
CARGO := cargo

FUZZER := upng_fuzzer
FUZZER_RELEASE := target/release/$(FUZZER)

TARGET_DIR := $(PWD)/bin
TARGET_SRC_DIR := $(TARGET_DIR)/src
TARGET_PROGRAM := $(TARGET_DIR)/upng
INIT_CORPUS_DIR := ./corpus
TMP_DIR := ./tmp
CORPUS_DIR := "$(TMP_DIR)/corpus"
WORK_DIR := "$(TMP_DIR)/work"
TRACE_FILE := $(TMP_DIR)/trace.txt

.DEFAULT_GOAL := run
.PHONY: check

build-target:
	NDK_PATH=$(NDK_PATH) TARGET_DIR=$(TARGET_DIR) $(MAKE) -C $(TARGET_SRC_DIR) build

clean-target:
	TARGET_DIR=$(TARGET_DIR) $(MAKE) -C $(TARGET_SRC_DIR) clean

build:
	$(CARGO) fmt
	$(CARGO) clippy
	$(CARGO) build --release
	$(CODESIGN) --sign - --entitlements entitlements.xml --deep --force "$(FUZZER_RELEASE)"

run: build
	mkdir -p $(CORPUS_DIR)
	mkdir -p $(WORK_DIR)
	cp $(INIT_CORPUS_DIR)/* $(CORPUS_DIR)
	$(FUZZER_RELEASE) fuzz \
		--binary $(TARGET_PROGRAM) \
		--corpus $(CORPUS_DIR) \
		--size 0x10000000 \
		--workdir $(WORK_DIR) \
		--workers 4 \
		;

trace: build
	mkdir -p $(TMP_DIR)
	$(FUZZER_RELEASE) trace \
		--binary $(TARGET_PROGRAM) \
		--size 0x10000000 \
		--trace $(TRACE_FILE) \
		--testcase $(filter-out $@,$(MAKECMDGOALS)) \
		;

check:
	TARGET_DIR=$(TARGET_DIR) $(MAKE) -C $(TARGET_SRC_DIR) check $(PWD)/$(filter-out $@,$(MAKECMDGOALS))

clean-dirs:
	rm -rf $(CORPUS_DIR)
	rm -rf $(WORK_DIR)

clean: clean-dirs clean-target
	$(CARGO) clean
