CODESIGN := codesign
CARGO := cargo

FUZZER := simple_fuzzer
FUZZER_RELEASE := target/release/$(FUZZER)

TARGET_DIR := ./bin
TARGET_PROGRAM := "$(TARGET_DIR)/simple_program"
TMP_DIR := ./tmp
CORPUS_DIR := "$(TMP_DIR)/corpus"
WORK_DIR := "$(TMP_DIR)/work"

.DEFAULT_GOAL := run

build-target:
	$(MAKE) -C $(TARGET_DIR) build

clean-target:
	$(MAKE) -C $(TARGET_DIR) clean

build:
	$(CARGO) fmt
	$(CARGO) clippy
	$(CARGO) build --release
	$(CODESIGN) --sign - --entitlements entitlements.xml --deep --force "$(FUZZER_RELEASE)"

run: clean-dirs build
	mkdir -p $(CORPUS_DIR)
	mkdir -p $(WORK_DIR)
	$(FUZZER_RELEASE) fuzz

clean-dirs:
	rm -rf $(CORPUS_DIR)
	rm -rf $(WORK_DIR)

clean: clean-dirs clean-target
	$(CARGO) clean
