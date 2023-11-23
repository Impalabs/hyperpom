CODESIGN := codesign
CARGO := cargo +nightly

TARGET := hyperpom
TARGET_DEBUG := target/debug/$(TARGET)
TARGET_RELEASE := target/release/$(TARGET)

TMP_DIR := ./tmp
CORPUS_DIR := "$(TMP_DIR)/corpus"
WORK_DIR := "$(TMP_DIR)/work"

ENTITLEMENTS := entitlements.xml

build-debug:
	$(CARGO) fmt
	$(CARGO) build

build-release:
	$(CARGO) fmt
	$(CARGO) build --release

build-test:
	$(CARGO) test --no-run
	$(CODESIGN) --sign - --entitlements "$(ENTITLEMENTS)" --deep --force \
		$(shell $(CARGO) test --no-run --message-format=json | \
			jq -r "select(.profile.test == true) | .filenames[]")

build-test-release:
	$(CARGO) test --no-run --release
	$(CODESIGN) --sign - --entitlements "$(ENTITLEMENTS)" --deep --force \
		$(shell $(CARGO) test --no-run --release --message-format=json | \
			jq -r "select(.profile.test == true) | .filenames[]")

tmp-dirs:
	mkdir -p $(CORPUS_DIR)
	mkdir -p $(WORK_DIR)

test: clean-dirs tmp-dirs build-test
	$(CARGO) test $(filter-out $@,$(MAKECMDGOALS)) -- --nocapture \
		--test-threads=1

tests: clean-dirs tmp-dirs build-test
	$(CARGO) test --tests -- --nocapture --test-threads=1

tests-release: build-test-release
	$(CARGO) test --release --tests -- --nocapture --test-threads=1

tests-threads: build-test
	$(CARGO) test --tests -- --nocapture

clean-dirs:
	rm -rf $(CORPUS_DIR)
	rm -rf $(WORK_DIR)

clean: clean-dirs
	$(CARGO) clean
