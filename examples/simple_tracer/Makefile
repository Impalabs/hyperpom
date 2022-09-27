CODESIGN := codesign
CARGO := cargo

EXECUTOR := simple_tracer
EXECUTOR_RELEASE := target/release/$(EXECUTOR)
KEYCHAIN := $(CERT_KEYCHAIN)

.DEFAULT_GOAL := run

build:
	$(CARGO) fmt
	$(CARGO) clippy
	$(CARGO) build --release
	$(CODESIGN) --entitlements entitlements.xml -f -s "$(KEYCHAIN)" "$(EXECUTOR_RELEASE)"

run: build
	$(EXECUTOR_RELEASE)

clean:
	$(CARGO) clean
