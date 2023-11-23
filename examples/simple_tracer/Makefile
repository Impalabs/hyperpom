CODESIGN := codesign
CARGO := cargo +nightly

EXECUTOR := simple_tracer
EXECUTOR_RELEASE := target/release/$(EXECUTOR)

.DEFAULT_GOAL := run

build:
	$(CARGO) fmt
	$(CARGO) clippy
	$(CARGO) build --release
	$(CODESIGN) --sign - --entitlements entitlements.xml --deep --force "$(EXECUTOR_RELEASE)"

run: build
	$(EXECUTOR_RELEASE)

clean:
	$(CARGO) clean
