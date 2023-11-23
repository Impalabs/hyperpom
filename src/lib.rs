//! Apple Silicon hypervisor-based fuzzer for ARM64 binaries.
//!
//! ## Disclaimer
//!
//! The idea behind this project was to create an efficient and fast fuzzer that would leverage
//! Apple Silicon's features. However, at this stage, while the fuzzer works, it is still mostly a
//! proof of concept and requires tons of enhancement to provide better features, usability and
//! performances.
//!
//! It might be enough for your use cases, but keep in mind that you might encounter limitations
//! that weren't factored in while designing the project. In any case, feel free to
//! [open an issue](https://github.com/impalabs/hyperpom/issues) and we'll try to address your
//! problem.
//!
//! ## Hyperpom Internals & Usage
//!
//! If you want an in-depth guide on how to use this fuzzer, you can directly jump to the
//! chapter about the [`Loader`](loader::Loader), which provides different examples.
//!
//! Otherwise, if you want a better understanding of the fuzzer's implementation and the
//! interactions between its components, it is recommended to read the documentation in the
//! following order.
//!
//! 1. Memory Management
//!     1. [Physical Memory Allocator](memory::PhysMemAllocator)
//!     2. [Slab Allocator](memory::SlabAllocator)
//!     3. [Page Table Manager](memory::PageTableManager)
//!     4. [Virtual Memory Allocator](memory::VirtMemAllocator)
//!  2. [Exception Handling](exceptions::Exceptions)
//!  3. [Cache Maintenance](caches::Caches)
//!  4. [Hooks](hooks::Hooks)
//!  5. [Coverage](coverage::GlobalCoverage)
//!  6. [Tracing](tracer::Tracer)
//!  7. [Corpus](corpus::Corpus)
//!  8. [Mutator](mutator::Mutator)
//!  9. Fuzzer's Core
//!     1. [HyperPom](core::HyperPom)
//!     2. [Worker](core::Worker)
//!     3. [Executor](core::Executor)
//!  10. [Config](config::Config)
//!  11. [Loader](loader::Loader)
//!
//! ## Getting Started
//!
//! ### Prerequisites
//!
//! 1. Install Rust and `rustup` using the
//!    [official guide](https://www.rust-lang.org/tools/install).
//! 2. Install the [nightly channel](https://rust-lang.github.io/rustup/concepts/channels.html).
//!
//! ```
//! rustup toolchain install nightly
//! ```
//!
//! 3. To use this channel when compiling you can either:
//!
//!     - set it as default using `rustup default nightly`;
//!     - or add `+nightly` everytime you compile a binary with `cargo`.
//!
//! 4. Install Cmake, using `brew` for example:
//!
//! ```console
//! brew install cmake
//! ```
//!
//! ### Self-Signed Binaries and Hypervisor Entitlement
//!
//! To be able to reach the Hypervisor Framework, a binary executable has to have been granted the
//! [hypervisor entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_hypervisor).
//!
//! #### Certificate Chain
//!
//! To add this entitlement to your project, you'll first need a certificate chain to sign your
//! binaries, which can be created by following the instructions below.
//!
//! - Open the *Keychain Access* application.
//! - Go to **Keychain Access** > **Certificate Assistant** > **Create a Certificate**.
//! - Fill out the **Name** field, this value will be used later on to identify the certificate we
//!   want to sign with and will be referred to as `${CERT_NAME}`.
//! - Set **Identity Type** to `Self-Signed Root`.
//! - Set **Certificate Type** to `Code Signing`.
//! - Click on **Create**.
//!
//! You can now sign binaries and add entitlements using the following command:
//!
//! ```
//! codesign --entitlements entitlements.xml -s ${CERT_NAME} /path/to/binary
//! ```
//!
//! **Note:** The `entitlements.xml` file is available at the root of the
//! [Hyperpom repository](https://github.com/impalabs/hyperpom/).
//!
//! ### Compilation Workflow
//!
//! Create a Rust project and add Hyperpom as a dependency in `Cargo.toml`. You can either pull it
//! from [crates.io](https://crates.io/crates/hyperpom) ...
//!
//! ```toml
//! # Check which version is the latest, this part of the README might not be updated
//! # in future releases.
//! hyperpom = "0.1.0"
//! ```
//!
//! ... or directly from the [GitHub repository](https://github.com/impalabs/hyperpom).
//!
//! ```toml
//! hyperpom = { git="https://github.com/impalabs/hyperpom", branch="master" }
//! ```
//!
//! Create a file called `entitlements.txt` in the project's root directory and add the following:
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
//! <plist version="1.0">
//! <dict>
//!     <key>com.apple.security.hypervisor</key>
//!     <true/>
//! </dict>
//! </plist>
//! ```
//!
//! Write code and then build the project.
//!
//! ```
//! cargo build --release
//! ```
//!
//! Sign the binary and grant the hypervisor entitlement.
//!
//! ```
//! codesign --entitlements entitlements.xml -s ${CERT_NAME} target/release/${PROJECT_NAME}
//! ```
//!
//! Run the binary.
//!
//! ```
//! target/release/${PROJECT_NAME}
//! ```
//!
//! ## Examples
//!
//! Four examples are provided to give you a better understanding of how the framework operates and
//! get you started:
//!
//! * [simple_executor](https://github.com/impalabs/hyperpom/tree/master/examples/simple_executor):
//!   showcases how to run arbitrary code in a VM using an `Executor`.
//! * [simple_tracer](https://github.com/impalabs/hyperpom/tree/master/examples/simple_tracer):
//!   runs a program while tracing its instructions.
//! * [simple_fuzzer](https://github.com/impalabs/hyperpom/tree/master/examples/simple_fuzzer):
//!   fuzzes a simple program.
//! * [upng_fuzzer](https://github.com/impalabs/hyperpom/tree/master/examples/upng_fuzzer): fuzzer
//!   for the [uPNG](https://github.com/elanthis/upng/) library.
//!
//! You can also have a look at the
//! [tests](https://github.com/impalabs/hyperpom/tree/master/tests/tests.rs).


#![feature(exclusive_range_pattern)]
#![feature(iterator_try_collect)]
#![feature(map_try_insert)]
#![feature(portable_simd)]
#![feature(slice_partition_dedup)]

pub mod backtrace;
pub mod caches;
pub mod config;
pub mod core;
pub mod corpus;
pub mod coverage;
pub mod crash;
pub mod error;
pub mod exceptions;
pub mod hooks;
pub mod loader;
pub mod memory;
pub mod mutator;
pub mod tracer;
pub mod utils;

pub extern crate applevisor;
