//! Contains all error types that can be returned by this crate.

use std::alloc;
use std::error;
use std::fmt;
use std::io;

/// Convenient `Result` type for custom errors.
pub type Result<T> = std::result::Result<T, Error>;

// -----------------------------------------------------------------------------------------------
// Errors - General
// -----------------------------------------------------------------------------------------------

/// Main error structure which is just a simple wrapper for all errors that can be returned by the
/// fuzzer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Core-related errors.
    Core(CoreError),
    /// Crash-related errors.
    Crash(CrashError),
    /// Exception-related errors.
    Exception(ExceptionError),
    /// Hook-related errors.
    Hook(HookError),
    /// Hypervisor-related errors.
    Hypervisor(applevisor::HypervisorError),
    /// Loader-related errors.
    Loader(LoaderError),
    /// Memory-related errors.
    Memory(MemoryError),
    /// Generic user-defined errors.
    Generic(String),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Core(e) => write!(f, "[Core error] {}", e),
            Error::Crash(e) => write!(f, "[Crash error] {}", e),
            Error::Exception(e) => write!(f, "[Exception error] {}", e),
            Error::Hook(e) => write!(f, "[Hook error] {}", e),
            Error::Loader(e) => write!(f, "[Loader error] {}", e),
            Error::Memory(e) => write!(f, "[Memory error] {}", e),
            Error::Hypervisor(e) => write!(f, "[Hypervisor error] {}", e),
            Error::Generic(e) => write!(f, "[Error] {}", e),
        }
    }
}

impl From<CoreError> for Error {
    fn from(error: CoreError) -> Self {
        Error::Core(error)
    }
}

impl From<CrashError> for Error {
    fn from(error: CrashError) -> Self {
        Error::Crash(error)
    }
}

impl From<ExceptionError> for Error {
    fn from(error: ExceptionError) -> Self {
        Error::Exception(error)
    }
}

impl From<HookError> for Error {
    fn from(error: HookError) -> Self {
        Error::Hook(error)
    }
}

impl From<LoaderError> for Error {
    fn from(error: LoaderError) -> Self {
        Error::Loader(error)
    }
}

impl From<MemoryError> for Error {
    fn from(error: MemoryError) -> Self {
        Error::Memory(error)
    }
}

impl From<applevisor::HypervisorError> for Error {
    fn from(error: applevisor::HypervisorError) -> Self {
        Error::Hypervisor(error)
    }
}

impl From<alloc::LayoutError> for Error {
    fn from(error: alloc::LayoutError) -> Self {
        Error::Memory(MemoryError::LayoutError(error))
    }
}

impl From<std::fmt::Error> for Error {
    fn from(error: std::fmt::Error) -> Self {
        Error::Crash(CrashError::FmtError(error))
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Core(CoreError::IoError(format!("{}", error)))
    }
}

// -----------------------------------------------------------------------------------------------
// Errors - Core
// -----------------------------------------------------------------------------------------------

/// Core-related errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    InvalidConfiguration,
    /// The corpus at the specified path is empty.
    EmptyCorpus(String),
    /// Corpus testcase generated a crash.
    CorpusCrash(std::path::PathBuf),
    /// The testcase provided is invalid.
    InvalidTestcase,
    /// An I/O error occured while processing the corpus.
    IoError(String),
    /// Too many workers are trying to be spawned.
    TooManyWorkers(u32),
    /// User-defined core error.
    Generic(String),
}

impl error::Error for CoreError {}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidConfiguration => write!(f, "invalid configuration type"),
            CoreError::EmptyCorpus(e) => write!(f, "corpus at {} is empty", e),
            CoreError::CorpusCrash(p) => {
                write!(f, "a corpus element crashed the fuzzer: {}", p.display())
            }
            CoreError::InvalidTestcase => write!(f, "testcase is invalid"),
            CoreError::IoError(e) => write!(f, "{}", e),
            CoreError::TooManyWorkers(n) => write!(f, "maximum number of workers reached ({})", n),
            CoreError::Generic(e) => write!(f, "{}", e),
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Errors - Crash
// -----------------------------------------------------------------------------------------------

/// Crash-related errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrashError {
    /// A format error occured.
    FmtError(std::fmt::Error),
    /// User-defined core error.
    Generic(String),
}

impl error::Error for CrashError {}

impl fmt::Display for CrashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrashError::FmtError(e) => write!(f, "{}", e),
            CrashError::Generic(e) => write!(f, "{}", e),
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Errors - Exception
// -----------------------------------------------------------------------------------------------

/// Exception-related errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExceptionError {
    /// The exception type is not implemented.
    UnimplementedException(u64),
    /// User-defined exception error.
    Generic(String),
}

impl error::Error for ExceptionError {}

impl fmt::Display for ExceptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExceptionError::UnimplementedException(e) => {
                write!(f, "unimplemented exception ({:?})", e)
            }
            ExceptionError::Generic(e) => write!(f, "{}", e),
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Errors - Hook
// -----------------------------------------------------------------------------------------------

/// Hook-related errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HookError {
    /// The hook already exists at this address.
    HookAlreadyExists(u64),
    /// The hook type is invalid.
    InvalidHookType(u16),
    /// There is no hook at the given address.
    UnknownHook(u64),
    /// User-defined hook error.
    Generic(String),
}

impl error::Error for HookError {}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookError::HookAlreadyExists(a) => write!(f, "hook already exists ({:#x})", a),
            HookError::InvalidHookType(t) => write!(f, "invalid hook type ({:#x})", t),
            HookError::UnknownHook(a) => write!(f, "unknown hook ({:#x})", a),
            HookError::Generic(e) => write!(f, "{}", e),
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Errors - Loader
// -----------------------------------------------------------------------------------------------

/// Loader-related errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoaderError {
    /// The symbol is unknown.
    UnknownSymbol(String),
    /// User-defined loader error.
    Generic(String),
}

impl error::Error for LoaderError {}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::UnknownSymbol(s) => write!(f, "unknown symbol: {}", s),
            LoaderError::Generic(e) => write!(f, "{}", e),
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Errors - Memory
// -----------------------------------------------------------------------------------------------

/// Memory-related errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryError {
    /// The address we're trying to map already exists in the page table.
    AlreadyMapped(u64),
    /// The slab is an unexpected state.
    CorruptedSlab,
    /// The address is invalid.
    InvalidAddress(u64),
    /// The index is invalid.
    InvalidIndex(usize),
    /// The size is invalid.
    InvalidSize(usize),
    /// Wrapper for `alloc::LayoutError`.
    LayoutError(alloc::LayoutError),
    /// The allocator is out of memory.
    OutOfMemory,
    /// The operation between an address and a size resulted in an overflow.
    Overflow(u64, usize),
    /// The address is not aligned as expected.
    UnalignedAddress(u64),
    /// The size is not aligned as expected.
    UnalignedSize(usize),
    /// The address we're trying to access has not been allocated.
    UnallocatedMemoryAccess(u64),
    /// User-defined memory error.
    Generic(String),
}

impl error::Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::AlreadyMapped(a) => write!(f, "address is already mapped: {:#x}", a),
            MemoryError::CorruptedSlab => write!(f, "corrupted slab"),
            MemoryError::InvalidAddress(a) => write!(f, "invalid address: {:#x}", a),
            MemoryError::InvalidIndex(i) => write!(f, "invalid index: {:#x}", i),
            MemoryError::InvalidSize(s) => write!(f, "invalid size: {:#x}", s),
            MemoryError::LayoutError(e) => write!(f, "layout error: {}", e),
            MemoryError::OutOfMemory => write!(f, "the allocator ran out of memory"),
            MemoryError::Overflow(a, s) => write!(f, "an overflow occured: {:#x}, {:#x}", a, s),
            MemoryError::UnalignedAddress(a) => write!(f, "unaligned address: ({:#x})", a),
            MemoryError::UnalignedSize(s) => write!(f, "unaligned size: ({:#x})", s),
            MemoryError::UnallocatedMemoryAccess(x) => {
                write!(f, "access to unallocated memory at address {:#x}", x)
            }
            MemoryError::Generic(e) => write!(f, "{}", e),
        }
    }
}
