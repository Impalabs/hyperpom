//! Interface used to implement user-defined behaviour. It is reponsible for loading the binary,
//! placing hooks, generating a symbols list, etc.

use crate::core::*;
use crate::corpus::{LoadTestcaseAction, Testcase};
use crate::coverage::CoverageRange;
use crate::crash::*;
use crate::error::*;
use crate::memory::VirtMemAllocator;
use crate::mutator::Mutator;
use crate::tracer::TraceRange;
use crate::utils::CodeRange;

use applevisor as av;

use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::sync::RwLock;
use std::time;

// -----------------------------------------------------------------------------------------------
// Loader - Symbols
// -----------------------------------------------------------------------------------------------

/// Represents a symbol found in an executable
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Symbol {
    /// The symbol's name.
    pub name: String,
    /// The executable's name that contains the symbol.
    pub binary: String,
    /// The symbol's address.
    pub addr: u64,
    /// The symbol's size.
    pub size: u64,
}

impl Symbol {
    /// Creates a new symbol.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::loader::Symbol;
    ///
    /// // Creates a symbol for the function main, which is 0x100-byte long and found at address
    /// // 0x12340000 in `binary.elf`.
    /// let symbol = Symbol::new("main", "binary.elf", 0x12340000, 0x100);
    /// ```
    pub fn new(name: &str, binary: &str, addr: u64, size: u64) -> Self {
        Self {
            name: name.to_string(),
            binary: binary.to_string(),
            addr,
            size,
        }
    }
}

/// Objects containing all the executable's symbols.
pub struct Symbols {
    /// Binary tree storing the symbols.
    pub symbols: BTreeMap<u64, Symbol>,
}

impl Symbols {
    /// Creates a new symbol tree.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::loader::Symbols;
    ///
    /// let symbols = Symbols::new();
    /// ```
    pub fn new() -> Self {
        Self::from_tree(BTreeMap::new())
    }

    /// Creates a new object from an existing tree of symbols.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::loader::Symbols;
    /// use std::collections::BTreeMap;
    ///
    /// // Creates a tree of symbols.
    /// let mut symbol_tree = BTreeMap::new();
    ///
    /// // Adds a symbol for the "main" function.
    /// symbol_tree.insert(0x1234, Symbol::new("main", "binary.elf", 0x12340000, 0x100));
    ///
    /// // Adds a symbol for the "memcpy" function.
    /// symbol_tree.insert(0x1234, Symbol::new("memcpy", "binary.elf", 0x34560000, 0x200));
    ///
    /// // Creates a `Symbols` object from the tree.
    /// let symbols = Symbols::from_tree(symbol_tree);
    /// ```
    pub fn from_tree(symbols: BTreeMap<u64, Symbol>) -> Self {
        Self { symbols }
    }

    /// Creates a new object from a vector of symbols.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::loader::Symbols;
    ///
    /// // Creates a vector.
    /// let mut symbol_vec = Vec::new();
    ///
    /// // Adds a symbol for the "main" function.
    /// symbol_vec.push(Symbol::new("main", "binary.elf", 0x12340000, 0x100));
    ///
    /// // Adds a symbol for the "memcpy" function.
    /// symbol_vec.push(Symbol::new("memcpy", "binary.elf", 0x34560000, 0x200));
    ///
    /// // Creates a `Symbols` object from the vector.
    /// let symbols = Symbols::from_vec(symbol_vec);
    /// ```
    pub fn from_vec(symbols: Vec<Symbol>) -> Self {
        Self {
            symbols: symbols
                .into_iter()
                .map(|s| (s.addr, s))
                .collect::<BTreeMap<u64, Symbol>>(),
        }
    }

    /// Looks for a symbol at address `addr` and formats it into a string.
    /// Returns the stringified address if the symbol doesn't exist.
    ///
    /// # Example
    ///
    /// ```
    /// use crate::loader::Symbols;
    ///
    /// // Symbols object that contains an entry for the "main" function at address 0x1000.
    /// let mut symbol_vec = Vec::new();
    /// symbol_vec.push(Symbol::new("main", "binary.elf", 0x1000, 0x100));
    /// let symbols = Symbols::from_vec(symbol_vec);
    ///
    /// // Prints the formatted symbol for address 0x1080.
    /// println!("{}", symbols.format(0x1080));
    /// ```
    ///
    /// Which outputs:
    ///
    /// ```text
    /// binary.elf  main+0x80/0x100 [0x1080]
    /// ```
    pub fn format(&self, addr: u64) -> String {
        if let Some((_, s)) = self.symbols.range(..addr).next_back() {
            if (s.addr..s.addr + s.size).contains(&addr) {
                format!(
                    "{} \t{}+{:#x}/{:#x}\t[{:#x}]",
                    s.binary,
                    s.name,
                    addr - s.addr,
                    s.size,
                    addr
                )
            } else {
                format!("{:#x}", addr)
            }
        } else {
            format!("{:#x}", addr)
        }
    }
}

impl Default for Symbols {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------------------------
// Loader - Loader trait
// -----------------------------------------------------------------------------------------------

/// The loader trait contains all the methods that can be configured and defined to fuzz a given
/// target.
///
/// # Role of the Loader Trait in the Fuzzer.
///
/// The loader trait is the main user-facing interface used to customize our fuzzer. It gives
/// access to core components of the fuzzer, such as the virtual memory allocators or virtual CPUs,
/// that can be used to load an arbitrary binary, define hooks and initialize the state of the CPU
/// before starting a fuzzing campaign.
///
/// The methods defined by this trait try to reflect as best as possible all the steps of the
/// binary's lifetime while being fuzzed.
///
///  * The binary is first parsed to be mapped into the virtual address space of the fuzzer using
///    [`Loader::map`].
///  * User-defined hooks can then be applied using [`Loader::hooks`].
///  * We've now reached the pre-snapshot stage. The method [`Loader::pre_snapshot`] can be used to
///    perform all the remaining operations before a snapshot of the virtual address space and the
///    CPU state is taken. This is the step where we can call, for example, initialization
///    functions from the binary so that we don't have to do it every iteration.
///  * From this point on, the fuzzer enters the iteration loop, whichs means that we'll return to
///    this step when an iteration finishes. For every iteration, the first operation will be to
///    retrieve a testcase from the corpus, mutate it using [`Loader::mutate`], and pass it to the
///    [`Loader::load_testcase`] function where it can be arbitrarily loaded into the address space
///    in order to be used by the targeted binary.
///  * Every action that needs to happen after the snapshot, but before the actual execution can
///    be defined in [`Loader::pre_exec`].
///  * Now the execution actually happens, this is the fuzzer's job, nothing to do here. :)
///  * If something needs to be cleaned-up after the execution of a testcase, you can do it using
///    [`Loader::post_exec`].
///
/// When a crash occurs, we break away from this lifecycle and switch over to the crash
/// verification process. Because internal and global states can evolve while the fuzzer is active,
/// we need to be able to control them when a testcase is replayed. If you need to reset variables
/// that could influence crash reruns, you can do so by implementing
/// [`Loader::reset_state`]. If it is a legitimate crash, it is formatted using
/// [`Loader::format_crash`] and written in a file by the fuzzer.
///
/// # Example
///
/// ## The Target Program
///
/// To illustrate the use of the fuzzer, we'll take the C program below as an example. Even though
/// it is not a real-world example, it should be enough to showcase some important features of
/// Hyperpom and how to use them.
///
/// ```
/// #define MAGIC_VALUE 0xdeadbeef
/// #define INIT_STATE 0x0bad0d0e
///
/// /* Global state variable. */
/// int g_state = 0;
/// char g_magic_string[0x11];
///
/// void init(int magic);
/// int sum(char* buffer, unsigned int size);
/// int process(char* buffer, unsigned int size);
/// unsigned int strlen(const char *str);
/// int strcmp(const char *s1, const char *s2);
/// unsigned long hex2long(const char *str);
///
/// /* The main function. */
/// int main(int argc, char *argv[]) {
///     if (argc < 3)
///         return -1;
///
///     /*
///      * Converts the first argument into a number from an hexadecimal
///      * representation.
///      */
///     unsigned int magic = hex2long(argv[1]);
///     init(magic);
///
///     /* Retrieves information about the buffer and calls the process function. */
///     char* buffer = argv[2];
///     unsigned int size = strlen(buffer);
///     return process(buffer, size);
/// }
///
/// /* Sets the global state variable to the initial state value. */
/// void init(int magic) {
///     /*
///      * The argument should be equal to the expected magic value.
///      * This is mostly an excuse to show how a function can be called from the
///      * fuzzer using arbitrary arguments.
///      */
///     g_state = (magic == MAGIC_VALUE) ? INIT_STATE : 0;
///
///     /*
///      * The global magic string is initialized in this function so we don't need
///      * to care about loading the string from the binary's data section.
///      */
///     *(unsigned long*)g_magic_string = 0x7362616c61706d69;
///     *(unsigned long*)(g_magic_string + 8) = 0x7362616c61706d69;
///     g_magic_string[0x10] = 0;
/// }
///
/// /* Computes the sum of the bytes in `buffer`. */
/// int sum(char* buffer, unsigned int size) {
///     int sum = 0;
///     for (int i = 0; i < size; i++) {
///         sum += buffer[i];
///     }
///     return sum;
/// }
///
/// /* Processes the user input */
/// int process(char* buffer, unsigned int size) {
///     /* Returns if we're not currently in the initialization state */
///     if (g_state != INIT_STATE)
///         return -2;
///
///     /* Checks that the input is big enough. */
///     if (size <= 24)
///         return -3;
///
///     /*
///      * Pre-check verifying that the sum of the input is the expected one
///      * before proceeding further. These types of functions can be arbitrarily
///      * hard to pass while fuzzing, so it's better to just place a hook that
///      * returns the correct value and ignore them.
///      */
///     if (sum(buffer, size) != 0x9db)
///         return -4;
///
///     /* Verifies that the buffer starts with the expected input. */
///     if (*(unsigned long*)buffer != 0x7362616c61706d69)
///         return -5;
///
///     /* Verifies that the buffer contains the rest of the string. */
///     if (strcmp(buffer + 8, g_magic_string))
///         return -6;
///
///     /* If we managed to reach this point, crash the program. */
///     *(unsigned long*)0xdeadbeefdeadbeef = 0xcafec0c0;
///
///     return 0;
/// }
///
/// /* strlen implementation */
/// unsigned int strlen(const char *str) {
///     const char *s = str;
///     while (*s++);
///     return (s - str);
/// }
///
/// /* strcmp implementation */
/// int strcmp(const char *s1, const char *s2) {
///     unsigned char c1, c2;
///     do {
///         c1 = *s1++;
///         c2 = *s2++;
///         if (c1 == 0)
///             return c1 - c2;
///     } while (c1 == c2);
///     return c1 - c2;
/// }
///
/// /*
///  * Converts a string that contains an hexadecimal representation of a number
///  * into a 64-bit integer.
///  * Equivalent to strtol(str, 0, 16).
///  */
/// unsigned long hex2long(const char *str) {
///     unsigned long res = 0;
///     char c;
///     while ((c = *str++)) {
///         char v = (c & 0xF) + (c >> 6) | ((c >> 3) & 0x8);
///         res = (res << 4) | (unsigned long) v;
///     }
///     return res;
/// }
/// ```
///
/// The program in itself doesn't do much. It is a CLI program that takes two arguments: a magic
/// value used during the "initialization" phase and a string.
///
/// The magic value is passed as an hexadecimal string to the program and is first converted to an
/// integer. The resulting integer is then passed to the function `init` where it is checked
/// against the constant named `MAGIC_VALUE`. If the values match, the global variable `g_state`
/// is set to `INIT_STATE`. `g_magic_string` is also initialized to `impalabsimpalabs`.
///
/// Then the function `process` is called. It takes as arguments the second string argument passed
/// to the program as well as its size. This function performs the following operations:
///
///  * it starts by checking if `g_state` is equal to `INIT_STATE`;
///  * then it verifies that the input buffer's length is bigger than 8 bytes;
///  * afterwards it performs a checksum on the input buffer using the `sum` function and makes
///    sure that the result is equal to `0x9db`;
///  * it dereferences the first 8 bytes of the buffer and compares them to the 64-bit magic value
///    `0x7362616c61706d69`.
///  * and finally, it verifies that the remaining bytes are the same than the ones in
///    `g_magic_string`.
///
/// If all these conditions are successfully met, the program will crash by dereferencing the
/// invalid address `0xdeadbeefdeadbeef`.
///
/// In the next sections, we'll see how we can use Hyperpom to reach this crash automatically by
/// fuzzing the function `process`.
///
/// ## Implementing the Loader
///
/// The first step will be to define an object on which we will implement the [`Loader`] trait.
/// In our case, this object will be called `SimpleLoader`.
///
/// ```
/// use hyperpom::config::*;
/// use hyperpom::core::*;
/// use hyperpom::coverage::*;
/// use hyperpom::crash::*;
/// use hyperpom::error::*;
/// use hyperpom::hooks::*;
/// use hyperpom::loader::*;
/// use hyperpom::memory::*;
/// use hyperpom::tracer::*;
/// use hyperpom::utils::*;
/// use hyperpom::*;
///
/// use hyperpom::applevisor as av;
///
/// use std::fs::File;
/// use std::io::prelude::*;
///
/// // Defines the global and local data structure, even though we won't use them here.
/// #[derive(Clone)]
/// struct GlobalData;
/// #[derive(Clone)]
/// struct LocalData;
///
/// #[derive(Clone)]
/// struct SimpleLoader {
///     /// The executable's name.
///     executable_name: String,
///     /// The content of the targeted binary.
///     binary: Vec<u8>,
/// }
///
/// impl SimpleLoader {
///     /// The targeted binary path.
///     const BINARY_PATH: &'static str = "bin/simple_program";
///     /// The program's address in memory.
///     const BINARY_ADDR: u64 = 0x10_0000;
///     /// The stack address.
///     const STACK_ADDR: u64 = 0x1_0000_0000;
///     /// The stack size.
///     const STACK_SIZE: usize = 0x1000;
///     /// The address in memory where the testcase should be loaded.
///     const TESTCASE_ADDR: u64 = 0x20_0000;
///     /// Maximum size of a testcase
///     const MAX_TESTCASE_SIZE: usize = 0x20;
///
///     /// Creates a new simple loader object.
///     ///
///     /// This simply retrieves the information we need about the binary. In this specific case,
///     /// the binary is just composed of raw instructions, but with real-world targets, it's much
///     /// more likely you'll have to parse executable formats such as Mach-O or ELF.
///     fn new() -> Result<Self> {
///         // Reads the binary.
///         let mut file = File::open(&Self::BINARY_PATH)?;
///         let mut binary = Vec::new();
///         file.read_to_end(&mut binary)?;
///         Ok(Self {
///             executable_name: "simple_program".to_string(),
///             binary: binary.to_vec(),
///         })
///     }
/// }
/// ```
///
/// Nothing too fancy for the moment, when the object is instanciated, it will open the binary
/// found at `BINARY_PATH`, read its content and store it into `binary`.
///
/// Now that we have our loader object, we can implement the [`Loader`] trait on it.
///
/// ```
/// // Defines the global and local data structure, even though we won't use them here.
/// #[derive(Clone)]
/// struct GlobalData;
/// #[derive(Clone)]
/// struct LocalData;
///
/// impl Loader for SimpleLoader {
///     type LD = LocalData;
///     type GD = GlobalData;
///
/// // [...]
///
/// }
/// ```
///
/// The next step, which is optional, is to implement the function that returns the [`Symbols`]
/// from the binary. This is particularily useful to call arbitrary functions by their name
/// or to get a symbolized backtrace during a crash. Unfortunately, this is a pretty rare occurence
/// when doing gray/black-box fuzzing.
///
/// ```
/// impl Loader for SimpleLoader {
///     // [...]
///
///     // An optional step we can start with, is to define the symbols found in the binary. In
///     // this specific case, it is relatively easy because there are only a few of them. On
///     // larger binaries without any debug information, things get a bit more complicated.
///     // Symbols are not required for the fuzzer to work, but they make things easier when we
///     // want to place hooks or retrieve the address of a specific function.
///     //
///     // Note: if you recompile the program, the offsets might change.
///     fn symbols(&self) -> Result<Symbols> {
///         Ok(Symbols::from_vec(vec![
///             Symbol::new("main", &self.executable_name, Self::BINARY_ADDR, 0x7c),
///             Symbol::new(
///                 "hex2long",
///                 &self.executable_name,
///                 Self::BINARY_ADDR + 0x7c,
///                 0xe4 - 0x7c,
///             ),
///             Symbol::new(
///                 "init",
///                 &self.executable_name,
///                 Self::BINARY_ADDR + 0xe4,
///                 0x140 - 0xe4,
///             ),
///             Symbol::new(
///                 "strlen",
///                 &self.executable_name,
///                 Self::BINARY_ADDR + 0x140,
///                 0x180 - 0x140,
///             ),
///             Symbol::new(
///                 "process",
///                 &self.executable_name,
///                 Self::BINARY_ADDR + 0x180,
///                 0x26c - 0x180,
///             ),
///             Symbol::new(
///                 "sum",
///                 &self.executable_name,
///                 Self::BINARY_ADDR + 0x26c,
///                 0x2c4 - 0x26c,
///             ),
///             Symbol::new(
///                 "strcmp",
///                 &self.executable_name,
///                 Self::BINARY_ADDR + 0x2c4,
///                 0x340 - 0x2c4,
///             ),
///         ]))
///     }
///
///     // [...]
/// }
/// ```
///
/// The first primary operation performed by the loader is to map the binary in memory. The
/// implementation given below will:
///
///  * map memory at address `BINARY_ADDR` and write the content of the binary file that was read
///    when we instanciated the loader;
///  * it also maps a page right after for the data section (which only contains the `g_state`
///    global variable in our case).
///  * it maps the region dedicated to the stack;
///  * and finally, it maps the region dedicated to the testcase that will be fed to the program
///    when we start fuzzing.
///
/// ```
/// impl Loader for SimpleLoader {
///     // [...]
///
///     // Once our binary has been parsed and we've retrieved all the information we needed from
///     // it when the loader was instanciated, we can start initializing the address space of the
///     // fuzzer by mapping the binary into it.
///     fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
///         // Maps memory to load the binary's instructions.
///         executor.vma.map(
///             // The mapping for the binary needs to be page-aligned.
///             align_virt_page!(Self::BINARY_ADDR),
///             // The mapping size needs to be rounded up to the next page.
///             round_virt_page!(self.binary.len()) as usize,
///             // Since we're mapping code, the mapping is readable and executable.
///             av::MemPerms::RX,
///         )?;
///         // Writes the content of the binary into the address space of the fuzzer.
///         executor.vma.write(Self::BINARY_ADDR, &self.binary)?;
///         // Maps the data section of the binary, which is right after the code.
///         executor.vma.map(
///             align_virt_page!(Self::BINARY_ADDR) + round_virt_page!(self.binary.len()),
///             VIRT_PAGE_SIZE,
///             // Since we're mapping data, the mapping is readable and writable.
///             av::MemPerms::RW,
///         )?;
///         // Stack mapping.
///         executor.vma.borrow_mut().map(
///             // Since the stack grows towards the lower addresses, the highest stack address,
///             // `STACK_ADDR`, is its base and we need to map it from its top, which is the
///             // lowest address.
///             Self::STACK_ADDR - Self::STACK_SIZE as u64,
///             Self::STACK_SIZE,
///             // The stack contains data that should not be executable and is therefore mapped as
///             // read-write.
///             av::MemPerms::RW,
///         )?;
///         // Finally, we reserve memory for our testcase.
///         executor.vma.borrow_mut().map(
///             Self::TESTCASE_ADDR,
///             round_virt_page!(Self::MAX_TESTCASE_SIZE as u64) as usize,
///             av::MemPerms::RW,
///         )?;
///         Ok(())
///     }
///
///     // [...]
/// }
/// ```
///
/// The next step will be to define the hooks we want to apply to the target. In this example,
/// a function we might want to hook is `sum`. It's very likely going to stall the fuzzer because
/// it expects specific inputs and it doesn't do much apart from verifying our input values. We
/// can simply hook it and return with the correct value to pass the condition in `process`, which
/// is `sum(buffer, size) == 0x9db`.
/// The second function to hook here is `strcmp`. If we compare two strings character by character,
/// the fuzzer can't tell whether 10 characters matched or just one, it only knows that the
/// comparison instruction was hit at least once. But this feature can be implemented by the user
/// in a hook. Here, we define `strcmp_hook` which updates coverage information for each character
/// that match between both strings.
///
/// ```
/// impl Loader for SimpleLoader {
///     // [...]
///
///    /// We can now define the hooks that we will apply to the binary.
///    /// The function we might want to hook is `sum`, which is found at offset `0x26c` in the
///    /// binary. It requires specific inputs to allow the program to continue and is just there
///    /// as a verification system, so it doesn't hurt to simply hook it and make it return the
///    /// expected value.
///    /// Another function that we can hook is strcmp, found at offset `0x2c4`. Currently the
///    /// fuzzer is unable to distinguish between an iteration that matched 10 characters during a
///    /// string comparison or only one. This hook will add additional paths in the coverage data
///    /// structure each time a new character is matched.
///    fn hooks(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
///        // We define the hook we will apply on the `sum` function at offset `0x26c` (which
///        // corresponds to address self.binary_address + 0x26c once the binary is mapped).
///        fn sum_hook(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
///            // We place in the `X0` register the value we want to return, which is 0x9db.
///            args.vcpu.set_reg(av::Reg::X0, 0x9db)?;
///            // We retrieve the LR register...
///            let lr = args.vcpu.get_reg(av::Reg::LR)?;
///            // ... and set PC to it, to return from function and effectively ignore it.
///            args.vcpu.set_reg(av::Reg::PC, lr)?;
///            // The return value of the function is set to `ExitKind::EarlyFunctionReturn`,
///            // because as its name suggests, we returned from the function before it did on its
///            // own. This specific value is there mostly when a crash occurs and the backtrace is
///            // computed. Backtrace hooks are place on `ret` instructions to know that we've
///            // returned from the function and update the backtrace accordingly. Although, when
///            // we hook a function and return manually, the fuzzer can't know we've returned
///            // earlier unless we tell him explicitly.
///            Ok(ExitKind::EarlyFunctionReturn)
///        }
///        // The hook is placed at the start of the `sum` function.
///        executor.add_function_hook("sum", sum_hook)?;
///        // We then define the hook we will apply on the `strcmp` function at offset `0x2c4`
///        // (which corresponds to address self.binary_address + 0x2c4 once the binary is mapped).
///        fn strcmp_hook(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
///            let s1 = args.vcpu.get_reg(av::Reg::X0)?;
///            let s2 = args.vcpu.get_reg(av::Reg::X1)?;
///            let mut i = 0;
///            let mut c1;
///            let mut c2;
///            loop {
///                c1 = args.vma.read_byte(s1 + i)? as u64;
///                c2 = args.vma.read_byte(s2 + i)? as u64;
///                i += 1;
///                if c1 == 0 || c2 == 0 || c1 != c2 {
///                    break;
///                }
///                let pc = (i as u128) << 0x40 | args.addr as u128;
///                args.cdata.set.insert(pc);
///            }
///            args.vcpu.set_reg(av::Reg::X0, c1 - c2)?;
///            let lr = args.vcpu.get_reg(av::Reg::LR)?;
///            args.vcpu.set_reg(av::Reg::PC, lr)?;
///            Ok(ExitKind::EarlyFunctionReturn)
///        }
///        // The hook is placed at the start of the `strcmp` function.
///        executor.add_function_hook("strcmp", strcmp_hook)?;
///        Ok(())
///    }
///
///
///     // [...]
/// }
/// ```
///
/// Now we enter the pre-snapshot phase, where we perform all the operations that do not have to be
/// repeated every iteration. In this example, we:
///
///  * set the stack address;
///  * call the initialization function `init` to which we pass the value `MAGIC_VALUE` so that
///    it sets `g_state` to `INIT_STATE`;
///  * set PC to the address of the function we want to fuzz, which is `process`.
///
/// ```
/// impl Loader for SimpleLoader {
///     // [...]
///
///     // Once the virtual memory space has been created and hooks have been placed, we set the
///     // initial state of the target program and make it ready to be fuzzed. This is the last
///     // function executed before the content of the virtual address space and the values of all
///     // registers are snapshotted. Afterwards, every time the fuzzer finishes an iteration, it
///     // will reset to this state.
///     fn pre_snapshot(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>)
///             -> Result<()> {
///         // Sets SP to the base of the stack.
///         executor
///             .vcpu
///             .set_sys_reg(av::SysReg::SP_EL0, Self::STACK_ADDR)?;
///         // We call the init function and pass the magic value to it. This will set the variable
///         // `g_state` to the correct value and will allow us to go further into the `process`
///         // function.
///         let ret = call_func_by_addr!(executor, Self::BINARY_ADDR + 0xf4, 0xdead_beef)?;
///         // We make sure that we returned from the function without a crash or another error.
///         assert_eq!(ret.1, ExitKind::Exit);
///         // We search for the address of the `process` function, since it will already have been
///         // defined in the executor by the time this function is called.
///         let process = executor
///             .symbols
///             .symbols
///             .iter()
///             .find(|(_, s)| &s.name == "process")
///             .map(|(_, s)| s)
///             .unwrap();
///         // We set the entry point of the fuzzer to the `process` function.
///         executor.vcpu.set_reg(av::Reg::PC, process.addr)?;
///         Ok(())
///     }
///
///     // [...]
/// }
/// ```
///
/// At this point, the snapshot has been taken and we enter the iteration loop. The fuzzer will
/// pass a mutated testcase to the loader and `load_testcase` will be responsible for loading it
/// in the fuzzer's address space at the appropriate location.
///
/// Here we load it at address `TESTCASE_ADDR` and we set the first arguments to the testcase
/// address and its size, respectively.
///
/// ```
/// impl Loader for SimpleLoader {
///     // [...]
///
///     // We now enter the iteration loop where the first step is to load the testcase mutated by
///     // the fuzzer.
///     fn load_testcase(
///         &mut self,
///         executor: &mut Executor<Self, Self::LD, Self::GD>,
///         testcase: &[u8],
///     ) -> Result<LoadTestcaseAction> {
///         // We write the content of the testcase into the fuzzer's address space.
///         executor.vma.write(Self::TESTCASE_ADDR, testcase)?;
///         // We also set the argument of the function to the address of the testcase and its
///         // size.
///         executor.vcpu.set_reg(av::Reg::X0, Self::TESTCASE_ADDR)?;
///         executor.vcpu.set_reg(av::Reg::X1, testcase.len() as u64)?;
///         // The return value of this function tells the fuzzer whether we want to discard the
///         // current testcase and reset the memory and cpu state. This feature is implemented
///         // because we might want to do multiple iterations with a single testcase, where we
///         // consume it partially every loop, until it's empty and we want another one. This can
///         // be useful for programs that rely on a state machine.
///         Ok(LoadTestcaseAction::NewAndReset)
///     }
///
///     // [...]
/// }
/// ```
///
/// This example doesn't use the [`Loader::pre_exec`] and [`Loader::post_exec`] methods, but more
/// complex fuzzer implementations can be found on the
/// [Hyperpom's repository](https://github.com/impalabs/hyperpom). What remains is to implement the
/// ranges where instruction, coverage and tracing hooks can be applied. In our example, only the
/// coverage ranges are useful, because we're not tracing anything and we didn't place
/// [instruction hooks](crate::core::Executor::add_instruction_hook).
///
/// ```
/// impl Loader for SimpleLoader {
///     // [...]
///
///     // This method defines the code ranges where coverage hooks can be applied.
///     fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
///         Ok(vec![CoverageRange::new(
///             Self::BINARY_ADDR,
///             Self::BINARY_ADDR + self.binary.len() as u64,
///         )])
///     }
///
///     // [...]
/// }
/// ```
///
/// ## Fuzzing the Program
///
/// We're done with the hardest part, now we just need to instanciate the fuzzer, configure it
/// and start it!
///
/// ```
/// fn main() {
///     // Instanciates global and local data.
///     let gdata = GlobalData;
///     let ldata = LocalData;
///     // Creates a loader for the target binary.
///     let loader = SimpleLoader::new().expect("could not create the loader");
///     // Creates a config for the fuzzer.
///     let config = Config::<_, _>::builder(0x1000_0000, "tmp/work", "tmp/corpus")
///         .nb_workers(4)
///         .seed(0xdeadbeefdeadbeef)
///         .max_nb_mutations(10)
///         .max_testcase_size(SimpleLoader::MAX_TESTCASE_SIZE)
///         .timeout(std::time::Duration::new(60, 0))
///         .comparison_unrolling(true)
///         .build();
///     // Creates an instance of the fuzzer.
///     let mut hp = HyperPom::<_, _, _>::new(config, loader, ldata, gdata)
///         .expect("could not create fuzzer");
///     // Start fuzzing!
///     hp.fuzz().expect("an error occured while fuzzing");
/// }
/// ```
///
/// If everything went as expected, the program should crash in a minute or two:
///
/// ```text
/// lyte@mini ~/simple_fuzzer > CERT_KEYCHAIN=Impalabs make run
/// # [...]
/// Loading corpus...
/// Corpus loaded!
/// [00:00:52] #: 8658541 - Execs/s: 166510 - Paths: 50 - Crashes: 100 (1 uniques) - Timeouts: 0
/// ```
///
/// And we should get the following crashes:
///
/// ```text
/// lyte@mini ~/simple_fuzzer > cat tmp/work/worker_0*/crashes/*.info
///
/// Synchronous Exception from Lower EL using AArch64
/// =================================================
///
/// Crash Reason
/// ------------
///
/// EXCEPTION => [syndrome: 000000005a000008, virtual addr: 0000000000000000, physical addr: 0000000000000000]
///
///
/// Virtual CPU State
/// -----------------
///
/// EL0:
///      X0: 0000000000000000    X1: 0000000000101004     X2: 0000000000000000     X3: 0000000000000000
///      X4: 0000000000000000    X5: 0000000000000000     X6: 0000000000000000     X7: 0000000000000000
///      X8: 00000000cafec0c0    X9: deadbeefdeadbeef    X10: 0000000000101000    X11: 0000000000000000
///     X12: 00000000deadbeef   X13: 0000000000000000    X14: 0000000000000000    X15: 0000000000000000
///     X16: 0000000000000000   X17: 0000000000000000    X18: 0000000000000000    X19: 0000000000000000
///     X20: 0000000000000000   X21: 0000000000000000    X22: 0000000000000000    X23: 0000000000000000
///     X24: 0000000000000000   X25: 0000000000000000    X26: 0000000000000000    X27: 0000000000000000
///     X28: 0000000000000000   X29: 0000000000000000     LR: 000000000010022c     PC: ffffffffffff0404
///      SP: 00000000ffffffd0
/// EL1:
///   SCTLR: 0000000030101185    SP: fffffffffffe1000
///    CPSR: 00000000604003c5  SPSR: 00000000600003c0
///     FAR: deadbeefdeadbeef   PAR: 0000000000000800
///     ESR: 0000000092000044   ELR: 0000000000100254
///
///
/// Backtrace
/// ---------
///
/// simple_program  process+0xd4/0xec   [0x100254]
/// ```
///
/// ```text
/// lyte@mini ~/simple_fuzzer > ls tmp/work/worker_0*/crashes/* | grep -v info | xargs xxd
/// 00000000: 696d 7061 6c61 6273 696d 7061 6c61 6273  impalabsimpalabs
/// 00000010: 696d 7061 6c61 6273 0000 0000 5b5b       impalabs....[[
/// ```
#[allow(clippy::needless_doctest_main)]
pub trait Loader: Clone + Send {
    /// Local data type.
    ///
    /// This type is local to the fuzzing [`Worker`](crate::core::Worker) instance running in a
    /// given thread. It can be used, for example, to store the state of a custom heap, to store
    /// objects that can be reused between iterations, etc.
    type LD: Clone;
    /// Global data type.
    ///
    /// This type is shared between all threads where fuzzing [`Workers`](crate::core::Worker) are
    /// instanciated.
    type GD: Clone;

    // -------------------------------------------------------------------------------------------
    // Execution lifetime

    /// Responsible for mapping the binary into the fuzzer's address space.
    ///
    /// # Example
    ///
    /// ```
    /// fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
    ///     // Maps memory to load the binary's instructions.
    ///     executor.vma.map(
    ///         align_virt_page!(Self::BINARY_ADDR),
    ///         round_virt_page!(self.binary.len()) as usize,
    ///         av::MemPerms::RX,
    ///     )?;
    ///     // Writes the content of the binary into the address space of the fuzzer.
    ///     executor.vma.write(Self::BINARY_ADDR, &self.binary)?;
    ///     // Stack mapping.
    ///     executor.vma.borrow_mut().map(
    ///         Self::STACK_ADDR - Self::STACK_SIZE as u64,
    ///         Self::STACK_SIZE,
    ///         av::MemPerms::RW,
    ///     )?;
    ///     // Finally, we reserve memory for our testcase.
    ///     executor.vma.borrow_mut().map(
    ///         Self::TESTCASE_ADDR,
    ///         round_virt_page!(Self::MAX_TESTCASE_SIZE as u64) as usize,
    ///         av::MemPerms::RW,
    ///     )?;
    ///     Ok(())
    /// }
    /// ```
    fn map(&mut self, vcpu: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()>;

    /// Responsible for placing user-defined hooks on specific functions or instructions.
    ///
    /// # Example
    ///
    /// ```
    /// fn hooks(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
    ///     // Hook placed at the start of the `sum` function.
    ///     executor.add_function_hook("sum", sum_hook)?;
    ///     Ok(())
    /// }
    /// ```
    fn hooks(&mut self, _executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        Ok(())
    }

    /// Performs all the operations necessary to setup the address space and the CPU state for
    /// snapshotting.
    ///
    /// # Example
    ///
    /// ```
    /// fn pre_snapshot(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>)
    ///         -> Result<()> {
    ///     // Sets SP to the base of the stack.
    ///     executor
    ///         .vcpu
    ///         .set_sys_reg(av::SysReg::SP_EL0, Self::STACK_ADDR)?;
    ///     // Calls an initialization function with arbitrary arguments.
    ///     let ret = call_func!(executor, "init", 0xdead_beef)?;
    ///     // We make sure that we returned from the function without a crash or another error.
    ///     assert_eq!(ret.1, ExitKind::Exit);
    ///     // We set PC to the binary's entry point.
    ///     executor.vcpu.set_reg(av::Reg::PC, self.entry)?;
    ///     Ok(())
    /// }
    /// ```
    fn pre_snapshot(&mut self, _executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        Ok(())
    }

    /// Mutates the `data` of a testcase taken from the corpus. A default implementation is
    /// provided, but is a bit arbitrary. You might want to redefin this method to use mutation
    /// strategies that better fit your target and your needs.
    ///
    /// # Example
    ///
    /// ```
    /// pub fn bitflip(&mut self, data: &mut Vec<u8>, _: usize) {
    ///     /// [...]
    /// }
    ///
    /// pub fn add(&mut self, data: &mut Vec<u8>, _: usize) {
    ///     /// [...]
    /// }
    ///
    /// pub fn sub(&mut self, data: &mut Vec<u8>, _: usize) {
    ///     /// [...]
    /// }
    ///
    /// fn mutate(
    ///     &self,
    ///     mutator: &mut Mutator,
    ///     data: &mut Vec<u8>,
    ///     max_size: usize,
    ///     max_mutations: usize,
    /// ) {
    ///     for _ in 0..max_mutations {
    ///         let strat_idx = mutator.rand.u64();
    ///         let strategy = match strat_idx % 3 {
    ///             0 => bitflip,
    ///             1 => add,
    ///             2 => sub,
    ///         }
    ///         strategy(mutator, data, max_size);
    ///     }
    /// }
    /// ```
    fn mutate(
        &self,
        mutator: &mut Mutator,
        data: &mut Vec<u8>,
        max_size: usize,
        max_mutations: usize,
    ) {
        // If our testcase is empty, we start by extending it.
        if data.is_empty() {
            mutator.extend(data, max_size);
        }
        // Scaling the mutation count based on the ratio between the input and max sizes, so we
        // don't have hundreds of mutations on a 10-byte input which could stall the fuzzer.
        let scaled_max_mutations = max_mutations as f64 / max_size as f64 * data.len() as f64;
        let scaled_max_mutations = std::cmp::max(2, scaled_max_mutations as u64);
        // It's safe to unwrap since 0 < scaled_max_mutations.
        let nb_mutations = mutator
            .rand
            .u64_range(1, scaled_max_mutations as u64)
            .unwrap();
        // Randomly mutates the input.
        for _ in 0..nb_mutations {
            let strat_idx = mutator.rand.u64();
            let strategy = match strat_idx % 459 {
                000..200 => Mutator::bitflip,
                200..300 => Mutator::byte_op,
                300..350 => Mutator::magic_replace,
                350..400 => Mutator::random_replace,
                400..450 => Mutator::repetition_replace,
                450..453 => Mutator::shrink,
                453..456 => Mutator::extend,
                456 => Mutator::magic_insert,
                457 => Mutator::random_insert,
                458 => Mutator::repetition_insert,
                _ => unreachable!(),
            };
            strategy(mutator, data, max_size);
        }
    }

    /// Responsible for loading the mutated testcase received from the fuzzer during an iteration
    /// loop.
    ///
    /// For programs that implement a state machine, or similar mechanisms, it might be interesting
    /// to run multiple iterations with a single testcase consumed in parts. For this purpose,
    /// the function can return a [`LoadTestcaseAction`](crate::corpus::LoadTestcaseAction). It can
    /// be used to specify whether you want to keep the testcase and/or reset the state, as well
    /// as signal to the fuzzer that the current testcase is invalid and that you'd rather have a
    /// new one.
    ///
    /// # Example
    ///
    /// ```
    /// fn load_testcase(
    ///     &mut self,
    ///     executor: &mut Executor<Self, Self::LD, Self::GD>,
    ///     testcase: &[u8],
    /// ) -> Result<LoadTestcaseAction> {
    ///     // We write the content of the testcase into the fuzzer's address space.
    ///     executor.vma.write(Self::TESTCASE_ADDR, testcase)?;
    ///     // We also set the argument of the function to the address of the testcase and its
    ///     // size.
    ///     executor.vcpu.set_reg(av::Reg::X0, Self::TESTCASE_ADDR)?;
    ///     executor.vcpu.set_reg(av::Reg::X1, testcase.len() as u64)?;
    ///     // The return value of this function tells the fuzzer whether we want to discard the
    ///     // current testcase and reset the memory and cpu state. This feature is implemented
    ///     // because we might want to do multiple iterations with a single testcase, where we
    ///     // consume it partially every loop, until it's empty and we want another one. This can
    ///     // be useful for programs that rely on a state machine.
    ///     Ok(LoadTestcaseAction::KeepAndReset)
    /// }
    /// ```
    fn load_testcase(
        &mut self,
        executor: &mut Executor<Self, Self::LD, Self::GD>,
        testcase: &[u8],
    ) -> Result<LoadTestcaseAction>;

    /// Performs operations before the execution of the testcase. These are operations that are
    /// dependent on the testcase (pre-processing, object creation, etc.) and that can't be part
    /// of the snapshot.
    ///
    /// # Example
    ///
    /// ```
    /// fn pre_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>)
    ///         -> Result<ExitKind> {
    ///     // Calls a function that operates on the current iteration's testcase.
    ///     let ret = call_func!(
    ///         executor,
    ///         "upng_new_from_bytes",
    ///         Self::TESTCASE_ADDR,
    ///         self.testcase_size,
    ///     )?;
    ///     assert_eq!(ret.1, ExitKind::Exit);
    ///     assert_ne!(ret.0, 0);
    ///     // Sets PC to the entry point of the target program.
    ///     executor.vcpu.set_reg(av::Reg::PC, self.entry)?;
    ///     Ok(ExitKind::Continue)
    /// }
    /// ```
    fn pre_exec(&mut self, _executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<ExitKind> {
        Ok(ExitKind::Continue)
    }

    /// Performs operations after the execution of the testcase. These can be cleanup operations,
    /// resets, etc.
    ///
    /// # Example
    ///
    /// ```
    /// fn post_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>)
    ///         -> Result<ExitKind> {
    ///     // Resets the state of a heap.
    ///     executor.ldata.heap.reset();
    ///     Ok(ExitKind::Continue)
    /// }
    /// ```
    fn post_exec(
        &mut self,
        _executor: &mut Executor<Self, Self::LD, Self::GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Continue)
    }

    /// Formats the information after a crash into a `String` that is then written into a file
    /// by the fuzzer.
    ///
    /// # Example
    ///
    /// ```
    /// fn format_crash(
    ///     &self,
    ///     title: &str,
    ///     tc: &Testcase,
    ///     executor: &Executor<Self, Self::LD, Self::GD>,
    ///     is_timeout: bool,
    /// ) -> Result<String> {
    ///     let mut crash_str = String::new();
    ///     // Crash title
    ///     writeln!(&mut crash_str, "{}", title)?;
    ///     writeln!(&mut crash_str, "{}", "=".repeat(title.len()))?;
    ///     writeln!(&mut crash_str)?;
    ///     // Virtual CPU state
    ///     writeln!(&mut crash_str, "Virtual CPU State")?;
    ///     writeln!(&mut crash_str, "-----------------")?;
    ///     writeln!(&mut crash_str)?;
    ///     writeln!(&mut crash_str, "{}", executor.vcpu)?;
    ///     // ...
    ///     Ok(crash_str)
    /// }
    /// ```
    fn format_crash(
        &self,
        title: &str,
        _tc: &Testcase,
        executor: &Executor<Self, Self::LD, Self::GD>,
        _is_timeout: bool,
    ) -> Result<String> {
        let mut crash_str = String::new();
        // Crash title
        writeln!(&mut crash_str, "{}", title)?;
        writeln!(&mut crash_str, "{}", "=".repeat(title.len()))?;
        writeln!(&mut crash_str)?;
        // Crash reason
        writeln!(&mut crash_str, "Crash Reason")?;
        writeln!(&mut crash_str, "------------")?;
        writeln!(&mut crash_str)?;
        writeln!(&mut crash_str, "{}", executor.vcpu.get_exit_info())?;
        writeln!(&mut crash_str)?;
        // Virtual CPU state
        writeln!(&mut crash_str, "Virtual CPU State")?;
        writeln!(&mut crash_str, "-----------------")?;
        writeln!(&mut crash_str)?;
        writeln!(&mut crash_str, "{}", executor.vcpu)?;
        writeln!(&mut crash_str)?;
        // Backtrace
        writeln!(&mut crash_str, "Backtrace")?;
        writeln!(&mut crash_str, "---------")?;
        writeln!(&mut crash_str)?;
        for addr in &executor.bdata.backtrace {
            writeln!(&mut crash_str, "{}", executor.symbols.format(*addr))?;
        }
        writeln!(
            &mut crash_str,
            "{}",
            executor
                .symbols
                .format(executor.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?)
        )?;
        writeln!(&mut crash_str)?;
        Ok(crash_str)
    }

    /// Workers have internal and global states that they can change however they like throughout
    /// the fuzzer's lifetime. However, when a crash occurs, the testcase is replayed to:
    ///
    /// - check if the crash is deterministic;
    /// - deduplicate crashes by running the testcase in the virtual address space where backtrace
    ///   hooks are enabled.
    ///
    /// This can be an issue if, for example, the original crash has changed local data and
    /// running the crash again wouldn't work because local data are not in the specific state
    /// they were in initially. It can also be an issue when a testcase is reused across multiple
    /// iterations. If we don't reset the worker's internal state, calling `load_testcase` is going
    /// to generate the next input in the middle of the testcase instead of restarting from the
    /// beginning.
    ///
    /// For these reasons, this method can be used to reset all variables influencing crash reruns.
    ///
    /// # Example
    ///
    /// ```
    /// fn reset_state(
    ///     &mut self,
    ///     _executor: &mut Executor<Self, Self::LD, Self::GD>,
    /// ) -> Result<()> {
    ///     // Resets an internal generator that creates multiple inputs from a single testcase.
    ///     self.current_cmd_id = 0;
    ///     self.generator.reset();
    ///     // Resets the state of a heap.
    ///     executor.ldata.heap.reset();
    /// }
    /// ```
    fn reset_state(&mut self, _executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        Ok(())
    }

    /// Returns the list of [`Symbol`]s from the binary.
    ///
    /// # Example
    ///
    /// ```
    /// fn symbols(&self) -> Result<Symbols> {
    ///     Ok(Symbols::from_vec(vec![
    ///         Symbol::new("main", &self.executable_name, Self::BINARY_ADDR, 0x100),
    ///         Symbol::new("init", &self.executable_name, Self::BINARY_ADDR + 0x100, 0x200),
    ///         Symbol::new("process", &self.executable_name, Self::BINARY_ADDR + 0x300, 0x123),
    ///     ]))
    /// }
    /// ```
    fn symbols(&self) -> Result<Symbols> {
        Ok(Symbols::new())
    }

    /// Function called periodically by the fuzzer to display the statistics stored in an
    /// [HyperPomInfo](crate::core::HyperPomInfo) object.
    ///
    /// # Example
    ///
    /// ```
    /// fn display_info(&self, info: &HyperPomInfo) {
    ///     println!("There are {} crashes so far!", info.nb_crashes);
    /// }
    /// ```
    fn display_info(&self, info: &HyperPomInfo) {
        let delta = time::Instant::now() - info.start_time;
        let elapsed_time = delta.as_secs_f64() as u64;
        if elapsed_time != 0 {
            let tc_per_sec = info.nb_testcases / elapsed_time;
            let hours = elapsed_time / 3600;
            let mins = elapsed_time / 60 % 60;
            let secs = elapsed_time % 60;
            print!(
                "\r[{:02}:{:02}:{:02}] #: {} - Execs/s: {} - Paths: {} - Crashes: {} ({} uniques) - Timeouts: {}",
                hours,
                mins,
                secs,
                info.nb_testcases,
                tc_per_sec,
                info.nb_paths,
                info.nb_crashes,
                info.nb_uniq_crashes,
                info.nb_timeouts,
            );
        }
    }

    // -------------------------------------------------------------------------------------------
    // Instrumentation

    /// This method defines the code ranges where coverage hooks can be applied.
    ///
    /// # Example
    ///
    /// ```
    /// fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
    ///     Ok(vec![CoverageRange::new(
    ///         Self::BINARY_ADDR,
    ///         Self::BINARY_ADDR + self.binary.len() as u64,
    ///     )])
    /// }
    /// ```
    fn coverage_ranges(&self) -> Result<Vec<CoverageRange>>;

    /// This method defines the code ranges where tracing hooks can be applied.
    ///
    /// # Example
    ///
    /// ```
    /// fn trace_ranges(&self) -> Result<Vec<TraceRange>> {
    ///     Ok(vec![TraceRange::new(
    ///         Self::BINARY_ADDR,
    ///         Self::BINARY_ADDR + self.binary.len() as u64,
    ///     )])
    /// }
    /// ```
    fn trace_ranges(&self) -> Result<Vec<TraceRange>>;

    /// This method defines the code ranges where instruction hooks can be applied.
    ///
    /// # Example
    ///
    /// ```
    /// fn code_ranges(&self) -> Result<Vec<CodeRange>> {
    ///     Ok(vec![CodeRange::new(
    ///         Self::BINARY_ADDR,
    ///         Self::BINARY_ADDR + self.binary.len() as u64,
    ///     )])
    /// }
    /// ```
    fn code_ranges(&self) -> Result<Vec<CodeRange>>;

    // -------------------------------------------------------------------------------------------
    // Exception handlers

    /// Custom handler for "Synchronous Exception from Current EL with SP0".
    fn exception_handler_sync_curel_sp0<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "Synchronous Exception from Current EL with SP0".to_string(),
        ))
    }

    /// Custom handler for "IRQ Exception from Current EL with SP0".
    fn exception_handler_irq_curel_sp0<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "IRQ Exception from Current EL with SP0".to_string(),
        ))
    }

    /// Custom handler for "FIQ Exception from Current EL with SP0".
    fn exception_handler_fiq_curel_sp0<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "FIQ Exception from Current EL with SP0".to_string(),
        ))
    }

    /// Custom handler for "SError Exception from Current EL with SP0".
    fn exception_handler_serror_curel_sp0<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "SError Exception from Current EL with SP0".to_string(),
        ))
    }

    /// Custom handler for "Synchronous Exception from Current EL with SPX".
    fn exception_handler_sync_curel_spx<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "Synchronous Exception from Current EL with SPX".to_string(),
        ))
    }

    /// Custom handler for "IRQ Exception from Current EL with SPX".
    fn exception_handler_irq_curel_spx<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "IRQ Exception from Current EL with SPX".to_string(),
        ))
    }

    /// Custom handler for "FIQ Exception from Current EL with SPX".
    fn exception_handler_fiq_curel_spx<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "FIQ Exception from Current EL with SPX".to_string(),
        ))
    }

    /// Custom handler for "SError Exception from Current EL with SPX".
    fn exception_handler_serror_curel_spx<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "SError Exception from Current EL with SPX".to_string(),
        ))
    }

    /// Custom handler for "Synchronous Exception from Lower EL using AArch64".
    fn exception_handler_sync_lowerel_aarch64<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "Synchronous Exception from Lower EL using AArch64".to_string(),
        ))
    }

    /// Custom handler for "IRQ Exception from Lower EL using AArch64".
    fn exception_handler_irq_lowerel_aarch64<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "IRQ Exception from Lower EL using AArch64".to_string(),
        ))
    }

    /// Custom handler for "FIQ Exception from Lower EL using AArch64".
    fn exception_handler_fiq_lowerel_aarch64<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "FIQ Exception from Lower EL using AArch64".to_string(),
        ))
    }

    /// Custom handler for "SError Exception from Lower EL using AArch64".
    fn exception_handler_serror_lowerel_aarch64<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "SError Exception from Lower EL using AArch64".to_string(),
        ))
    }

    /// Custom handler for "Synchronous Exception from Lower EL using AArch32".
    fn exception_handler_sync_lowerel_aarch32<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "Synchronous Exception from Lower EL using AArch32".to_string(),
        ))
    }

    /// Custom handler for "IRQ Exception from Lower EL using AArch32".
    fn exception_handler_irq_lowerel_aarch32<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "IRQ Exception from Lower EL using AArch32".to_string(),
        ))
    }

    /// Custom handler for "FIQ Exception from Lower EL using AArch32".
    fn exception_handler_fiq_lowerel_aarch32<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "FIQ Exception from Lower EL using AArch32".to_string(),
        ))
    }

    /// Custom handler for "SySError Exception from Lower EL using AArch32".
    fn exception_handler_serror_lowerel_aarch32<LD, GD>(
        &self,
        _vcpu: &mut av::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut LD,
        _gdata: &RwLock<GD>,
    ) -> Result<ExitKind> {
        Ok(ExitKind::Crash(
            "SError Exception from Lower EL using AArch32".to_string(),
        ))
    }
}
