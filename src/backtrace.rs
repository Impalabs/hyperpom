//! Handles everything related to backtrace generation.

use crate::core::*;
use crate::coverage::*;
use crate::crash::*;
use crate::error::*;
use crate::hooks::*;
use crate::memory::*;

/// Contains backtrace information for one testcase executed by one worker.
///
/// # Backtrace
///
/// When a crash occurs, it's useful to get a backtrace to observe the path taken by our input.
/// Hooks are place so that everytime a `bl` or `blr` instruction occurs, [`Backtrace::hook_in`]
/// is called and we push the current address to a vector. When we reach a `ret` instruction,
/// [`Backtrace::hook_out`] pops the latest one added. If the program crashes, the addresses stored
/// in the vector will be used to form a backtrace, as shown below.
///
/// ```text
/// Backtrace
/// ---------
///
/// main+0x14/0x28
/// func0+0x20/0x30
/// func1+0x20/0x30
/// func2+0x20/0x30
/// func3+0x1c/0x2c
/// func4+0x10/0x18
/// ```
///
/// *Note:* symbolized backtraces are produced when implementing [`crate::loader::Loader::symbols`]
///         from the [`crate::loader::Loader`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Backtrace {
    /// Vector that represents the backtrace and acts as a stack. The earliest stack frame we're in
    /// is at the beginning, while the latest is at the end. Entering and leaving functions
    /// results, respectively, in the return address being pushed in and popped out.
    pub backtrace: Vec<u64>,
}

impl Backtrace {
    /// Instructions updating the backtrace.
    const BT_INSNS: &'static [&'static str] = &["bl", "blr"];

    /// Instanciates a new structure containing backtrace information.
    pub fn new() -> Self {
        Self {
            backtrace: Vec::new(),
        }
    }

    /// Resets the backtrace information.
    pub fn clear(&mut self) {
        self.backtrace.clear();
    }

    /// Adds backtrace hooks to the fuzzed program.
    ///
    /// There are two hook types:
    ///
    ///  * *backtrace in* hooks signaling that we've entered a new function and pushing the
    ///    return address on the backtrace;
    ///  * *backtrace out* hooks signaling that we've left a function and popping the latest
    ///    address push on the backtrace.
    pub fn add_hooks<LD: Clone, GD: Clone>(
        ranges: Vec<CoverageRange>,
        vma: &VirtMemAllocator,
        hooks: &mut Hooks<LD, GD>,
    ) -> Result<()> {
        // Iterates over the code ranges.
        for CoverageRange(range) in ranges.iter() {
            // In a given range, iterates over each instruction address.
            for addr in range.clone().step_by(4) {
                // Reads the instruction at the current address.
                let mut code = [0; 4];
                vma.read(addr, &mut code)?;
                // Disassemble the instruction and returns a tuple that contains:
                //
                //  * if the instruction enters a function;
                //  * if the instruction leaves a function.
                let (bt_in, bt_out) = CSE.with(|cs| {
                    let insns = cs
                        .disasm_count(&code, addr, 1)
                        .expect("could not disassemble while adding backtrace hooks");
                    if let Some(insn) = insns.as_ref().first() {
                        (
                            Self::BT_INSNS.contains(&insn.mnemonic().unwrap()),
                            insn.mnemonic().unwrap() == "ret",
                        )
                    } else {
                        (false, false)
                    }
                });
                // Adds the corresponding hook(s) depending on the instruction type.
                if bt_in {
                    hooks.add_backtrace_hook(addr, Self::hook_in);
                } else if bt_out {
                    hooks.add_backtrace_hook(addr, Self::hook_out);
                }
            }
        }
        Ok(())
    }

    /// Handles *backtrace in* hooks by adding the current instruction's address to the backtrace
    /// vector.
    pub fn hook_in<LD, GD>(args: &mut HookArgs<LD, GD>) -> Result<ExitKind> {
        args.bdata.backtrace.push(args.addr);
        Ok(ExitKind::Continue)
    }

    /// Handles *backtrace out* hooks by removing the most recently added instruction address of
    /// the backtrace vector.
    pub fn hook_out<LD, GD>(args: &mut HookArgs<LD, GD>) -> Result<ExitKind> {
        args.bdata.backtrace.pop();
        Ok(ExitKind::Continue)
    }

    /// Hashes backtrace PCs to get a unique crash identifier.
    pub fn get_crash_hash(bt: &Backtrace) -> u64 {
        let mut hash = 0;
        for pc in bt.backtrace.iter() {
            hash ^= pc << 13;
            hash ^= hash >> 7;
            hash ^= hash >> 17;
        }
        hash
    }
}

impl Default for Backtrace {
    fn default() -> Self {
        Self::new()
    }
}
