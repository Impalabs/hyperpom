//! Handles everything related to instruction tracing.

use crate::core::*;
use crate::crash::*;
use crate::error::*;
use crate::hooks::*;

/// A range of virtual addresses where tracing is applied. Arguments are the range's start and
/// end address.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct TraceRange(pub(crate) std::ops::Range<u64>);

impl TraceRange {
    /// Creates a new tracing range.
    ///
    /// This structure is instanciated by the [`crate::loader::Loader`] in
    /// [`crate::loader::Loader::trace_ranges`] to specify which virtual address ranges tracing
    /// should be applied to. We can't just instrument everything, because of data sections
    /// found in code ranges that could be interpreted as instructions. The onus is on the user to
    /// identify which ranges are actual code ranges.
    pub fn new(start: u64, end: u64) -> Self {
        Self(start..end)
    }
}

/// Structure that defines hooks handling instruction tracing operations.
///
/// # Role of Tracing in the Fuzzer
///
/// Tracing systems usually display or store all the instructions executed during a given test-run.
/// This system is not directly used by the fuzzer, but it can be a really helpful debugging tool
/// to analyze a crash or understand why the fuzzer is not behaving as it should (e.g. observing
/// where a fuzzer is stuck, understanding why it's not producing new paths anymore, etc.).
///
/// # Tracing Implementation
///
/// The current implementation is extremely primitive. It hooks all instructions found in the
/// user-defined [`TraceRange`] with [`Tracer::hook`]. This hook simply displays in `stdout` the
/// instruction currently executed.
///
/// Future versions could include output to known trace formats (gcov, tenet, etc.) to have a more
/// efficient and user-friendly way of analyzing traces.
pub struct Tracer;

impl Tracer {
    /// Adds tracing hooks to the fuzzed program.
    pub fn add_hooks<LD: Clone, GD: Clone>(
        ranges: Vec<TraceRange>,
        hook: Option<HookFn<LD, GD>>,
        hooks: &mut Hooks<LD, GD>,
    ) -> Result<()> {
        let hook = if let Some(tracer_hook) = hook {
            tracer_hook
        } else {
            Tracer::hook
        };
        for TraceRange(range) in ranges.into_iter() {
            for addr in range.step_by(4) {
                hooks.add_tracer_hook(addr, hook);
            }
        }
        Ok(())
    }

    /// Handles tracing hooks and displays the current instruction to `stdout`.
    pub fn hook<LD, GD>(args: &mut HookArgs<LD, GD>) -> Result<ExitKind> {
        CSE.with(|cs| {
            let insns = cs
                .disasm_count(args.insn, args.addr, 1)
                .expect("could not disassemble while adding coverage hooks");
            let insn = insns.as_ref().first().unwrap();
            println!("{}", insn);
        });
        Ok(ExitKind::Continue)
    }
}
