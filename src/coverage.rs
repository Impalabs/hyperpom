//! Handles everything related to coverage gathering at runtime.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, RwLock};

use applevisor as av;

use crate::core::*;
use crate::crash::*;
use crate::error::*;
use crate::hooks::*;
use crate::memory::*;

/// A range of virtual addresses where coverage is applied. Arguments are the range's start and
/// end address.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CoverageRange(pub(crate) std::ops::Range<u64>);

impl CoverageRange {
    /// Creates a new coverage range.
    ///
    /// This structure is instanciated by the [`Loader`](crate::loader::Loader) in
    /// [`Loader::coverage_ranges`](crate::loader::Loader::coverage_ranges) to specify which
    /// virtual address ranges should be covered. We can't just instrument everything, because of
    /// data sections found in code ranges that could be interpreted as instructions. The onus is
    /// on the user to identify which ranges are actual code ranges.
    pub fn new(start: u64, end: u64) -> Self {
        Self(start..end)
    }
}

/// Contains coverage information for one testcase executed by one worker.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Coverage {
    /// Binary tree set that contains the address of the local worker coverage associated to the
    /// current testcase.
    pub set: BTreeSet<u128>,
}

impl Coverage {
    /// Instanciates a new structure containing coverage information.
    pub fn new() -> Self {
        Self {
            set: BTreeSet::new(),
        }
    }

    /// Reset the coverage information.
    pub fn clear(&mut self) {
        self.set.clear();
    }

    /// Returns the number of PCs covered.
    pub fn count(&self) -> usize {
        self.set.len()
    }
}

impl Default for Coverage {
    fn default() -> Self {
        Self::new()
    }
}

/// Non-thread safe version of [`GlobalCoverage`].
#[derive(Clone, Debug)]
pub struct GlobalCoverageInner {
    /// Structure that contains the aggregated coverage information from all fuzzing workers.
    pub(crate) coverage: Coverage,
    /// The virtual address ranges where coverage hooks can be placed without risking any
    /// data corruption that could lead to unwanted crashes or undefined behaviours.
    ranges: Vec<CoverageRange>,
    /// Contains a set of hashed backtrace to deduplicate crashes.
    known_crashes: HashSet<u64>,
}

impl GlobalCoverageInner {
    /// Creates a new global coverage structure.
    fn new(ranges: Vec<CoverageRange>) -> Self {
        Self {
            coverage: Coverage::new(),
            ranges,
            known_crashes: HashSet::new(),
        }
    }
}

/// Global coverage structure shared between threads and updated after each testcase run.
///
/// # Role of Coverage in the Fuzzer
///
/// Coverage-guided fuzzing is used in a lot of modern fuzzers nowadays (e.g. LibFuzzer,
/// HonggFuzz, etc.). The idea is to gather information during the execution of a program to
/// identify which parts have actually been executed. The information gathered can be of different
/// types (addresses, stack frames generated, etc.) and so do gathering methods (hardware
/// mechanisms, hooks added at compile-time / runtime, etc.).
///
/// While using coverage is not necessary and can hinder performances, it's a decent strategy for
/// a generic fuzzer unaware of the input formats expected by the program, since the generated
/// data can be used to identify interesting testcases (e.g. if they cover new paths).
///
/// # Coverage Implementation
///
/// ## Coverage
///
/// Coverage is implemented in this fuzzer by hooking instructions that perform arbitrary or
/// conditional branching, namely:
///
///  * all the `b.cond` instructions;
///  * `cbz` and `cbnz`;
///  * `tbz` and `tbnz`;
///  * `blr` and `br`.
///
/// The hooking function used for coverage is [`GlobalCoverage::hook_coverage`] and is placed while
/// initializing the fuzzed program's virtual space using [`GlobalCoverage::add_hooks`].
///
/// **Note:** for more information on hooking, you can refer to [`Hooks`](crate::hooks::Hooks).
///
/// Although, placing these hooks is a little bit complicated on ARM systems: it's possible to
/// have data sections, such as literal pools, wove into code sections. If we were to
/// indiscriminately place hooks on any byte sequences that can be disassembled into the
/// instructions listed above, we could corrupt one of these data sections, which might result in
/// unwanted crashes or undefined behaviours. To prevent this from happening, the user is
/// responsible for defining the ranges where coverage should be applied by implementing
/// [`Loader::code_ranges`](crate::loader::Loader::code_ranges) from the
/// [`Loader`](crate::loader::Loader) trait. This function will return a list of [`CoverageRange`]s
/// defining the virtual address ranges that are safe to hook.
///
/// Once a program is running on a worker, coverage hooks that are hit take the current address
/// and store it into a [`Coverage`] object. Each worker owns an instance of this structure.
/// To make fuzzing more efficient, coverage information are shared between all workers using
/// [`GlobalCoverage`]. At the end of each iteration, a worker take the coverage information that
/// was generated from the current testcase and compare it to the global one. If new paths have
/// been found, the testcase is added to the corpus so it can be reused and mutated to reach
/// increasingly deeper execution paths.
///
/// Additionally, since the only information we're interested in here is whether or not new paths
/// have been hit, keeping hooks for paths that have already been covered is redundant. We can then
/// get better performances by removing coverage hooks corresponding to new paths using
/// [`Hooks::revert_coverage_hooks`](crate::hooks::Hooks::revert_coverage_hooks).
///
/// ## Comparison Unrolling
///
/// One of the main roadblocks to overcome while fuzzing is handling comparisons with constant
/// magic values. For example, imagine that we have a program that checks that our input starts
/// with `0xdeadbeef` before processing it.
///
/// ```
/// if u32::from_le_bytes(input[0..4]) == 0xdeadbeef {
///     process();
/// } else {
///     exit();
/// }
/// ```
///
/// The fuzzer would have to guess 32 bits in a single iteration, which is very unlikely and would
/// stall the fuzzer until it guesses it correctly.
///
/// There are different approaches possible to solve this problem, like hooking comparisons to
/// always pass them or informing the mutator of the comparison value to generate a custom testcase
/// with it. This fuzzer implements comparison unrolling. The idea is to take a comparison on a
/// multi-byte value and split it into multiple single-byte comparisons.
///
/// ```
/// if input[3] == 0xde {
///     if input[2] == 0xad {
///         if input[1] == 0xbe {
///             // [...]
///         }
///     }
/// }
/// ```
///
/// When the fuzzer is initialized, it looks for every comparison instructions it can find and
/// then place a [`GlobalCoverage::hook_cmp`] hook on them. This function takes the hooked
/// comparison instruction, disassemble it to retrieve the values being compared and adds a path
/// for every byte it manages to guess correctly.
///
/// One of the issue with this implementation is that it adds new testcases for input values that
/// partially match. Once we have a testcase that pass the comparison, the other intermediate
/// testcases are less likely to produce interesting results and are mostly clogging up the input
/// queue at this point. A possible way to improve the fuzzer in the future would be to add an
/// additional queue for these intermediate testcases that would be flushed when the comparison
/// is no longer an issue.
#[derive(Clone, Debug)]
pub struct GlobalCoverage {
    pub inner: Arc<RwLock<GlobalCoverageInner>>,
}

impl GlobalCoverage {
    /// Instructions updating coverage.
    const B_INSNS: &'static [&'static str] = &[
        "b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "b.ge",
        "b.lt", "b.gt", "b.le", "b.al", "cbnz", "cbz", "tbnz", "tbz", "blr", "br",
    ];
    /// Instructions that influence conditional behavior.
    const CMP_INSNS: &'static [&'static str] = &["cmp", "subs"];

    /// Instanciantes a new shared global coverage structure using user-provided virtual memory
    /// ranges where coverage should be applied.
    pub fn new(ranges: Vec<CoverageRange>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(GlobalCoverageInner::new(ranges))),
        }
    }

    /// Returns a copy of the inner coverage structure.
    pub fn cloned(&self) -> Coverage {
        let inner = self.inner.read().unwrap();
        inner.coverage.clone()
    }

    /// Returns the number of PCs covered.
    pub fn count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.coverage.count()
    }

    /// Adds coverage hooks to the fuzzed program.
    ///
    /// There are two hook types:
    ///
    ///  * *coverage* hooks that updates the global coverage map;
    ///  * *comparison* hooks that perform comparison unrolling and update the global coverage map
    ///    when a new byte is matched.
    pub fn add_hooks<LD: Clone, GD: Clone>(
        &self,
        vma: &VirtMemAllocator,
        hooks: &mut Hooks<LD, GD>,
        comparison_unrolling: bool,
    ) -> Result<()> {
        let inner = self.inner.read().unwrap();
        // Iterates over the code ranges.
        for CoverageRange(range) in inner.ranges.iter() {
            // In a given range, iterates over each instruction address.
            for addr in range.clone().step_by(4) {
                // Reads the instruction at the current address.
                let mut code = [0; 4];
                vma.read(addr, &mut code)?;
                // Disassemble the instruction and returns a tuple that contains:
                //
                //  * if the instruction influences coverage;
                //  * if the instruction is a comparison.
                let (cov, cmp) = CSE.with(|cs| {
                    let insns = cs
                        .disasm_count(&code, addr, 1)
                        .expect("could not disassemble while adding coverage hooks");
                    if let Some(insn) = insns.as_ref().first() {
                        (
                            Self::B_INSNS.contains(&insn.mnemonic().unwrap()),
                            Self::CMP_INSNS.contains(&insn.mnemonic().unwrap()),
                        )
                    } else {
                        (false, false)
                    }
                });
                // Adds the corresponding hook(s) depending on the instruction type.
                if cov {
                    hooks.add_coverage_hook(addr, GlobalCoverage::hook_coverage);
                } else if comparison_unrolling && cmp {
                    hooks.add_coverage_hook(addr, GlobalCoverage::hook_cmp);
                }
            }
        }
        Ok(())
    }

    /// Checks if the crash already exists in the list of known crashes and inserts it if it's
    /// not the case. Returns `true` if the crash is new, `false` otherwise.
    pub fn update_new_crashes(&mut self, hash: u64) -> bool {
        let inner = self.inner.read().unwrap();
        if inner.known_crashes.contains(&hash) {
            false
        } else {
            drop(inner);
            let mut inner = self.inner.write().unwrap();
            inner.known_crashes.insert(hash);
            true
        }
    }

    /// Checks if the coverage computed by the current worker adds new path to the global coverage.
    /// If it's the case, the function adds the new paths covered to the global coverage map and
    /// returns `true` to signal that the current testcase yielded interesting results and should
    /// be added to the corpus.
    pub fn update_new_coverage(&self, other: &Coverage) -> Option<u64> {
        let inner = self.inner.read().unwrap();
        if other.set.is_subset(&inner.coverage.set) {
            None
        } else {
            drop(inner);
            let mut inner = self.inner.write().unwrap();
            // Make sure it's still a subset, because another thread might have updated the
            // coverage right after the lock was dropped.
            if other.set.is_subset(&inner.coverage.set) {
                None
            } else {
                let old_size = inner.coverage.set.len();
                inner.coverage.set = inner.coverage.set.union(&other.set).copied().collect();
                Some((inner.coverage.set.len() - old_size) as u64)
            }
        }
    }

    /// Handles coverage hooks and adds the current instruction's address to the local worker
    /// coverage.
    pub fn hook_coverage<LD, GD>(args: &mut HookArgs<LD, GD>) -> Result<ExitKind> {
        args.cdata.set.insert(args.addr as u128);
        Ok(ExitKind::Continue)
    }

    /// Handles comparison hooks by disassembling the current instruction, retrieving the compared
    /// value and adding new paths based on how many bytes match.
    pub fn hook_cmp<LD, GD>(args: &mut HookArgs<LD, GD>) -> Result<ExitKind> {
        let addr = args.addr as u128;
        let value = Comparisons::get_value(args.insn_int, args.vcpu)?;
        match value {
            ComparisonResult::U64(reg_value, cmp_value) => {
                for i in (0u128..8u128).rev() {
                    if (reg_value >> (i * 8)) & 0xff == (cmp_value >> (i * 8)) & 0xff {
                        let pc = ((i + 1) << 0x30) | addr;
                        args.cdata.set.insert(pc);
                    } else {
                        break;
                    }
                }
            }
            ComparisonResult::U32(reg_value, cmp_value) => {
                for i in (0u128..4u128).rev() {
                    if (reg_value >> (i * 8)) & 0xff == (cmp_value >> (i * 8)) & 0xff {
                        let pc = ((i + 1) << 0x30) | addr;
                        args.cdata.set.insert(pc);
                    } else {
                        break;
                    }
                }
            }
            _ => {}
        }
        Ok(ExitKind::Continue)
    }
}

// -----------------------------------------------------------------------------------------------
// Coverage - Comparisons
// -----------------------------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
/// Operands of a comparison instruction.
enum ComparisonResult {
    /// 32-bit operands.
    U32(u32, u32),
    /// 64-bit operands.
    U64(u64, u64),
    /// Other instruction.
    Other,
}

/// Empty structure that represents the comparison emulator of the fuzzer.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
struct Comparisons;

impl Comparisons {
    /// Retrieves the operands of a comparison instruction.
    fn get_value(insn: u32, vcpu: &av::Vcpu) -> Result<ComparisonResult> {
        match insn {
            // -----------------------------------------------------------------------------------
            // Add/subtract (immediate)
            // -----------------------------------------------------------------------------------
            // SUBS (immediate)
            i if (i >> 23) & 0xff == 0b11100010 => Self::subs_immediate(i, vcpu),
            // -----------------------------------------------------------------------------------
            // Add/subtract (shifted registers)
            // -----------------------------------------------------------------------------------
            // SUBS (shifted registers)
            i if (i >> 24) & 0x7f == 0b1101011 => Self::subs_shifted_reg(i, vcpu),
            _ => Ok(ComparisonResult::Other),
        }
    }

    /// Returns the value stored in a register based on an instruction operand value.
    fn get_operand(vcpu: &av::Vcpu, rd: u32) -> Result<u64> {
        match rd {
            0 => Ok(vcpu.get_reg(av::Reg::X0)?),
            1 => Ok(vcpu.get_reg(av::Reg::X1)?),
            2 => Ok(vcpu.get_reg(av::Reg::X2)?),
            3 => Ok(vcpu.get_reg(av::Reg::X3)?),
            4 => Ok(vcpu.get_reg(av::Reg::X4)?),
            5 => Ok(vcpu.get_reg(av::Reg::X5)?),
            6 => Ok(vcpu.get_reg(av::Reg::X6)?),
            7 => Ok(vcpu.get_reg(av::Reg::X7)?),
            8 => Ok(vcpu.get_reg(av::Reg::X8)?),
            9 => Ok(vcpu.get_reg(av::Reg::X9)?),
            10 => Ok(vcpu.get_reg(av::Reg::X10)?),
            11 => Ok(vcpu.get_reg(av::Reg::X11)?),
            12 => Ok(vcpu.get_reg(av::Reg::X12)?),
            13 => Ok(vcpu.get_reg(av::Reg::X13)?),
            14 => Ok(vcpu.get_reg(av::Reg::X14)?),
            15 => Ok(vcpu.get_reg(av::Reg::X15)?),
            16 => Ok(vcpu.get_reg(av::Reg::X16)?),
            17 => Ok(vcpu.get_reg(av::Reg::X17)?),
            18 => Ok(vcpu.get_reg(av::Reg::X18)?),
            19 => Ok(vcpu.get_reg(av::Reg::X19)?),
            20 => Ok(vcpu.get_reg(av::Reg::X20)?),
            21 => Ok(vcpu.get_reg(av::Reg::X21)?),
            22 => Ok(vcpu.get_reg(av::Reg::X22)?),
            23 => Ok(vcpu.get_reg(av::Reg::X23)?),
            24 => Ok(vcpu.get_reg(av::Reg::X24)?),
            25 => Ok(vcpu.get_reg(av::Reg::X25)?),
            26 => Ok(vcpu.get_reg(av::Reg::X26)?),
            27 => Ok(vcpu.get_reg(av::Reg::X27)?),
            28 => Ok(vcpu.get_reg(av::Reg::X28)?),
            29 => Ok(vcpu.get_reg(av::Reg::X29)?),
            30 => Ok(vcpu.get_reg(av::Reg::LR)?),
            31 => Ok(vcpu.get_reg(av::Reg::PC)?),
            _ => unreachable!("invalid operand"),
        }
    }

    // -------------------------------------------------------------------------------------------
    // Add/subtract (immediate)
    // -------------------------------------------------------------------------------------------

    #[inline]
    /// Retrieves the operands from a SUBS (immediate).
    fn subs_immediate(insn: u32, vcpu: &av::Vcpu) -> Result<ComparisonResult> {
        let imm = (insn >> 10) & 0xfff;
        let sh = (insn >> 22) & 1;
        let value = imm << (12 * sh);
        let sf = ((insn >> 31) & 1) == 1;
        let rn = (insn >> 5) & 0x1f;
        let rn_val = Self::get_operand(vcpu, rn)?;
        if sf {
            Ok(ComparisonResult::U64(rn_val, value as u64))
        } else {
            Ok(ComparisonResult::U32(rn_val as u32, value))
        }
    }

    // -------------------------------------------------------------------------------------------
    // Add/subtract (shifted registers)
    // -------------------------------------------------------------------------------------------

    #[inline]
    /// Retrieves the operands from a SUBS (shifted registers).
    fn subs_shifted_reg(insn: u32, vcpu: &av::Vcpu) -> Result<ComparisonResult> {
        let rn = (insn >> 5) & 0x1f;
        let rn_val = Self::get_operand(vcpu, rn)?;
        let rm = (insn >> 16) & 0x1f;
        let rm_val = Self::get_operand(vcpu, rm)?;
        let shift_amount = (insn >> 10) & 0x3f;
        let shift_type = (insn >> 22) & 3;
        let sf = ((insn >> 31) & 1) == 1;
        if sf && (shift_amount >> 5) == 1 {
            return Ok(ComparisonResult::Other);
        }
        if sf {
            Ok(match shift_type {
                0b00 => ComparisonResult::U64(rn_val, rm_val << shift_amount),
                0b01 => ComparisonResult::U64(rn_val, rm_val >> shift_amount),
                0b10 => ComparisonResult::U64(rn_val, ((rm_val as i64) >> shift_amount) as u64),
                _ => return Ok(ComparisonResult::Other),
            })
        } else {
            Ok(match shift_type {
                0b00 => ComparisonResult::U32(rn_val as u32, (rm_val as u32) << shift_amount),
                0b01 => ComparisonResult::U32(rn_val as u32, (rm_val as u32) >> shift_amount),
                0b10 => {
                    ComparisonResult::U32(rn_val as u32, ((rm_val as i32) >> shift_amount) as u32)
                }
                _ => return Ok(ComparisonResult::Other),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cov_cmp_subs_immediate() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates a new Vcpu
        let vcpu = av::Vcpu::new().unwrap();
        vcpu.set_reg(av::Reg::X0, 0xdeadbeefdeadbeef).unwrap();
        // cmp x0, #0x123 - subs xzr, x0, #0x123
        let insn = 0xf1048c1fu32;
        let value = Comparisons::get_value(insn, &vcpu);
        assert_eq!(value, Ok(ComparisonResult::U64(0xdeadbeefdeadbeef, 0x123)));
        // cmp w0, #0x345 - subs xzr, x0, #0x345
        let insn = 0x710d141fu32;
        let value = Comparisons::get_value(insn, &vcpu);
        assert_eq!(value, Ok(ComparisonResult::U32(0xdeadbeef, 0x345)));
        // cmp x0, #0x678000 - subs xzr, x0, #0x678000
        let insn = 0xf159e01fu32;
        let value = Comparisons::get_value(insn, &vcpu);
        assert_eq!(
            value,
            Ok(ComparisonResult::U64(0xdeadbeefdeadbeef, 0x678000))
        );
        // cmp w0, #0x912000 - subs wzr, w0, #0x912000
        let insn = 0x7164481fu32;
        let value = Comparisons::get_value(insn, &vcpu);
        assert_eq!(value, Ok(ComparisonResult::U32(0xdeadbeef, 0x912000)));
    }
}
