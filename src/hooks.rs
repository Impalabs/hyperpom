//! Handles instruction hooking and emulation of branch instructions.

use std::collections::{hash_map::Entry, HashMap};
use std::sync::{Arc, RwLock};

use applevisor as av;
use bitfield::bitfield;

use crate::backtrace::*;
use crate::caches::*;
use crate::coverage::*;
use crate::crash::*;
use crate::error::*;
use crate::memory::*;

// -----------------------------------------------------------------------------------------------
// Hooks
// -----------------------------------------------------------------------------------------------

/// Represents the types of hook implemented for the fuzzer.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum HookType {
    /// First stage handler hook.
    /// You can refer to [`Hooks`] for more information.
    HandlerStage1,
    /// Second stage handler hook.
    /// You can refer to [`Hooks`] for more information.
    HandlerStage2,
    /// A hook that stops the execution of the current [`applevisor::Vcpu`] and stops the
    /// corresponding thread.
    Exit,
    /// Used for unknown hook types.
    Unknown(u16),
}

impl From<u16> for HookType {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::HandlerStage1,
            1 => Self::HandlerStage2,
            0xffff => Self::Exit,
            u => Self::Unknown(u),
        }
    }
}

/// Fuzzer structures passed as argument to a hook.
pub struct HookArgs<'a, LD, GD> {
    /// Hook address.
    pub addr: u64,
    /// Hooked instruction.
    pub insn: &'a [u8],
    /// Hooked instruction as an integer.
    pub insn_int: u32,
    /// VCPU state.
    pub vcpu: &'a mut av::Vcpu,
    /// Virtual address space.
    pub vma: &'a mut VirtMemAllocator,
    /// Snapshot of the virtual address space.
    pub vma_snapshot: &'a VirtMemAllocator,
    /// Local data.
    pub ldata: &'a mut LD,
    /// Global data.
    pub gdata: &'a RwLock<GD>,
    /// Backtrace data.
    pub bdata: &'a mut Backtrace,
    /// Coverage data.
    pub cdata: &'a mut Coverage,
}

/// Type defining the function pointer signature for hooks.
pub type HookFn<LD, GD> = fn(&mut HookArgs<LD, GD>) -> Result<ExitKind>;

/// A user-applied hook that exits from the current thread iteration if it's reached.
#[derive(Clone)]
pub struct ExitHook {
    /// Saves the instruction at the hook's location.
    insn: [u8; 4],
    /// `true` if the hook is in-effect in the address space, `false` otherwise.
    applied: bool,
}

impl ExitHook {
    /// Creates a new exit hook.
    fn new() -> Self {
        Self {
            insn: [0; 4],
            applied: false,
        }
    }
}

impl std::default::Default for ExitHook {
    fn default() -> Self {
        ExitHook::new()
    }
}

/// Represents a hook applied by the fuzzer at a given location.
///
/// One instance contains four types of hooks: custom, coverage, backtrace and tracer.
///
/// Only one hook of each types can be applied and hooks are called when a Vcpu reaches the
/// hooked address.
#[derive(Clone)]
struct Hook<LD, GD> {
    /// Saves the instruction at the hook's location.
    insn: [u8; 4],
    /// Saves the instruction executed after the hook.
    next_insn: Option<[u8; 4]>,
    /// Contains a user-defined handler.
    custom_handler: Option<HookFn<LD, GD>>,
    /// Contains a coverage handler.
    coverage_handler: Option<HookFn<LD, GD>>,
    /// Contains a coverage handler.
    backtrace_handler: Option<HookFn<LD, GD>>,
    /// Contains a tracer handler.
    tracer_handler: Option<HookFn<LD, GD>>,
    /// `true` if the hook is in-effect in the address space, `false` otherwise.
    applied: bool,
}

impl<LD, GD> Hook<LD, GD> {
    /// Creates a hook and adds a custom handler to it.
    fn with_custom(handler: HookFn<LD, GD>) -> Self {
        Self {
            insn: [0; 4],
            next_insn: None,
            custom_handler: Some(handler),
            coverage_handler: None,
            backtrace_handler: None,
            tracer_handler: None,
            applied: false,
        }
    }

    /// Creates a hook and adds a coverage handler to it.
    fn with_coverage(handler: HookFn<LD, GD>) -> Self {
        Self {
            insn: [0; 4],
            next_insn: None,
            custom_handler: None,
            coverage_handler: Some(handler),
            backtrace_handler: None,
            tracer_handler: None,
            applied: false,
        }
    }

    /// Creates a hook and adds a backtrace handler to it.
    fn with_backtrace(handler: HookFn<LD, GD>) -> Self {
        Self {
            insn: [0; 4],
            next_insn: None,
            custom_handler: None,
            coverage_handler: None,
            backtrace_handler: Some(handler),
            tracer_handler: None,
            applied: false,
        }
    }

    /// Creates a hook and adds a tracer handler to it.
    fn with_tracer(handler: HookFn<LD, GD>) -> Self {
        Self {
            insn: [0; 4],
            next_insn: None,
            custom_handler: None,
            coverage_handler: None,
            backtrace_handler: None,
            tracer_handler: Some(handler),
            applied: false,
        }
    }
}

/// Manages and handles instruction hooks.
///
/// # Role of Instruction Hooking in the Fuzzer
///
/// The ability to place arbitrary function hooks is a fondamental part of the fuzzer. It allows us
/// to instrument and get information about binary programs at runtime. With the current
/// implementation in the fuzzer we can:
///
///  * get coverage information;
///  * trace executed instructions;
///  * call user-defined functions.
///
/// # Hooking Implementation
///
/// ## Instructions That Do Not Alter the Execution Flow
///
/// In the current implementation of the hypervisor by Apple, there are no built-in mechanism for
/// hooking. We can't, for example, stop the execution at a specific address and execute arbitrary
/// functions from there.
///
/// The only way we have to stop the execution of a guest VM at a specific address is through
/// exceptions. In our implementation this is achieved using breakpoints.
///
/// A breakpoint is placed at an arbitrary address, when the program reaches it, it raises an
/// exception to the hypervisor and then we can check in the fuzzer if a handler exists at this
/// address.
///
/// ```text
///   Original instructions           Hooked instructions
///   +----------------------+        +----------------------+
///   | 0x00: mov x0, 0x42   |        | 0x00: mov x0, 0x42   |
///   | 0x04: mov x1, 0x43   |------->| 0x04: brk #0  --------------> executes handler
///   | 0x08: add x0, x0, x1 |        | 0x08: add x0, x0, x1 |        for address 0x04
///   | 0x0c: ret            |        | 0x0c: ret            |
///   +----------------------+        +----------------------+
/// ```
///
/// Running a hook when a given address is reached is easy. Resuming the execution from this state
/// is the hard part. The first issue we encounter is that we need to execute the instruction
/// that was replaced by the breakpoint.
///
/// If we could execute a given number of instructions and have the hypervisor return on its own,
/// we could just replace the breakpoint by the original instruction, run this one instruction,
/// return to the fuzzer and place the hook again. Unfortunately it's not currently possible.
///
/// Another possible solution would have been to write small handlers somewhere in memory that
/// contain the instructions we want to run. After the hook has returned, we could jump to one
/// of them, execute the instruction, before jumping back right after the original hook's location.
/// However, many ARM instructions are PC-relative and we would either have to reassemble them or
/// move some other code chunks (such as ARM literal pools) to match the expected memory layout.
///
/// As we'll see in this section and the next, the solution implemented in this fuzzer is a rough
/// combination of both of these approaches. First we'll explain how we can execute one instruction
/// at a time by dividing hook handling in two stages.
///
///  * In the first stage, a breakpoint `brk #0` is placed on the instruction we want to place a
///    hook on. When the guest reaches the breapoint an exception is raised to the hypervisor. The
///    hypervisor retrieves the address of the instruction and checks if a hook exists. If it's the
///    case, the hook is executed. Then the original instruction is restored while the instruction
///    that follows is replaced by a second breakpoint. Execution is resumed from the instruction
///    that was restored.
///
///  * In the second stage, when the second breakpoint is hit, another exception is raised to the
///    hypervisor. We restore the second instruction and we reapply the breakpoint on the first
///    instruction. This way, the hook can still trigger if the execution flow reaches it again.
///
/// ```text
///                   +----------------------+
///                   | Saves instruction at |
///                   | address 0x04 and     |
///                   | replaces it with a   |
///                   | breakpoint           |
///                   +----------------------+
///                      ^                |
/// HYPERVISOR           |                |
/// ---------------------|----------------|-------------------------------------------------------
/// GUEST VM             |                |
///                      |                v
///   +------------------+---+        +----------------------+
///   | 0x00: mov x0, 0x42   |        | 0x00: mov x0, 0x42   |
///   | 0x04: mov x1, 0x43   |        | 0x04: brk #0  -------------+
///   | 0x08: add x0, x0, x1 |        | 0x08: add x0, x0, x1 |     |
///   | 0x0c: ret            |        | 0x0c: ret            |     |
///   +----------------------+        +----------------------+     | Exception raised by
///   Original instructions           Hooked instructions          | the stage 1 breakpoint
///                                   (stage 1)                    |
///                                                                |
///                      +-----------------------------------------+
/// GUEST VM             |
/// ---------------------|------------------------------------------------------------------------
/// HYPERVISOR           |
///                      v            +----------------------+
///   +----------------------+        | Restores the first   |        +----------------------+
///   | Finds the handler    |        | instruction, saves   |        | Resumes execution    |
///   | for address 0x04 and |------->| the next one and     |------->| from the instruction |
///   | runs it              |        | replaces it by a     |        | at address 0x04      |
///   +----------------------+        | breakpoint           |        +----------+-----------+
///                                   +----------+-----------+                   |
///                                              |                               |
/// HYPERVISOR                  +----------------+-------------------------------+
/// ----------------------------|----------------|------------------------------------------------
/// GUEST VM                    |                |
///                             |                v
///                             |     +----------------------+
///                             |     | 0x00: mov x0, 0x42   |
///                             +---->| 0x04: mov x1, 0x43   |
///                                   | 0x08: brk #1  -------------+
///                                   | 0x0c: ret            |     |
///                                   +----------------------+     |
///                                   Hooked instructions          | Exception raised by
///                                   (stage 2)                    | the stage 2 breakpoint
///                                                                |
///                                              +-----------------+
/// GUEST VM                                     |
/// ---------------------------------------------|------------------------------------------------
/// HYPERVISOR                                   v
///                                   +----------------------+        +----------------------+
///                                   | Restores the second  |        | Resumes execution    |
///                                   | instruction and      |------->| from the instruction |
///                                   | restores the hook    |        | at address 0x08      |
///                                   +----------------------+        +----------+-----------+
///                                              |                               |
/// HYPERVISOR                  +----------------+-------------------------------+
/// ----------------------------|----------------|------------------------------------------------
/// GUEST VM                    |                |
///                             |                v
///                             |     +----------------------+
///                             |     | 0x00: mov x0, 0x42   |
///                             |     | 0x04: brk #0         |
///                             +---->| 0x08: add x0, x0, x1 |
///                                   | 0x0c: ret            |
///                                   +----------------------+
///                                   Hooked instructions
///                                   (hook is reset back to
///                                   stage 1)
/// ```
///
/// ## Instructions Changing the Execution Flow
///
/// Things get a little bit more complicated for instructions that alter the execution flow,
/// instructions such as `bl`, `ret`, etc. We can place the first stage breakpoint, but if we
/// set the second stage breakpoint on the instruction right after, we'll never reach it.
///
/// Fortunately for us, there aren't that many instructions that modify PC and we can simply
/// disassemble them and emulate their behavior.
///
/// For example, let's imagine that we put a hook on a `blr` instruction.
///
/// ```text
///   +----------------------+        +----------------------+
///   | 0x00: mov x0, 0x1000 |        | 0x00: mov x0, 0x1000 |
///   | 0x08: blr x0         |        | 0x08: brk #0         |
///   | 0x0c: ret            |        | 0x0c: ret            |
///   +----------------------+        +----------------------+
///   Original instructions           Hooked instructions
/// ```
///
/// When the execution reaches the breakpoint, it raises an exception to the hypervisor.
/// We disassemble the instruction and since it's a branch, we won't set a stage 2 breakpoint.
/// Instead we retrieve information from the instruction to emulate its behaviour. In our example
/// this means that we read the address to jump to from `x0` and set `lr` to the intruction after
/// the branch, which is `0xc`. The operation performed will depend on the hooked instruction.
/// You can refer to the source code of the private `Emulator` implementation for more
/// information.
///
/// With both categories of instructions handled, we now have a full hooking system that can be
/// used to implement features such as coverage, tracing, etc. The next section describes the types
/// of hooks that can be used with this fuzzer.
///
/// # Hook Types
///
/// There is currently three types of hooks that can be called when hooking an instruction. One
/// instruction can have only one hook of each type. This system could be refactored in the future
/// to be more generic and allow more hooks to be executed, but it should enough for most
/// use-cases.
///
///  * Tracer: hook applied on all instructions by
///            [`Tracer::add_hooks`](crate::tracer::Tracer::add_hooks).
///  * Coverage: hook applied on branch and comparison instructions by
///              [`GlobalCoverage::add_hooks`](crate::coverage::GlobalCoverage::add_hooks).
///  * Backtrace: hook applied on function entries and exits by
///               [`Backtrace::add_hooks`](crate::backtrace::Backtrace::add_hooks).
///  * Custom: user-defined hook applied by the user through
///            [`Executor::add_custom_hook`](crate::core::Executor::add_custom_hook).
///  * Exit: hook that stops the program when it's reached, can applied using
///          [`Executor::add_exit_hook`](crate::core::Executor::add_exit_hook).
#[derive(Clone)]
pub struct Hooks<LD, GD> {
    /// Maps an address to a [`Hook`] object.
    hooks: HashMap<u64, Hook<LD, GD>>,
    /// Maps an address to an [`ExitHook`] object.
    exit_hooks: HashMap<u64, ExitHook>,
}

impl<LD: Clone, GD: Clone> Hooks<LD, GD> {
    /// `brk #0` instruction.
    const BRK_STAGE_1: u32 = 0xd4200000;
    /// `brk #1` instruction.
    const BRK_STAGE_2: u32 = 0xd4200020;
    /// `brk #0xffff` instruction.
    const BRK_EXIT: u32 = 0xd43fffe0;

    /// Creates a new hooks manager.
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
            exit_hooks: HashMap::new(),
        }
    }

    /// Handles the exception raised by a breakpoint which are used by the fuzzer to hook
    /// instructions. Unrecognized breakpoint values return an error.
    ///
    /// # Return Value
    ///
    /// Returns `true` if the thread needs to exit, false otherwise.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn handle(
        &mut self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        vma_snapshot: &VirtMemAllocator,
        ldata: &mut LD,
        gdata: &Arc<RwLock<GD>>,
        cdata: &mut Coverage,
        bdata: &mut Backtrace,
    ) -> Result<ExitKind> {
        let exit = vcpu.get_exit_info();
        match HookType::from(exit.exception.syndrome as u16) {
            HookType::HandlerStage1 => {
                self.hook_stage1(vcpu, vma, vma_snapshot, ldata, gdata, cdata, bdata)
            }
            HookType::HandlerStage2 => self.hook_stage2(vcpu, vma),
            HookType::Exit => Ok(ExitKind::Exit),
            HookType::Unknown(u) => Err(HookError::InvalidHookType(u))?,
        }
    }

    /// Tries to add a hook into the custom handler hashmap using its address.
    pub fn add_exit_hook(&mut self, addr: u64) {
        if let Entry::Vacant(e) = self.exit_hooks.entry(addr) {
            e.insert(ExitHook::new());
        };
    }

    /// Tries to add a hook into the custom handler hashmap using its address.
    pub fn remove_exit_hook(&mut self, addr: u64) {
        self.exit_hooks.remove(&addr);
    }

    /// Tries to add a hook into the custom handler hashmap using its address.
    pub fn add_custom_hook(&mut self, addr: u64, handler: HookFn<LD, GD>) {
        match self.hooks.entry(addr) {
            Entry::Vacant(e) => {
                e.insert(Hook::with_custom(handler));
            }
            Entry::Occupied(mut e) => {
                let _ = e.get_mut().custom_handler.insert(handler);
            }
        };
    }

    /// Removes a hook from the custom handler hashmap using its address.
    /// Returns whether or not the corresponding hook object was deleted.
    pub fn remove_custom_hook(&mut self, addr: u64) -> bool {
        if let Some(hook) = self.hooks.get_mut(&addr) {
            if hook.coverage_handler.is_some()
                || hook.tracer_handler.is_some()
                || hook.backtrace_handler.is_some()
            {
                hook.custom_handler = None;
                false
            } else {
                self.hooks.remove(&addr);
                true
            }
        } else {
            true
        }
    }

    /// Tries to add a hook into the coverage handler hashmap using its address.
    pub fn add_coverage_hook(&mut self, addr: u64, handler: HookFn<LD, GD>) {
        match self.hooks.entry(addr) {
            Entry::Vacant(e) => {
                e.insert(Hook::with_coverage(handler));
            }
            Entry::Occupied(mut e) => {
                let _ = e.get_mut().coverage_handler.insert(handler);
            }
        };
    }

    /// Removes a hook from the coverage handler hashmap using its address.
    /// Returns whether or not the corresponding hook object was deleted.
    pub fn remove_coverage_hook(&mut self, addr: u64) -> bool {
        if let Some(hook) = self.hooks.get_mut(&addr) {
            if hook.custom_handler.is_some()
                || hook.tracer_handler.is_some()
                || hook.backtrace_handler.is_some()
            {
                hook.coverage_handler = None;
                false
            } else {
                self.hooks.remove(&addr);
                true
            }
        } else {
            true
        }
    }

    /// Tries to add a hook into the backtrace handler hashmap using its address.
    pub fn add_backtrace_hook(&mut self, addr: u64, handler: HookFn<LD, GD>) {
        match self.hooks.entry(addr) {
            Entry::Vacant(e) => {
                e.insert(Hook::with_backtrace(handler));
            }
            Entry::Occupied(mut e) => {
                let _ = e.get_mut().backtrace_handler.insert(handler);
            }
        };
    }

    /// Removes a hook from the backtrace handler hashmap using its address.
    /// Returns whether or not the corresponding hook object was deleted.
    pub fn remove_backtrace_hook(&mut self, addr: u64) -> bool {
        if let Some(hook) = self.hooks.get_mut(&addr) {
            if hook.custom_handler.is_some()
                || hook.tracer_handler.is_some()
                || hook.coverage_handler.is_some()
            {
                hook.backtrace_handler = None;
                false
            } else {
                self.hooks.remove(&addr);
                true
            }
        } else {
            true
        }
    }

    /// Tries to add a hook into the tracer handler hashmap using its address.
    pub fn add_tracer_hook(&mut self, addr: u64, handler: HookFn<LD, GD>) {
        match self.hooks.entry(addr) {
            Entry::Vacant(e) => {
                e.insert(Hook::with_tracer(handler));
            }
            Entry::Occupied(mut e) => {
                let _ = e.get_mut().tracer_handler.insert(handler);
            }
        };
    }

    /// Removes a hook from the tracer handler hashmap using its address.
    /// Returns whether or not the corresponding hook object was deleted.
    pub fn remove_tracer_hook(&mut self, addr: u64) -> bool {
        if let Some(hook) = self.hooks.get_mut(&addr) {
            if hook.custom_handler.is_some()
                || hook.coverage_handler.is_some()
                || hook.backtrace_handler.is_some()
            {
                hook.tracer_handler = None;
                false
            } else {
                self.hooks.remove(&addr);
                true
            }
        } else {
            true
        }
    }

    /// Iterates over the hooks in the `hooks` hashmap, saves the instructions at the corresponding
    /// addresses and replaces them with `HandlerStage1` breakpoints.
    pub fn apply(&mut self, vma: &mut VirtMemAllocator) -> Result<()> {
        self.apply_inner(vma, true)
    }

    /// Iterates over the hooks in the `hooks` hashmap, saves the instructions at the corresponding
    /// addresses and replaces them with `HandlerStage1` breakpoints.
    pub fn fill_instructions(&mut self, vma: &mut VirtMemAllocator) -> Result<()> {
        self.apply_inner(vma, false)
    }

    /// Iterates over the hooks in the `hooks` hashmap, saves the instructions at the corresponding
    /// addresses and replaces them with `HandlerStage1` breakpoints.
    pub fn apply_inner(&mut self, vma: &mut VirtMemAllocator, apply: bool) -> Result<()> {
        // Applies custom hooks.
        for (&addr, hook) in self.hooks.iter_mut() {
            if !hook.applied {
                vma.read(addr, &mut hook.insn)?;
                if apply {
                    vma.write_dword(addr, Self::BRK_STAGE_1)?;
                    hook.applied = true;
                }
            }
        }
        // Applies exit hooks.
        for (&addr, hook) in self.exit_hooks.iter_mut() {
            if !hook.applied {
                vma.read(addr, &mut hook.insn)?;
                if apply {
                    vma.write_dword(addr, Self::BRK_EXIT)?;
                    hook.applied = true;
                }
            }
        }
        Ok(())
    }

    /// Removes coverage hooks in the current virtual address space and in its snapshot at address
    /// `addr`.
    #[inline]
    pub fn revert_coverage_hooks(
        &mut self,
        addr: u64,
        vma: &mut VirtMemAllocator,
        vma_snapshot: &mut VirtMemAllocator,
    ) -> Result<()> {
        // Checks if a hook exists at this address.
        if let Some(hook) = self.hooks.get_mut(&addr) {
            if hook.custom_handler.is_some()
                || hook.tracer_handler.is_some()
                || hook.backtrace_handler.is_some()
            {
                // If there are other handlers associated with the hook object, we just remove the
                // coverage handler, but leave the rest...
                hook.coverage_handler = None;
            } else {
                // However, if the object exists only to provide coverage information, we can
                // remove the breakpoint and restore the current and next instructions. Although,
                // even if the object is basically empty, we don't remove it because another hook
                // object might depend on it to restore its next instruction (i.e. the instruction
                // at address+4).
                // Restoring the instructions is performed on both the current VMA and its
                // snapshot. If we only did it on the snapshot, it's unlikely the change would be
                // applied to the VMA since code pages are generally non-writable and we only
                // restore pages that have been modified.
                vma.write(addr, &hook.insn)?;
                vma_snapshot.write(addr, &hook.insn)?;
                // Restores the next instruction if needed.
                if let Some(next_insn) = hook.next_insn {
                    if let Some(next_hook) = self.hooks.get(&(addr + 4)) {
                        // If a hook exists on the next instruction, we use the instruction stored
                        // in this hook, because the `next_insn` field in the hook object for the
                        // current address might be the stage 1 breakpoint of the other hook
                        // object.
                        vma.write(addr + 4, &next_hook.insn)?;
                        vma_snapshot.write(addr + 4, &next_hook.insn)?;
                    } else {
                        vma.write(addr + 4, &next_insn)?;
                        vma_snapshot.write(addr + 4, &next_insn)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handles the `brk #0` instruction by running the handlers associated to the hooked address
    /// and setting up the hook's second stage (if needed).
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn hook_stage1(
        &mut self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        vma_snapshot: &VirtMemAllocator,
        ldata: &mut LD,
        gdata: &Arc<RwLock<GD>>,
        cdata: &mut Coverage,
        bdata: &mut Backtrace,
    ) -> Result<ExitKind> {
        let addr = vcpu.get_reg(av::Reg::PC)?;
        let hook = self
            .hooks
            .get_mut(&addr)
            .ok_or(HookError::UnknownHook(addr))?;
        let insn = u32::from_le_bytes(hook.insn);
        let mut args = HookArgs {
            addr,
            insn: &hook.insn,
            insn_int: insn,
            vcpu,
            vma,
            vma_snapshot,
            ldata,
            gdata,
            bdata,
            cdata,
        };
        // Executes the tracer hook.
        let tracer_res = if let Some(tracer_handler) = hook.tracer_handler {
            tracer_handler(&mut args)?
        } else {
            ExitKind::Continue
        };
        // Executes the custom hook.
        let custom_res = if let Some(custom_handler) = hook.custom_handler {
            custom_handler(&mut args)?
        } else {
            ExitKind::Continue
        };
        // Executes the coverage hook.
        let coverage_res = if let Some(coverage_handler) = hook.coverage_handler {
            coverage_handler(&mut args)?
        } else {
            ExitKind::Continue
        };
        // Executes the backtrace hook.
        let backtrace_res = if let Some(backtrace_handler) = hook.backtrace_handler {
            backtrace_handler(&mut args)?
        } else {
            ExitKind::Continue
        };

        // If one of the hook results is a crash, a timeout or an exit request, we return and
        // propagate the return value.
        match (custom_res.clone(), coverage_res, tracer_res, backtrace_res) {
            (x, _, _, _) | (_, x, _, _) | (_, _, x, _) | (_, _, _, x)
                if x != ExitKind::Continue =>
            {
                match x {
                    ExitKind::Crash(_) | ExitKind::Timeout | ExitKind::Exit => return Ok(x),
                    _ => {}
                }
            }
            _ => {}
        }

        // If a custom hooks early returned from a function (i.e. didn't let the function use the
        // `ret` instruction to return), the backtrace hook will not have triggered and we need to
        // do it explicitely.
        if let ExitKind::EarlyFunctionReturn = custom_res {
            bdata.backtrace.pop();
        }

        // We compare pc with our previously stored value. If it changed, it means one of the hooks
        // modified it explicitly and we just continue the execution without caring about other
        // breakpoints.
        let new_addr = vcpu.get_reg(av::Reg::PC)?;
        if addr != new_addr {
            return Ok(ExitKind::Continue);
        }

        let emu_res = Emulator::emulate(insn, vcpu)?;
        // Updates the return address depending on the instruction that was hooked.
        match emu_res {
            EmulationResult::BranchRel(offset) => {
                let addr = if offset >= 0 {
                    addr + offset as u64
                } else {
                    (addr as i64 + offset as i64) as u64
                };
                vcpu.set_reg(av::Reg::PC, addr)?;
            }
            EmulationResult::BranchAbs(addr) => vcpu.set_reg(av::Reg::PC, addr)?,
            EmulationResult::Other => {
                // Backs the next instruction up.
                let mut next_insn = [0; 4];
                vma.read(addr + 4, &mut next_insn)?;
                hook.next_insn = Some(next_insn);
                // Writes the stage 2 breakpoint at the next instruction location.
                vma.write_dword(addr + 4, Self::BRK_STAGE_2)?;
                // Restores the current instruction.
                vma.write(addr, &hook.insn)?;
                // Sets PC to the restored instruction.
                vcpu.set_reg(av::Reg::PC, addr)?;
                // Invalidate caches.
                // They are only invalidated once this function returns and the Vcpu resumes its
                // execution. It's the reason why it must be the last function executed: it will
                // setup the Vcpu's state to jump on the cache invalidation handler before
                // returning to the fuzzed program's execution flow using an `eret` instruction.
                Caches::ic_ivau(vcpu, vma)?;
            }
        };
        Ok(ExitKind::Continue)
    }

    /// Handles the `brk #1` instruction, restores the original instructions and reapply the
    /// hook's stage 1.
    #[inline]
    fn hook_stage2(&mut self, vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<ExitKind> {
        let addr = vcpu.get_reg(av::Reg::PC)?;
        // The first stage breakpoint should always be exactly one instruction before the second
        // stage.
        let stage1_addr = addr - 4; // Should always be the case.
        let hook = self
            .hooks
            .get(&stage1_addr)
            .ok_or(HookError::UnknownHook(stage1_addr))?;
        // Restores the current instruction.
        // We can unwrap here because we know there's a next instruction since it's the one this
        // hook has been applied on.
        vma.write(addr, &hook.next_insn.unwrap())?;
        // Writes the stage 1 breakpoint at the previous instruction location if a custom or a
        // tracing hook exists. We don't need to restore the stage 1 if it's only a coverage hook
        // since it wouldn't provide additional information.
        if hook.tracer_handler.is_some() || hook.coverage_handler.is_some() {
            vma.write_dword(stage1_addr, Self::BRK_STAGE_1)?;
        }
        // Invalidate caches.
        // They are only invalidated once this function returns and the Vcpu resumes its execution.
        // It's the reason why it must be the last function executed: it will setup the Vcpu's
        // state to jump on the cache invalidation handler before returning to the fuzzed program's
        // execution flow using an `eret` instruction.
        Caches::ic_ivau(vcpu, vma)?;
        Ok(ExitKind::Continue)
    }
}

impl<LD: Clone, GD: Clone> Default for Hooks<LD, GD> {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------------------------
// Hooks - ARM Emulator
// -----------------------------------------------------------------------------------------------

bitfield! {
    /// Current Program Status Register
    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    struct Cpsr(u32);
    impl Debug;
    get_m, set_m: 3, 0;
    get_f, set_f: 6;
    get_i, set_i: 7;
    get_a, set_a: 8;
    get_e, set_e: 9;
    get_ge, set_ge: 19, 16;
    get_dit, set_dit: 21;
    get_pan, set_pan: 22;
    get_ssbs, set_ssbs: 23;
    get_q, set_q: 27;
    get_v, set_v: 28;
    get_c, set_c: 29;
    get_z, set_z: 30;
    get_n, set_n: 31;
}

/// Returns what type of instruction was disassembled, in order for the hook handler to update
/// the Vcpu registers accordingly (e.g. PC is set directly when `BranchAbs` is returned, while
/// a value is added if `BranchRel` is returned).
#[derive(Debug)]
enum EmulationResult {
    BranchRel(i32),
    BranchAbs(u64),
    Other,
}

/// Empty structure that represents the branch emulator of the fuzzer.
struct Emulator;

impl Emulator {
    /// This function takes an instruction as argument, disassembles it and returns to the hook
    /// handler an [`EmulationResult`].
    #[inline]
    fn emulate(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        match insn {
            // -----------------------------------------------------------------------------------
            // Conditional branch
            // -----------------------------------------------------------------------------------
            // B.cond
            i if (i >> 24) == 0b01010100 => Self::b_cond(i, vcpu),
            // CBNZ
            i if (i >> 24) == 0b10110101 || (i >> 24) == 0b00110101 => Self::cbnz(i, vcpu),
            // CBZ
            i if (i >> 24) == 0b10110100 || (i >> 24) == 0b00110100 => Self::cbz(i, vcpu),
            // TBNZ
            i if (i >> 24) == 0b10110111 || (i >> 24) == 0b00110111 => Self::tbnz(i, vcpu),
            // TBZ
            i if (i >> 24) == 0b10110110 || (i >> 24) == 0b00110110 => Self::tbz(i, vcpu),
            // -----------------------------------------------------------------------------------
            // Unconditional branch (immediate)
            // -----------------------------------------------------------------------------------
            // B
            i if (i >> 26) == 0b000101 => Self::b(i),
            // BL
            i if (i >> 26) == 0b100101 => Self::bl(i, vcpu),
            // BLR
            i if (i >> 10) == 0b1101011000111111000000 && i & 0x1f == 0 => Self::blr(i, vcpu),
            // BR
            i if (i >> 10) == 0b1101011000011111000000 && i & 0x1f == 0 => Self::br(i, vcpu),
            // RET
            i if (i >> 10) == 0b1101011001011111000000 && i & 0x1f == 0 => Self::ret(i, vcpu),
            _ => Ok(EmulationResult::Other),
        }
    }

    /// Evaluates an instruction condition based on CPSR flags.
    #[inline]
    fn evaluate_condition(cond: u32, cpsr: Cpsr) -> bool {
        let ret = match cond >> 1 {
            // EQ or NE
            0b000 => cpsr.get_z(),
            // CS or CC
            0b001 => cpsr.get_c(),
            // MI or PL
            0b010 => cpsr.get_n(),
            // VS or VC
            0b011 => cpsr.get_v(),
            // HI or LS
            0b100 => cpsr.get_c() && !cpsr.get_z(),
            // GE or LT
            0b101 => cpsr.get_n() == cpsr.get_v(),
            // GT or LE
            0b110 => cpsr.get_n() == cpsr.get_v() && !cpsr.get_z(),
            // AL
            0b111 => true,
            _ => unreachable!("invalid instruction condition"),
        };
        if cond & 1 == 1 && cond != 0b1111 {
            !ret
        } else {
            ret
        }
    }

    /// Sign extend a `size`-bit number (stored in a u32) to an i32.
    ///
    /// Taken from [bitutils](https://crates.io/crates/bitutils).
    #[inline]
    fn sign_extend32(data: u32, size: u32) -> i32 {
        assert!(size > 0 && size <= 32);
        ((data << (32 - size)) as i32) >> (32 - size)
    }

    /// Returns the value stored in a register based on an instruction operand value.
    #[inline]
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
    // Conditional branch
    // -------------------------------------------------------------------------------------------

    /// Emulates a `b.cond` instruction.
    #[inline]
    fn b_cond(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let cpsr = Cpsr(vcpu.get_reg(av::Reg::CPSR)? as u32);
        let cond = insn & 0xf;
        if Self::evaluate_condition(cond, cpsr) {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3ffff, 18) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    /// Emulates a `cbnz` instruction.
    #[inline]
    fn cbnz(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn & 0x1f;
        let op = if insn >> 31 == 1 {
            Self::get_operand(vcpu, rd)?
        } else {
            Self::get_operand(vcpu, rd)? as u32 as u64
        };
        if op != 0 {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3ffff, 18) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    /// Emulates a `cbz` instruction.
    #[inline]
    fn cbz(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn & 0x1f;
        let op = if insn >> 31 == 1 {
            Self::get_operand(vcpu, rd)?
        } else {
            Self::get_operand(vcpu, rd)? as u32 as u64
        };
        if op == 0 {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3ffff, 18) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    /// Emulates a `tbnz` instruction.
    #[inline]
    fn tbnz(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn & 0x1f;
        let bit_pos = ((insn >> 31) << 5) | ((insn >> 19) & 0x1f);
        let op = if insn >> 31 == 1 {
            Self::get_operand(vcpu, rd)?
        } else {
            Self::get_operand(vcpu, rd)? as u32 as u64
        };
        if (op >> bit_pos) & 1 != 0 {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3fff, 14) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    /// Emulates a `tbz` instruction.
    #[inline]
    fn tbz(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn & 0x1f;
        let bit_pos = ((insn >> 31) << 5) | ((insn >> 19) & 0x1f);
        let op = if insn >> 31 == 1 {
            Self::get_operand(vcpu, rd)?
        } else {
            Self::get_operand(vcpu, rd)? as u32 as u64
        };
        if (op >> bit_pos) & 1 == 0 {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3fff, 14) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    // -------------------------------------------------------------------------------------------
    // Unconditional branch
    // -------------------------------------------------------------------------------------------

    /// Emulates a `b` instruction.
    #[inline]
    fn b(insn: u32) -> Result<EmulationResult> {
        Ok(EmulationResult::BranchRel(
            Self::sign_extend32(insn & 0x3ffffff, 26) * 4,
        ))
    }

    /// Emulates a `bl` instruction.
    #[inline]
    fn bl(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        vcpu.set_reg(av::Reg::LR, vcpu.get_reg(av::Reg::PC)? + 4)?;
        Self::b(insn)
    }

    /// Emulates a `br` instruction.
    #[inline]
    fn br(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn >> 5 & 0x1f;
        let target = Self::get_operand(vcpu, rd)?;
        Ok(EmulationResult::BranchAbs(target))
    }

    /// Emulates a `blr` instruction.
    #[inline]
    fn blr(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        vcpu.set_reg(av::Reg::LR, vcpu.get_reg(av::Reg::PC)? + 4)?;
        Self::br(insn, vcpu)
    }

    /// Emulates a `ret` instruction.
    #[inline]
    fn ret(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        Self::br(insn, vcpu)
    }
}
