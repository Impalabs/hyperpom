//! Handles everything related to ARMv8 exceptions, from setting up the exception vector table, to
//! handling exceptions raised by the guest VMs.

use applevisor as av;

use crate::caches::*;
use crate::core::*;
use crate::crash::*;
use crate::error::*;
use crate::loader::*;
use crate::memory::*;

// -----------------------------------------------------------------------------------------------
// Exceptions - Types
// -----------------------------------------------------------------------------------------------

/// Represents the type of exceptions found in an ARMv8 exception vector table.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum ExceptionVectorType {
    /// Synchronous exception from current EL with SP0.
    SynchronousCurElSp0,
    /// IRQ from current EL with SP0.
    IrqCurElSp0,
    /// FIQ from current EL with SP0.
    FiqCurElSp0,
    /// System error exception from current EL with SP0.
    SerrorCurElSp0,
    /// Synchronous exception from current EL with SPX.
    SynchronousCurElSpX,
    /// IRQ from current EL with SPX.
    IrqCurElSpX,
    /// FIQ from current EL with SPX.
    FiqCurElSpX,
    /// System error exception from current EL with SPX.
    SerrorCurElSpX,
    /// Synchronous exception from lower EL using AArch64.
    SynchronousLowerElA64,
    /// IRQ from lower EL using AArch64.
    IrqLowerElA64,
    /// FIQ from lower EL using AArch64.
    FiqLowerElA64,
    /// System error exception from lower EL using AArch64.
    SerrorLowerElA64,
    /// Synchronous exception from lower EL using AArch32 (unimplemented on Apple Silicon).
    SynchronousLowerElA32,
    /// IRQ from lower EL using AArch32 (unimplemented on Apple Silicon).
    IrqLowerElA32,
    /// FIQ from lower EL using AArch32 (unimplemented on Apple Silicon).
    FiqLowerElA32,
    /// System error exception from lower EL using AArch32 (unimplemented on Apple Silicon).
    SerrorLowerElA32,
    /// Unknown type.
    Unknown(u8),
}

impl From<u8> for ExceptionVectorType {
    fn from(val: u8) -> Self {
        match val {
            0x0 => Self::SynchronousCurElSp0,
            0x1 => Self::IrqCurElSp0,
            0x2 => Self::FiqCurElSp0,
            0x3 => Self::SerrorCurElSp0,
            0x4 => Self::SynchronousCurElSpX,
            0x5 => Self::IrqCurElSpX,
            0x6 => Self::FiqCurElSpX,
            0x7 => Self::SerrorCurElSpX,
            0x8 => Self::SynchronousLowerElA64,
            0x9 => Self::IrqLowerElA64,
            0xa => Self::FiqLowerElA64,
            0xb => Self::SerrorLowerElA64,
            0xc => Self::SynchronousLowerElA32,
            0xd => Self::IrqLowerElA32,
            0xe => Self::FiqLowerElA32,
            0xf => Self::SerrorLowerElA32,
            _ => Self::Unknown(val),
        }
    }
}

/// Represents the ARMv8 exception classes.
/// Most of those are unused on the hypervisor for Apple Silicon systems, but we're still
/// implementing them for the sake of exhaustivity.
/// Some classes are also specific to Apple Silicon and cannot be used as-is on other SoCs.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum ExceptionClass {
    /// Unknown reason.
    Unknown(u64),
    /// Trapped WF* instruction execution.
    WfTrap,
    /// Trapped MCR or MRC access with (coproc==0b1111).
    McrMrcTrap0,
    /// Trapped MCRR or MRRC access with (coproc==0b1111).
    McrrMrrcTrap,
    /// Trapped MCR or MRC access with (coproc==0b1110).
    McrMrcTrap1,
    /// Trapped LDC or STC access.
    LdcStcTrap,
    /// Access to SVE, Advanced SIMD or floating-point functionality trapped by CPACR_EL1.FPEN,
    /// CPTR_EL2.FPEN, CPTR_EL2.TFP, or CPTR_EL3.TFP control.
    SveSimdFpTrap,
    /// Trapped execution of an LD64B, ST64B, ST64BV, or ST64BV0 instruction.
    Ld64St64Trap,
    /// Trapped MRRC access with (coproc==0b1110).
    MrrcTrap,
    /// Branch Target Exception.
    BranchTargetException,
    /// Illegal Execution state.
    IllegalExecutionState,
    /// SVC instruction execution in AArch32 state.
    SvcA32,
    /// SVC instruction execution in AArch64 state.
    SvcA64,
    /// HVC instruction execution in AArch64 state.
    HvcA64,
    /// Trapped MSR, MRS or System instruction execution in AArch64 state.
    MsrMrsSysTrap,
    /// Access to SVE functionality trapped as a result of CPACR_EL1.ZEN, CPTR_EL2.ZEN,
    /// CPTR_EL2.TZ, or CPTR_EL3.EZ.
    SveTrap,
    /// Exception from a Pointer Authentication instruction authentication failure.
    PacAuthFailure,
    /// Instruction Abort from a lower Exception level.
    InsAbortLowerEl,
    /// Instruction Abort taken without a change in Exception level.
    InsAbortCurEl,
    /// PC alignment fault exception.
    PcALignmentFault,
    /// Data Abort from a lower Exception level.
    DataAbortLowerEl,
    /// Data Abort taken without a change in Exception level.
    DataAbortCurEl,
    /// SP alignment fault exception.
    SpALignmentFault,
    /// Trapped floating-point exception taken from AArch32 state.
    FpTrapA32,
    /// Trapped floating-point exception taken from AArch64 state.
    FpTrapA64,
    /// SError interrupt.
    SerrorInterrupt,
    /// Breakpoint exception from a lower Exception level.
    BreakpointLowerEl,
    /// Breakpoint exception taken without a change in Exception level.
    BreakpointCurEl,
    /// Software Step exception from a lower Exception level.
    SoftwareStepLowerEL,
    /// Software Step exception taken without a change in Exception level.
    SoftwareStepCurEL,
    /// Watchpoint exception from a lower Exception level.
    WatchpointLowerEL,
    /// Watchpoint exception taken without a change in Exception level.
    WatchpointCurEL,
    /// BKPT instruction execution in AArch32 state.
    BkptA32,
    /// BRK instruction execution in AArch64 state.
    BrkA64,
}

impl From<u64> for ExceptionClass {
    fn from(val: u64) -> Self {
        match val & 0x3f {
            0b000001 => Self::WfTrap,
            0b000011 => Self::McrMrcTrap0,
            0b000100 => Self::McrrMrrcTrap,
            0b000101 => Self::McrMrcTrap1,
            0b000110 => Self::LdcStcTrap,
            0b000111 => Self::SveSimdFpTrap,
            0b001010 => Self::Ld64St64Trap,
            0b001100 => Self::MrrcTrap,
            0b001101 => Self::BranchTargetException,
            0b001110 => Self::IllegalExecutionState,
            0b010001 => Self::SvcA32,
            0b010101 => Self::SvcA64,
            0b010110 => Self::HvcA64,
            0b011000 => Self::MsrMrsSysTrap,
            0b011001 => Self::SveTrap,
            0b011100 => Self::PacAuthFailure,
            0b100000 => Self::InsAbortLowerEl,
            0b100001 => Self::InsAbortCurEl,
            0b100010 => Self::PcALignmentFault,
            0b100100 => Self::DataAbortLowerEl,
            0b100101 => Self::DataAbortCurEl,
            0b100110 => Self::SpALignmentFault,
            0b101000 => Self::FpTrapA32,
            0b101100 => Self::FpTrapA64,
            0b101111 => Self::SerrorInterrupt,
            0b110000 => Self::BreakpointLowerEl,
            0b110001 => Self::BreakpointCurEl,
            0b110010 => Self::SoftwareStepLowerEL,
            0b110011 => Self::SoftwareStepCurEL,
            0b110100 => Self::WatchpointLowerEL,
            0b110101 => Self::WatchpointCurEL,
            0b111000 => Self::BkptA32,
            0b111100 => Self::BrkA64,
            _ => Self::Unknown(val),
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Exceptions - Core
// -----------------------------------------------------------------------------------------------

/// The EL1 exception vector table base address.
pub const EVTABLE_ADDR: u64 = 0xffff_ffff_ffff_0000;

/// An unmapped address used as a return address for the first function called by the program.
/// It is used by the fuzzer to detect when a fuzzing iteration has finished when it didn't crash
/// or timeout. When the entry function returns, it will jump to this address. Since it is unmapped
/// it will generated an exception that we can catch and handle appropriately.
pub const END_ADDR: u64 = 0xdead_beef_0bad_0d0e;

/// Exception handling and management.
///
/// # Role of Exceptions in the Fuzzer
///
/// Exceptions are an integral part of the fuzzer: whether it's to detect that a crash occured or
/// to track dirty states for virtual memory pages, we have to handle them appropriately to
/// resume the execution or exit gracefully.
///
/// # ARM Exception Vector Table
///
/// The ARM architecture can operate at four different Exception Levels (ELs) with EL3 being the
/// most privileged and EL0 the least privileged. EL0, EL1 and EL2 also have Secure World
/// counterparts. Each of these ELs have their own exception vector tables (except for EL0 and
/// S-EL0, which are implemented in respectively EL1 and S-EL1). However, we won't get into too
/// much details, since Apple Silicon systems only implement EL0, EL1 and EL2.
///
/// The Apple Silicon hypervisor runs at EL2 and the guest VMs we create in it, can run at most at
/// EL1, which means it's the only exception vector table we're interested in.
///
/// All exception vector tables follow the format given below:
///
/// ```text
/// +------------------+------------------+------------------------------+
/// | Address          | Exception type   | Description                  |
/// +------------------+------------------+------------------------------+
/// | VBAR_EL1 + 0x000 | Synchronous      |                              |
/// |          + 0x080 | IRQ / vIRQ       | Current EL with SP0          |
/// |          + 0x100 | FIQ / vFIQ       |                              |
/// |          + 0x180 | SError / vSError |                              |
/// +------------------+------------------+------------------------------+
/// | VBAR_EL1 + 0x200 | Synchronous      |                              |
/// |          + 0x280 | IRQ / vIRQ       | Current EL with SPx          |
/// |          + 0x300 | FIQ / vFIQ       |                              |
/// |          + 0x380 | SError / vSError |                              |
/// +------------------+------------------+------------------------------+
/// | VBAR_EL1 + 0x400 | Synchronous      |                              |
/// |          + 0x480 | IRQ / vIRQ       | Lower EL using AArch64       |
/// |          + 0x500 | FIQ / vFIQ       |                              |
/// |          + 0x580 | SError / vSError |                              |
/// +------------------+------------------+------------------------------+
/// | VBAR_EL1 + 0x600 | Synchronous      |                              |
/// |          + 0x680 | IRQ / vIRQ       | Lower EL using AArch32       |
/// |          + 0x700 | FIQ / vFIQ       |                              |
/// |          + 0x780 | SError / vSError |                              |
/// +------------------+------------------+------------------------------+
/// ```
///
/// The exception vector table is 0x800-byte long and `VBAR_EL1` is the register that stores its
/// base address.
///
/// Each exception entry is 0x80-byte long. It's possible to directly write small functions in
/// there to handle the exception, but we're actually going to propagate the exception to the
/// hypervisor using HVC (hypervisor calls) instructions. Each entry will have an ID, from 0 to 15,
/// that we can encode into the HVC instruction and that we can retrieve when the exception is
/// raised to the hypervisor. This way, we'll be able to identify which exception occured at EL0 or
/// EL1 and handle it appropriately.
///
/// ```text
/// GUEST VM
/// +-------------------------------------------------------------------+
/// |                                                                   |
/// |  +------------------+      Current EL      +----------+           |
/// |  | Exception occurs |--------------------->| VBAR_EL1 |----> HVC ---> Exception raised
/// |  |      at EL1      |                      +----------+           |   to the hypervisor
/// |  +------------------+                           ^                 |
/// |                                                 |                 |
/// |  +------------------+       Lower EL            |                 |
/// |  | Exception occurs |---------------------------+                 |
/// |  |      at EL0      |                                             |
/// |  +------------------+                                             |
/// |                                                                   |
/// +-------------------------------------------------------------------+
/// ```
///
/// # Breakpoints
///
/// Breakpoints are another type of exceptions that we use extensively in the fuzzer. You can refer
/// to [`Hooks`](crate::hooks::Hooks) for more information.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Exceptions;

impl Exceptions {
    /// Initializes the EL1 exception vector table for the hypervisor.
    /// Each exception's handler code is an HVC instruction which raises an hypervisor exception
    /// where the syndrome contains the ID of the initial exception.
    pub fn init(vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        // Exception vector table mapping. This needs to be a privileged mapping, otherwise
        // it will hang indefinitely because of PAN raising an exception.
        vma.map_privileged(EVTABLE_ADDR, 0x1000, av::MemPerms::RX)?;
        // Each exception handler code is set to a HVC instruction where the immediate value is
        // the exception type ID.
        for i in 0..16 {
            let asm = format!("hvc #{}", i);
            let hvc = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
            vma.write(EVTABLE_ADDR + i * 0x80, &hvc.bytes)?;
        }
        // Sets VBAR_EL1 to our exception vector table.
        vcpu.set_sys_reg(av::SysReg::VBAR_EL1, EVTABLE_ADDR)?;
        Ok(())
    }

    /// Handles the hypervisor exceptions.
    pub fn handle<L: Loader + Loader<LD = LD> + Loader<GD = GD>, LD: Clone, GD: Clone>(
        executor: &mut Executor<L, LD, GD>,
    ) -> Result<ExitKind> {
        let exit = executor.vcpu.get_exit_info();
        match ExceptionClass::from(exit.exception.syndrome >> 26) {
            ExceptionClass::HvcA64 => Self::handle_hvc(executor),
            ExceptionClass::BrkA64 => executor.hooks.handle(
                &mut executor.vcpu,
                &mut executor.vma.borrow_mut(),
                &executor.vma.borrow_snapshot(),
                &mut executor.ldata,
                &executor.gdata,
                &mut executor.cdata,
                &mut executor.bdata,
            ),
            _ => Err(ExceptionError::UnimplementedException(
                exit.exception.syndrome,
            ))?,
        }
    }

    /// Handles exceptions raised to the hypervisor. The least significant bits of the exception
    /// syndrome contains the ID of the original exception that occured in the guest VM.
    /// The corresponding handlers for each exception come from the user-defined loader.
    #[allow(clippy::single_match)]
    pub fn handle_hvc<L: Loader + Loader<LD = LD> + Loader<GD = GD>, LD: Clone, GD: Clone>(
        executor: &mut Executor<L, LD, GD>,
    ) -> Result<ExitKind> {
        let exit = executor.vcpu.get_exit_info();
        let mut vma = executor.vma.borrow_mut();
        match exit.exception.syndrome & 0xf {
            // -----------------------------------------------------------------------------------
            // Synchronous Exception from Current EL with SP0
            0x00 => {
                let esr = executor.vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;
                match ExceptionClass::from(esr >> 26) {
                    ExceptionClass::DataAbortCurEl => {
                        let far = executor.vcpu.get_sys_reg(av::SysReg::FAR_EL1)?;
                        match vma.page_fault_dirty_state_handler(far) {
                            Ok(true) => {
                                // Now that we've remapped the page with the correct permissions we
                                // can retry.
                                let elr = executor.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
                                executor.vcpu.set_reg(av::Reg::PC, elr)?;
                                Caches::tlbi_vaae1_on_fault(&mut executor.vcpu, &mut vma)?;
                                return Ok(ExitKind::Continue);
                            }
                            Err(Error::Memory(MemoryError::UnallocatedMemoryAccess(_))) => {}
                            Err(Error::Memory(MemoryError::InvalidAddress(_))) => {
                                // Our magic return address value can be used during cache
                                // maintenance or other operations. When we encounter it, we handle
                                // the exception and exit the program.
                                if far == END_ADDR {
                                    return Ok(ExitKind::Exit);
                                }
                            }
                            Err(e) => return Err(e)?,
                            _ => {}
                        }
                    }
                    _ => {}
                };
                executor.loader.exception_handler_sync_curel_sp0(
                    &mut executor.vcpu,
                    &mut vma,
                    &mut executor.ldata,
                    &executor.gdata,
                )
            }
            // -----------------------------------------------------------------------------------
            // IRQ Exception from Current EL with SP0
            0x01 => executor.loader.exception_handler_irq_curel_sp0(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // FIQ Exception from Current EL with SP0
            0x02 => executor.loader.exception_handler_fiq_curel_sp0(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // SError Exception from Current EL with SP0
            0x03 => executor.loader.exception_handler_serror_curel_sp0(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // Synchronous Exception from Current EL with SPX
            0x04 => {
                let esr = executor.vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;
                match ExceptionClass::from(esr >> 26) {
                    ExceptionClass::DataAbortCurEl => {
                        let far = executor.vcpu.get_sys_reg(av::SysReg::FAR_EL1)?;
                        match vma.page_fault_dirty_state_handler(far) {
                            Ok(true) => {
                                // Now that we've remapped the page with the correct permissions we
                                // can retry.
                                let elr = executor.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
                                executor.vcpu.set_reg(av::Reg::PC, elr)?;
                                Caches::tlbi_vaae1_on_fault(&mut executor.vcpu, &mut vma)?;
                                return Ok(ExitKind::Continue);
                            }
                            Err(Error::Memory(MemoryError::UnallocatedMemoryAccess(_))) => {}
                            Err(Error::Memory(MemoryError::InvalidAddress(_))) => {
                                // Our magic return address value can be used during cache
                                // maintenance or other operations. When we encounter it, we handle
                                // the exception and exit the program.
                                if far == END_ADDR {
                                    return Ok(ExitKind::Exit);
                                }
                            }
                            Err(e) => return Err(e)?,
                            _ => {}
                        }
                    }
                    _ => {
                        // Checks the return address. If it's our magic value, we know that the
                        // program returned and we can simply return.
                        let lr = executor.vcpu.get_reg(av::Reg::LR)?;
                        if lr == END_ADDR {
                            return Ok(ExitKind::Exit);
                        }
                    }
                };
                executor.loader.exception_handler_sync_curel_spx(
                    &mut executor.vcpu,
                    &mut vma,
                    &mut executor.ldata,
                    &executor.gdata,
                )
            }
            // -----------------------------------------------------------------------------------
            // IRQ Exception from Current EL with SPX
            0x05 => executor.loader.exception_handler_irq_curel_spx(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // FIQ Exception from Current EL with SPX
            0x06 => executor.loader.exception_handler_fiq_curel_spx(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // SError Exception from Current EL with SPX
            0x07 => executor.loader.exception_handler_serror_curel_spx(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // Synchronous Exception from Lower EL using AArch64
            0x08 => {
                let esr = executor.vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;
                match ExceptionClass::from(esr >> 26) {
                    ExceptionClass::DataAbortLowerEl => {
                        let far = executor.vcpu.get_sys_reg(av::SysReg::FAR_EL1)?;
                        match vma.page_fault_dirty_state_handler(far) {
                            Ok(true) => {
                                // Now that we've remapped the page with the correct permissions we
                                // can retry.
                                let elr = executor.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
                                executor.vcpu.set_reg(av::Reg::PC, elr)?;
                                Caches::tlbi_vaae1_on_fault(&mut executor.vcpu, &mut vma)?;
                                return Ok(ExitKind::Continue);
                            }
                            Err(Error::Memory(MemoryError::UnallocatedMemoryAccess(_))) => {}
                            Err(Error::Memory(MemoryError::InvalidAddress(_))) => {}
                            Err(e) => return Err(e)?,
                            _ => {}
                        }
                    }
                    _ => {
                        // Checks the return address. If it's our magic value, we know that the
                        // program returned and we can simply return.
                        let lr = executor.vcpu.get_reg(av::Reg::LR)?;
                        if lr == END_ADDR {
                            return Ok(ExitKind::Exit);
                        }
                    }
                };
                executor.loader.exception_handler_sync_lowerel_aarch64(
                    &mut executor.vcpu,
                    &mut vma,
                    &mut executor.ldata,
                    &executor.gdata,
                )
            }
            // -----------------------------------------------------------------------------------
            // IRQ Exception from Lower EL using AArch64
            0x09 => executor.loader.exception_handler_irq_lowerel_aarch64(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // FIQ Exception from Lower EL using AArch64
            0x0a => executor.loader.exception_handler_fiq_lowerel_aarch64(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // SError Exception from Lower EL using AArch64
            0x0b => executor.loader.exception_handler_serror_lowerel_aarch64(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // Synchronous Exception from Lower EL using AArch32
            0x0c => executor.loader.exception_handler_sync_lowerel_aarch32(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // IRQ Exception from Lower EL using AArch32
            0x0d => executor.loader.exception_handler_irq_lowerel_aarch32(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // FIQ Exception from Lower EL using AArch32
            0x0e => executor.loader.exception_handler_fiq_lowerel_aarch32(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            // -----------------------------------------------------------------------------------
            // SError Exception from Lower EL using AArch32
            0x0f => executor.loader.exception_handler_serror_lowerel_aarch32(
                &mut executor.vcpu,
                &mut vma,
                &mut executor.ldata,
                &executor.gdata,
            ),
            _ => Ok(ExitKind::Crash("Unknown Exception".to_string())),
        }
    }
}
