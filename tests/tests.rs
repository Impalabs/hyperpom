// -----------------------------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hyperpom::caches::*;
    use hyperpom::config::*;
    use hyperpom::core::*;
    use hyperpom::corpus::*;
    use hyperpom::coverage::*;
    use hyperpom::crash::*;
    use hyperpom::error::*;
    use hyperpom::exceptions::*;
    use hyperpom::hooks::*;
    use hyperpom::loader::*;
    use hyperpom::memory::*;
    use hyperpom::tracer::*;
    use hyperpom::utils::*;
    use hyperpom::*;

    use applevisor as av;
    use keystone_engine as ks;

    use std::fs::File;
    use std::io::prelude::*;
    use std::path::Path;
    use std::time::Duration;

    // -------------------------------------------------------------------------------------------
    // Slab Allocator

    #[test]
    fn slab_allocations_single_threaded() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let ba = PhysMemAllocator::new(0x10000000).unwrap();
        // Creates a slab allocator for objects of size 0x1000
        let mut sa = SlabAllocator::new(ba.clone(), 0x1000).unwrap();
        // Allocates objects from the slab
        let objects = (0..8).map(|_| sa.alloc().unwrap()).collect::<Vec<_>>();
        objects.into_iter().for_each(|x| {
            sa.free(x).unwrap();
        });
    }

    #[test]
    fn slab_allocations_multi_threaded() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let ba = PhysMemAllocator::new(0x10000000).unwrap();
        let join_handles = (0..64)
            .map(|_| {
                let pma = ba.clone();
                // Creates a slab allocator for objects of size 0x1000
                std::thread::spawn(move || {
                    let mut sa = SlabAllocator::new(pma, 0x1000).unwrap();
                    // Allocates objects from the slab
                    for _ in 0..10 {
                        let objects = (0..0x100).map(|_| sa.alloc().unwrap()).collect::<Vec<_>>();
                        objects.into_iter().for_each(|x| {
                            sa.free(x).unwrap();
                        });
                    }
                })
            })
            .collect::<Vec<_>>();
        // Waits for the threads to stop.
        for handle in join_handles {
            handle.join().expect("Threads failed on join");
        }
    }

    // -------------------------------------------------------------------------------------------
    // Guest Page Tables

    #[test]
    fn page_table_map_unmap() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let pma = PhysMemAllocator::new(0x10000000).unwrap();
        // Creates a page table manager
        let mut ptm = PageTableManager::new(pma.clone()).unwrap();
        assert_eq!(ptm.map(0x0, 0x100000, av::MemPerms::RWX, false), Ok(()));
        assert_eq!(ptm.unmap(0x0, 0x100000), Ok(()));
    }

    // -------------------------------------------------------------------------------------------
    // Virtual Memory Allocator

    #[test]
    fn virtmem_clone_vma() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let pma = PhysMemAllocator::new(0x100000).unwrap();
        // Creates a virtual memory allocator
        let mut vma = VirtMemAllocator::new(pma.clone()).unwrap();
        vma.map(0x0000_0000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0x0000_0000_0000_0000, 0x1111_1111_1111_1111)
            .is_ok());
        vma.map(0x0000_0000_1000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0x0000_0000_1000_0000, 0x2222_2222_2222_2222)
            .is_ok());
        vma.map(0x0000_f000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0x0000_f000_0000_0000, 0x3333_3333_3333_3333)
            .is_ok());
        vma.map(0xffff_0000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0xffff_0000_0000_0000, 0x4444_4444_4444_4444)
            .is_ok());
        vma.map(0xffff_0000_1000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0xffff_0000_1000_0000, 0x5555_5555_5555_5555)
            .is_ok());
        vma.map(0xffff_f000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0xffff_f000_0000_0000, 0x6666_6666_6666_6666)
            .is_ok());
        let vma_clone = vma.clone();
        assert!(vma_clone.read_qword(0x0000_0000_0000_0000).is_ok());
        assert!(vma_clone.read_qword(0x0000_0000_1000_0000).is_ok());
        assert!(vma_clone.read_qword(0x0000_f000_0000_0000).is_ok());
        assert!(vma_clone.read_qword(0xffff_0000_0000_0000).is_ok());
        assert!(vma_clone.read_qword(0xffff_0000_1000_0000).is_ok());
        assert!(vma_clone.read_qword(0xffff_f000_0000_0000).is_ok());
        assert_eq!(
            vma_clone.read_qword(0xffff_dead_dead_0000),
            Err(Error::Memory(MemoryError::UnallocatedMemoryAccess(
                0xffff_dead_dead_0000
            )))
        );
    }

    #[test]
    fn virtmem_restore_from_snapshot() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let pma = PhysMemAllocator::new(0x100000).unwrap();
        // Creates a virtual memory allocator
        let mut vma = VirtMemAllocator::new(pma.clone()).unwrap();
        // Creates a new Vcpu
        let mut vcpu = av::Vcpu::new().unwrap();
        // Initializes Vcpu system registers
        assert!(vma.init(&mut vcpu, true).is_ok());
        // Initializes caches
        assert!(Caches::init(&mut vcpu, &mut vma).is_ok());
        // Data mappings
        vma.map(0x0000_0000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0x0000_0000_0000_0000, 0x1111_1111_1111_1111)
            .is_ok());
        vma.map(0x0000_0000_1000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0x0000_0000_1000_0000, 0x2222_2222_2222_2222)
            .is_ok());
        vma.map(0x0000_f000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0x0000_f000_0000_0000, 0x3333_3333_3333_3333)
            .is_ok());
        vma.map(0xffff_0000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0xffff_0000_0000_0000, 0x4444_4444_4444_4444)
            .is_ok());
        vma.map(0xffff_0000_1000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0xffff_0000_1000_0000, 0x5555_5555_5555_5555)
            .is_ok());
        vma.map(0xffff_f000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        assert!(vma
            .write_qword(0xffff_f000_0000_0000, 0x6666_6666_6666_6666)
            .is_ok());
        let snapshot = vma.clone();

        // Entry function at address 0x100000
        assert!(vma.map(0x100000, 0x1000, av::MemPerms::RX).is_ok());
        let ks = ks::Keystone::new(ks::Arch::ARM64, ks::Mode::LITTLE_ENDIAN)
            .expect("Could not initialize Keystone engine");
        let asm = String::from(
            "mov x0, #0x0000
            movk x0, #0x1000, lsl #16
            str x0, [x0]
            mov x0, #0x0000
            movk x0, #0x1000, lsl #16
            movk x0, #0xffff, lsl #48
            str x0, [x0]
            brk #0",
        );
        let entry_func = ks.asm(asm, 0).expect("could not assemble");
        assert!(vma.write(0x100000, &entry_func.bytes).is_ok());

        vma.unmap(0x0000_0000_0000_0000, 0x1000).unwrap();
        vma.unmap(0xffff_0000_0000_0000, 0x1000).unwrap();
        vma.map(0x0000_1000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();
        vma.map(0xffff_1000_0000_0000, 0x1000, av::MemPerms::RWX)
            .unwrap();

        // Sets PC to the entry point address
        assert_eq!(vcpu.set_reg(av::Reg::PC, 0x100000), Ok(()));

        let mut exit = false;
        while !exit {
            // Starts the vcpu
            assert_eq!(vcpu.run(), Ok(()));

            let esr = vcpu.get_sys_reg(av::SysReg::ESR_EL1).unwrap();
            exit = match ExceptionClass::from(esr >> 26) {
                ExceptionClass::DataAbortCurEl | ExceptionClass::DataAbortLowerEl => {
                    let far = vcpu.get_sys_reg(av::SysReg::FAR_EL1).unwrap();
                    let elr = vcpu.get_sys_reg(av::SysReg::ELR_EL1).unwrap();
                    if vma.page_fault_dirty_state_handler(far).unwrap() {
                        // Now that we've remapped the page with the correct permissions we can retry.
                        vcpu.set_reg(av::Reg::PC, elr).unwrap();
                        Caches::tlbi_vaae1_on_fault(&mut vcpu, &mut vma).unwrap();
                        false
                    } else {
                        true
                    }
                }
                _ => panic!(),
            }
        }

        assert_eq!(
            vma.read_qword(0x0000_0000_1000_0000),
            Ok(0x0000_0000_1000_0000)
        );
        assert_eq!(
            vma.read_qword(0xffff_0000_1000_0000),
            Ok(0xffff_0000_1000_0000)
        );

        assert_eq!(vma.restore_from_snapshot(&snapshot), Ok(()));
        assert_eq!(
            vma.read_qword(0x0000_0000_1000_0000),
            Ok(0x2222_2222_2222_2222)
        );
        assert_eq!(
            vma.read_qword(0xffff_0000_1000_0000),
            Ok(0x5555_5555_5555_5555)
        );
        assert!(vma.read_qword(0x0000_0000_0000_0000).is_ok());
        assert!(vma.read_qword(0x0000_0000_1000_0000).is_ok());
        assert!(vma.read_qword(0x0000_f000_0000_0000).is_ok());
        assert!(vma.read_qword(0xffff_0000_0000_0000).is_ok());
        assert!(vma.read_qword(0xffff_0000_1000_0000).is_ok());
        assert!(vma.read_qword(0xffff_f000_0000_0000).is_ok());
        assert_eq!(
            vma.read_qword(0x0000_1000_0000_0000),
            Err(Error::Memory(MemoryError::UnallocatedMemoryAccess(
                0x0000_1000_0000_0000
            )))
        );
        assert_eq!(
            vma.read_qword(0xffff_1000_0000_0000),
            Err(Error::Memory(MemoryError::UnallocatedMemoryAccess(
                0xffff_1000_0000_0000
            )))
        );
    }

    #[test]
    fn virtmem_allocator_read_write() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let pma = PhysMemAllocator::new(0x10000000).unwrap();
        // Creates a virtual memory allocator
        let mut vma = VirtMemAllocator::new(pma.clone()).unwrap();
        vma.map(0x0, 0x100000, av::MemPerms::RWX).unwrap();
        let data = (0..0x42).map(|i| i as u8).collect::<Vec<u8>>();
        vma.write(0x1000 - 0x21, &data).unwrap();
        let mut data = [0u8; 0x2000];
        vma.read(0, &mut data).unwrap();
        // Testing all write functions
        assert_eq!(vma.write(0x10000, &vec![0x10, 0x11, 0x12, 0x13]), Ok(4));
        assert_eq!(vma.write_byte(0x10010, 0x41), Ok(1));
        assert_eq!(vma.write_word(0x10020, 0x4242), Ok(2));
        assert_eq!(vma.write_dword(0x10030, 0x43434343), Ok(4));
        assert_eq!(vma.write_qword(0x10040, 0x4444444444444444), Ok(8));
        // Testing all read functions
        let mut data = vec![0, 0, 0, 0];
        assert_eq!(vma.read(0x10000, &mut data), Ok(4));
        assert_eq!(data, vec![0x10, 0x11, 0x12, 0x13]);
        assert_eq!(vma.read_byte(0x10010), Ok(0x41));
        assert_eq!(vma.read_word(0x10020), Ok(0x4242));
        assert_eq!(vma.read_dword(0x10030), Ok(0x43434343));
        assert_eq!(vma.read_qword(0x10040), Ok(0x4444444444444444));
    }

    #[test]
    fn virtmem_allocator_vcpu_ttbr0() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let pma = PhysMemAllocator::new(0x10000000).unwrap();
        // Creates a virtual memory allocator
        let mut vma = VirtMemAllocator::new(pma.clone()).unwrap();
        // Creates a new Vcpu
        let mut vcpu = av::Vcpu::new().unwrap();
        // Initializes Vcpu system registers
        assert!(vma.init(&mut vcpu, true).is_ok());
        // Entry function at address 0x100000
        assert!(vma.map(0x100000, 0x1000, av::MemPerms::RX).is_ok());
        let ks = ks::Keystone::new(ks::Arch::ARM64, ks::Mode::LITTLE_ENDIAN)
            .expect("Could not initialize Keystone engine");
        let asm = String::from(
            "mov x0, #0x0000
            movk x0, #0x20, lsl #16
            blr x0
            brk #0",
        );
        let entry_func = ks.asm(asm, 0).expect("could not assemble");
        assert!(vma.write(0x100000, &entry_func.bytes).is_ok());
        // Function called at address 0x200000
        assert!(vma.map(0x200000, 0x1000, av::MemPerms::RX).is_ok());
        let asm = String::from(
            "mov x0, #0x42
            ret",
        );
        let func = ks.asm(asm, 0).expect("could not assemble");
        assert_eq!(vma.write(0x200000, &func.bytes), Ok(8));
        // Sets PC to the entry point address
        assert_eq!(vcpu.set_reg(av::Reg::PC, 0x100000), Ok(()));
        assert_eq!(vcpu.run(), Ok(()));
        assert_eq!(vcpu.get_reg(av::Reg::X0), Ok(0x42));
        let exit = vcpu.get_exit_info();
        // Checks that the Vcpu stopped its execution after an exception was raised when hitting
        // the breakpoint.
        assert_eq!(exit.reason, av::ExitReason::EXCEPTION);
        assert_eq!(exit.exception.syndrome, 0xf2000000);
    }

    #[test]
    fn virtmem_allocator_vcpu_ttbr0_exception() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let pma = PhysMemAllocator::new(0x10000000).unwrap();
        // Creates a virtual memory allocator
        let mut vma = VirtMemAllocator::new(pma.clone()).unwrap();
        // Creates a new Vcpu
        let mut vcpu = av::Vcpu::new().unwrap();
        // Initializes Vcpu system registers
        assert!(vma.init(&mut vcpu, true).is_ok());
        // Entry function at address 0x100000
        assert!(vma.map(0x100000, 0x1000, av::MemPerms::RWX).is_ok());
        let ks = ks::Keystone::new(ks::Arch::ARM64, ks::Mode::LITTLE_ENDIAN)
            .expect("Could not initialize Keystone engine");
        let asm = String::from(
            "
            mov x1, 0x1000
            svc #123
            ",
        );
        let entry_func = ks.asm(asm, 0).expect("could not assemble");
        assert_eq!(vma.write(0x100000, &entry_func.bytes), Ok(8));

        // Sets PC to the entry point address
        assert_eq!(vcpu.set_reg(av::Reg::PC, 0x100000), Ok(()));
        assert_eq!(vcpu.run(), Ok(()));
        // assert_eq!(vcpu.get_reg(av::Reg::X0), Ok(0x42));
        let exit = vcpu.get_exit_info();
        // Checks that the Vcpu stopped its execution after an exception was raised when
        // executing the SVC.
        assert_eq!(exit.reason, av::ExitReason::EXCEPTION);
        assert_eq!(exit.exception.syndrome, 0x5a000008);
    }

    #[test]
    fn virtmem_allocator_vcpu_ttbr1() {
        let _vm = av::VirtualMachine::new().unwrap();
        // Creates an address space of size 0x10000000.
        let pma = PhysMemAllocator::new(0x10000000).unwrap();
        // Creates a virtual memory allocator
        let mut vma = VirtMemAllocator::new(pma.clone()).unwrap();
        // Creates a new Vcpu
        let mut vcpu = av::Vcpu::new().unwrap();
        // Initializes Vcpu system registers
        assert!(vma.init(&mut vcpu, true).is_ok());
        // Entry function at address 0xFFFF000000100000
        assert!(vma
            .map(0xFFFF_0000_0010_0000, 0x1000, av::MemPerms::RX)
            .is_ok());
        let ks = ks::Keystone::new(ks::Arch::ARM64, ks::Mode::LITTLE_ENDIAN)
            .expect("Could not initialize Keystone engine");
        let asm = String::from(
            "mov x0, #0x0000
            movk x0, #0x20, lsl #16
            movk x0, #0xffff, lsl #48
            blr x0
            brk #0",
        );
        let entry_func = ks.asm(asm, 0).expect("could not assemble");
        assert_eq!(vma.write(0xFFFF_0000_0010_0000, &entry_func.bytes), Ok(20));
        // Function called at address 0xFFFF000000200000
        assert!(vma
            .map(0xFFFF_0000_0020_0000, 0x1000, av::MemPerms::RX)
            .is_ok());
        let asm = String::from(
            "mov x0, #0x42
            ret",
        );
        let func = ks.asm(asm, 0).expect("could not assemble");
        assert_eq!(vma.write(0xFFFF_0000_0020_0000, &func.bytes), Ok(8));
        // Sets PC to the entry point address
        assert_eq!(vcpu.set_reg(av::Reg::PC, 0xFFFF_0000_0010_0000), Ok(()));
        assert_eq!(vcpu.run(), Ok(()));
        assert_eq!(vcpu.get_reg(av::Reg::X0), Ok(0x42));
        let exit = vcpu.get_exit_info();
        // Checks that the Vcpu stopped its execution after an exception was raised when hitting
        // the breakpoint.
        assert_eq!(exit.reason, av::ExitReason::EXCEPTION);
        assert_eq!(exit.exception.syndrome, 0xf2000000);
    }

    // -------------------------------------------------------------------------------------------
    // Shared test objects & functions

    #[derive(Clone)]
    pub struct GlobalData(u32);

    #[derive(Clone)]
    pub struct LocalData(u32);

    // -------------------------------------------------------------------------------------------
    // Raw Loader

    // A simple loader that maps a binary at virtual address `0x100000`.
    #[derive(Clone)]
    pub struct Raw {
        binary: Vec<u8>,
        entry_point: u64,
        stack_ptr: u64,
        stack_size: u64,
        data_ptr: u64,
        data_size: u64,
        testcase_ptr: u64,
        testcase_size: u64,
        test_id: u64,
    }

    impl Raw {
        // Creates a new Raw loader object.
        fn new(binary: &[u8], test_id: u64) -> Result<Self> {
            Ok(Self {
                binary: binary.to_vec(),
                entry_point: 0x100000,
                stack_ptr: 0x1_0000_0000,
                stack_size: 0x10000,
                data_ptr: 0x0,
                data_size: 0x10000,
                testcase_ptr: 0x10000,
                testcase_size: 0x10000,
                test_id,
            })
        }
    }

    impl Loader for Raw {
        type LD = LocalData;
        type GD = GlobalData;

        // Creates the mapping needed for the binary and writes the instructions into it.
        fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
            // Binary
            executor.vma.map(
                self.entry_point,
                round_virt_page!(self.binary.len()) as usize,
                av::MemPerms::RX,
            )?;
            executor.vma.write(self.entry_point, &self.binary)?;
            // Stack
            executor.vma.map(
                self.stack_ptr - self.stack_size,
                self.stack_size as usize,
                av::MemPerms::RW,
            )?;
            executor.vma.map(
                self.data_ptr,
                round_virt_page!(self.data_size) as usize,
                av::MemPerms::R,
            )?;
            Ok(())
        }

        // Sets PC to the entry point.
        fn hooks(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
            match self.test_id {
                // hook_local_hook
                1 => {
                    // Hooks at address `0x100004` and `0x100008`.
                    executor.add_custom_hook(0x100004, hook_test);
                    executor.add_custom_hook(0x100008, hook_verif);
                }
                // hook_exit_hook
                2 => {
                    // Hooks at address `0x100004`.
                    executor.add_custom_hook(0x100004, hook_exit);
                }
                // hook_branch_hook
                3 => {
                    // B hooks
                    executor.add_custom_hook(0x100008, hook_branch);
                    // cbnz hooks
                    executor.add_custom_hook(0x100014, hook_branch);
                    executor.add_custom_hook(0x100024, hook_branch);
                    // cbz hooks
                    executor.add_custom_hook(0x100034, hook_branch);
                    executor.add_custom_hook(0x100044, hook_branch);
                    // tbnz hooks
                    executor.add_custom_hook(0x100054, hook_branch);
                    executor.add_custom_hook(0x100064, hook_branch);
                    // tbz hooks
                    executor.add_custom_hook(0x100074, hook_branch);
                    executor.add_custom_hook(0x100084, hook_branch);
                    // bl hook
                    executor.add_custom_hook(0x100094, hook_branch);
                    // blr hook
                    executor.add_custom_hook(0x1000a4, hook_branch);
                    // blr hook
                    executor.add_custom_hook(0x1000b4, hook_branch);
                    // ret hook
                    executor.add_custom_hook(0x1000c8, hook_branch);
                }
                _ => {}
            }
            Ok(())
        }

        // Sets PC to the entry point.
        fn pre_exec(
            &mut self,
            executor: &mut Executor<Self, Self::LD, Self::GD>,
        ) -> Result<ExitKind> {
            match self.test_id {
                // coverage_cmp_unrolling_immediate
                4 => executor.vcpu.set_reg(av::Reg::X0, 0x42)?,
                5 => executor.vcpu.set_reg(av::Reg::X0, 0x423)?,
                6 => executor.vcpu.set_reg(av::Reg::X0, 0x123)?,
                7 => executor.vcpu.set_reg(av::Reg::X0, 0xdeadbeefdeadbeef)?,
                _ => {}
            }
            executor.vcpu.set_reg(av::Reg::PC, self.entry_point)?;
            executor
                .vcpu
                .set_sys_reg(av::SysReg::SP_EL0, self.stack_ptr - 8)?;
            Ok(ExitKind::Continue)
        }

        fn code_ranges(&self) -> Result<Vec<CodeRange>> {
            Ok(vec![CodeRange::new(
                self.entry_point,
                self.entry_point + self.binary.len() as u64,
            )])
        }

        fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
            Ok(vec![CoverageRange::new(
                self.entry_point,
                self.entry_point + self.binary.len() as u64,
            )])
        }

        fn trace_ranges(&self) -> Result<Vec<TraceRange>> {
            Ok(vec![TraceRange::new(
                self.entry_point,
                self.entry_point + self.binary.len() as u64,
            )])
        }

        fn load_testcase(
            &mut self,
            executor: &mut Executor<Self, LocalData, GlobalData>,
            testcase: &[u8],
        ) -> Result<LoadTestcaseAction> {
            executor.vma.map(
                self.testcase_ptr,
                round_virt_page!(self.testcase_size) as usize,
                av::MemPerms::RW,
            )?;
            executor.vma.write(self.testcase_ptr, testcase)?;
            Ok(LoadTestcaseAction::NewAndReset)
        }

        fn symbols(&self) -> Result<Symbols> {
            Ok(Symbols::new())
        }
    }

    // -------------------------------------------------------------------------------------------
    // Hooks

    fn hook_test(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
        let mut gdata = args.gdata.write().unwrap();
        gdata.0 += 1;
        args.ldata.0 += 1;
        args.vcpu
            .set_reg(av::Reg::X0, args.vcpu.get_reg(av::Reg::X0)? + 0x42)?;
        Ok(ExitKind::Continue)
    }

    fn hook_verif(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
        assert_eq!(args.vcpu.get_reg(av::Reg::X0), Ok(0x84));
        Ok(ExitKind::Continue)
    }

    #[test]
    fn hook_local_hook() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let asm = String::from(
            "mov x0, #0x42
            mov x1, #0x43
            mov x2, #0x44",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 1).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .build();
        let _vm = av::VirtualMachine::new();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.vcpu.get_reg(av::Reg::X0), Ok(0x84));
        assert_eq!(executor.vcpu.get_reg(av::Reg::X1), Ok(0x43));
        assert_eq!(executor.vcpu.get_reg(av::Reg::X2), Ok(0x44));
    }

    fn hook_exit(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
        let mut data = args.gdata.write().unwrap();
        data.0 += 0x42;
        Ok(ExitKind::Crash("Hook Crash".to_string()))
    }

    #[test]
    fn hook_exit_hook() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let asm = String::from(
            "mov x0, #0x42
            mov x1, #0x43
            mov x2, #0x44",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 2).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .build();
        let _vm = av::VirtualMachine::new();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.vcpu.get_reg(av::Reg::X0), Ok(0x42));
        assert_eq!(executor.vcpu.get_reg(av::Reg::X1), Ok(0));
        assert_eq!(executor.vcpu.get_reg(av::Reg::X2), Ok(0));
    }

    fn hook_branch(_args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
        Ok(ExitKind::Continue)
    }

    #[test]
    fn hook_branch_hook() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let asm = String::from(
            "mov x0, #0x42
            cmp x0, #0x42
            b.eq .+8
            b .-4

            mov x1, #0x42
            cbnz x1, .+8
            b .-4
            nop

            mov x1, #0
            cbnz x1, .+4
            b .+8
            b .-4

            mov x1, #0
            cbz x1, .+8
            b .-4
            nop

            mov x1, #0x42
            cbz x1, .+4
            b .+8
            b .-4

            mov x1, #0x100
            tbnz x1, 8, .+8
            b .-4
            nop

            movn x1, #0x100
            tbnz x1, 8, .+8
            b .+8
            b .-4

            movn x1, #0x100
            tbz x1, 8, .+8
            b .-4
            nop

            mov x1, #0x100
            tbz x1, 8, .+8
            b .+8
            b .-4

            adr x1, func
            bl func
            nop
            nop

            adr x1, func
            blr x1
            nop
            nop

            adr x1, exit
            br x1
            nop
            nop

            exit:
            brk #0xffff

            func:
            mov x0, 0x42
            ret",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 3).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .build();
        let _vm = av::VirtualMachine::new();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.vcpu.get_reg(av::Reg::X0), Ok(0x42));
    }

    // -------------------------------------------------------------------------------------------
    // Simple Test Loader

    // A simple loader that maps a binary at virtual address `0x100000`.
    #[derive(Clone)]
    pub struct SimpleTest {
        name: String,
        binary: Vec<u8>,
        entry_point: u64,
        stack_ptr: u64,
        stack_size: u64,
        testcase_ptr: u64,
        testcase_size: u64,
    }

    impl SimpleTest {
        // Creates a new Simple Test loader object.
        fn new(path: impl AsRef<Path>) -> Result<Self> {
            let name = path
                .as_ref()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            // Parses the binary
            let mut file = File::open(&path)?;
            let mut binary = Vec::new();
            file.read_to_end(&mut binary)?;
            Ok(Self {
                name,
                binary: binary.to_vec(),
                entry_point: 0x10000,
                stack_ptr: 0x1_0000_0000,
                stack_size: 0x10000,
                testcase_ptr: 0x20000,
                testcase_size: 0x1000,
            })
        }
    }

    impl Loader for SimpleTest {
        type LD = LocalData;
        type GD = GlobalData;

        // Creates the mapping needed for the binary and writes the instructions into it.
        fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
            // Binary
            executor.vma.map(
                self.entry_point,
                round_virt_page!(self.binary.len()) as usize,
                av::MemPerms::RX,
            )?;
            executor.vma.write(self.entry_point, &self.binary)?;
            // Stack
            executor.vma.map(
                self.stack_ptr - self.stack_size,
                self.stack_size as usize,
                av::MemPerms::RW,
            )?;
            // Testcase
            executor.vma.map(
                self.testcase_ptr,
                round_virt_page!(self.testcase_size) as usize,
                av::MemPerms::RW,
            )?;
            Ok(())
        }

        // Sets PC to the entry point.
        fn hooks(&mut self, _executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
            Ok(())
        }

        // Sets PC to the entry point.
        fn pre_exec(
            &mut self,
            executor: &mut Executor<Self, Self::LD, Self::GD>,
        ) -> Result<ExitKind> {
            executor.vcpu.set_reg(av::Reg::PC, self.entry_point)?;
            executor
                .vcpu
                .set_sys_reg(av::SysReg::SP_EL0, self.stack_ptr - 8)?;
            Ok(ExitKind::Continue)
        }

        fn code_ranges(&self) -> Result<Vec<CodeRange>> {
            Ok(vec![CodeRange::new(
                self.entry_point,
                self.entry_point + self.binary.len() as u64,
            )])
        }

        fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
            Ok(vec![CoverageRange::new(
                self.entry_point,
                self.entry_point + self.binary.len() as u64,
            )])
        }

        fn trace_ranges(&self) -> Result<Vec<TraceRange>> {
            Ok(vec![TraceRange::new(
                self.entry_point,
                self.entry_point + self.binary.len() as u64,
            )])
        }

        fn load_testcase(
            &mut self,
            executor: &mut Executor<Self, LocalData, GlobalData>,
            testcase: &[u8],
        ) -> Result<LoadTestcaseAction> {
            executor
                .vma
                .write(self.testcase_ptr, &vec![0; self.testcase_size as usize])?;
            executor.vma.write(self.testcase_ptr, testcase)?;
            Ok(LoadTestcaseAction::NewAndReset)
        }

        fn symbols(&self) -> Result<Symbols> {
            Ok(Symbols::from_vec(vec![
                Symbol::new("main", &self.name, self.entry_point + 0x00, 0x28),
                Symbol::new("func0", &self.name, self.entry_point + 0x28, 0x30),
                Symbol::new("func1", &self.name, self.entry_point + 0x58, 0x30),
                Symbol::new("func2", &self.name, self.entry_point + 0x88, 0x30),
                Symbol::new("func3", &self.name, self.entry_point + 0xb8, 0x2c),
                Symbol::new("func4", &self.name, self.entry_point + 0xe4, 0x18),
            ]))
        }

        // fn display_info(&self, _info: &HyperPomInfo) {}
    }

    // -------------------------------------------------------------------------------------------
    // Hyperpom - Core

    #[test]
    fn loader_load_binary() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let asm = String::from("mov x0, #0x42");
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 0).expect("could not create loader");
        let config = FuzzConfig::builder(0x10000000, "tmp/work", "tmp/corpus")
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .iterations(Some(1))
            .build();
        let mut hp = HyperPom::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
            .expect("could not create fuzzer");
        hp.fuzz().expect("fuzzing failed");
    }

    #[test]
    fn hyperpom_dirty_state() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let asm = String::from(
            "sub sp, sp, 0x1000
            mov x1, 0x1
            mov x2, sp
            str x1, [sp]
            mov x3, sp
            str x1, [sp, 8]
            mov x4, sp
            sub sp, sp, 0x1000
            mov x1, 0x2
            mov x5, sp
            str x1, [sp]
            str x1, [sp, 8]",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 0).expect("could not create loader");
        let config = FuzzConfig::builder(0x10000000, "tmp/work", "tmp/corpus")
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .iterations(Some(1000))
            .build();
        let mut hp = HyperPom::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
            .expect("could not create fuzzer");
        hp.fuzz().expect("fuzzing failed");
    }

    #[test]
    fn hyperpom_timeout() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let asm = String::from("b +0");
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 0).expect("could not create loader");
        let config = FuzzConfig::builder(0x10000000, "tmp/work", "tmp/corpus")
            .nb_workers(64)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(2, 0))
            .iterations(Some(1))
            .save_timeouts(true)
            .load_corpus_at_init(false)
            .build();
        let mut hp = HyperPom::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
            .expect("could not create fuzzer");
        hp.fuzz().expect("fuzzing failed");
    }

    #[test]
    fn hyperpom_crash_write_to_read_only_mem() {
        let _vm = av::VirtualMachine::new();
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let asm = String::from(
            "mov x0, 0
            mov x1, 0x42
            str x1, [x0]
            ",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 0).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .iterations(Some(1))
            .build();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        let ek = executor.run(None).expect("execution failed");
        assert!(if let ExitKind::Crash(_) = ek {
            true
        } else {
            false
        });
    }

    #[test]
    fn hyperpom_simple_test_fuzzing_single_worker() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let loader =
            SimpleTest::new("./tests/test_programs/simple_test").expect("could not create loader");
        let config = FuzzConfig::builder(0x10000000, "tmp/work", "tmp/corpus")
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .load_corpus_at_init(false)
            .timeout(Duration::new(60, 0))
            .iterations(Some(100000))
            .build();
        let mut hp =
            HyperPom::<SimpleTest, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create fuzzer");
        hp.fuzz().expect("fuzzing failed");
    }

    #[test]
    fn hyperpom_simple_test_fuzzing_multi_workers() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let loader =
            SimpleTest::new("./tests/test_programs/simple_test").expect("could not create loader");
        let config = FuzzConfig::builder(0x10000000, "tmp/work", "tmp/corpus")
            .nb_workers(8)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .load_corpus_at_init(false)
            .timeout(Duration::new(60, 0))
            .iterations(Some(100000))
            .build();
        let mut hp =
            HyperPom::<SimpleTest, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create fuzzer");
        hp.fuzz().expect("fuzzing failed");
    }

    #[test]
    fn hyperpom_cmp_unrolling_fuzzing() {
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        // Test binary
        let loader = SimpleTest::new("./tests/test_programs/cmp_unrolling")
            .expect("could not create loader");
        let config = FuzzConfig::builder(0x10000000, "tmp/work", "tmp/corpus")
            .nb_workers(6)
            .seed(0xdeadbeef)
            .max_nb_mutations(10)
            .max_testcase_size(0x100)
            .load_corpus_at_init(false)
            .timeout(Duration::new(60, 0))
            .iterations(Some(100000))
            .comparison_unrolling(true)
            .build();
        let mut hp =
            HyperPom::<SimpleTest, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create fuzzer");
        hp.fuzz().expect("fuzzing failed");
    }

    // -------------------------------------------------------------------------------------------
    // Coverage

    #[test]
    fn coverage_cmp_unrolling_immediate() {
        let _vm = av::VirtualMachine::new();
        // With X0 = 0x42 ------------------------------------------------------------------------
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        let asm = String::from(
            "cmp x0, 0x123
            ret",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 4).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .comparison_unrolling(true)
            .build();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.cdata.set.len(), 6);
        drop(executor);
        // With W0 = 0x423 -----------------------------------------------------------------------
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        let asm = String::from(
            "cmp w0, 0x456
            ret",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 5).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .comparison_unrolling(true)
            .build();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.cdata.set.len(), 3);
        drop(executor);
        // With X0 = 0x123 -----------------------------------------------------------------------
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        let asm = String::from(
            "cmp x0, 0x123
            ret",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 6).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .comparison_unrolling(true)
            .build();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.cdata.set.len(), 8);
        drop(executor);
        // With X0 = 0x42 ------------------------------------------------------------------------
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        let asm = String::from(
            "mov x1, 0x123
            cmp x1, x0
            ret",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 4).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .comparison_unrolling(true)
            .build();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.cdata.set.len(), 6);
        drop(executor);
        // With X0 = 0x423 -----------------------------------------------------------------------
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        let asm = String::from(
            "movk x1, 0x123, lsl#16
            cmp x1, x0, lsl#16
            ret",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 5).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .comparison_unrolling(true)
            .build();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.cdata.set.len(), 4);
        drop(executor);
        // With X0 = 0xdeadbeefdeadbeef ----------------------------------------------------------
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        let asm = String::from(
            "mov x1, 0xbeef
            movk x1, 0xdead, lsl#16
            movk x1, 0xbeef, lsl#32
            movk x1, 0xdead, lsl#48
            cmp x1, x0
            ret",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 7).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .comparison_unrolling(true)
            .build();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.cdata.set.len(), 8);
        drop(executor);
        // With w0 = 0xdeadbeef ----------------------------------------------------------
        let gdata = GlobalData(0);
        let ldata = LocalData(0);
        let asm = String::from(
            "mov w1, 0xbeef
            movk w1, 0xdead, lsl#16
            cmp w1, w0
            ret",
        );
        let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
        let loader = Raw::new(&binary.bytes, 7).expect("could not create loader");
        let config = ExecConfig::builder(0x10000000)
            .nb_workers(1)
            .seed(0xdeadbeef)
            .max_nb_mutations(0x10)
            .max_testcase_size(0x100)
            .timeout(Duration::new(60, 0))
            .comparison_unrolling(true)
            .build();
        let mut executor =
            Executor::<Raw, LocalData, GlobalData>::new(config, loader, ldata, gdata)
                .expect("could not create executor");
        executor.init().expect("could not init executor");
        executor.run(None).expect("execution failed");
        assert_eq!(executor.cdata.set.len(), 4);
        drop(executor);
    }
}
