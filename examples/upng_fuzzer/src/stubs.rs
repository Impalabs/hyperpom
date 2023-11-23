use applevisor as av;
use hyperpom::crash::*;
use hyperpom::error::*;
use hyperpom::hooks::*;
use hyperpom::memory::*;
use hyperpom::*;

use crate::loader::*;

pub struct Stub;

impl Stub {
    // -------------------------------------------------------------------------------------------
    // Helper functions

    fn ret(vcpu: &mut av::Vcpu) -> Result<ExitKind> {
        vcpu.set_reg(av::Reg::X0, 0)?;
        let lr = vcpu.get_reg(av::Reg::LR)?;
        vcpu.set_reg(av::Reg::PC, lr)?;
        Ok(ExitKind::EarlyFunctionReturn)
    }

    fn retval(vcpu: &mut av::Vcpu, value: u64) -> Result<ExitKind> {
        vcpu.set_reg(av::Reg::X0, value)?;
        let lr = vcpu.get_reg(av::Reg::LR)?;
        vcpu.set_reg(av::Reg::PC, lr)?;
        Ok(ExitKind::EarlyFunctionReturn)
    }

    // -------------------------------------------------------------------------------------------
    // Heap

    /// Allocates a new heap chunk of `size` bytes.
    fn allocate(
        ldata: &mut LocalData,
        _vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        size: usize,
    ) -> Result<Option<u64>> {
        if size > 0x100000 {
            return Ok(None);
        }
        // Minimal size for 0-byte allocations.
        let size = if size == 0 { 8 } else { size };
        // Computes the remaining size in the heap.
        let remaining_size = ldata.heap_size - ldata.heap_offset;
        // If the allocation we want to perform exceeds it, we map a new page right after.
        if remaining_size < size {
            let next_addr = round_virt_page!(PngLoader::HEAP_ADDR + ldata.heap_offset as u64);
            let next_size = round_virt_page!((size - remaining_size) as u64) as usize;
            let ret = vma.map(next_addr, next_size, av::MemPerms::RW);
            // If any error occurs while mapping the new heap page, we just return nothing from
            // this function. Propagating the error would stop the fuzzer and resetting the
            // fuzzer during the next iteration should be enough to recover from it.
            if ret.is_err() {
                return Ok(None);
            }
            vma.write(next_addr, &vec![0; next_size])?;
            ldata.heap_size += next_size;
        }
        let addr = PngLoader::HEAP_ADDR + ldata.heap_offset as u64;
        ldata.allocs.insert(addr, size);
        ldata.heap_offset += size;
        Ok(Some(addr))
    }

    /// Stub for the `malloc` function.
    pub fn malloc(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
        let size = args.vcpu.get_reg(av::Reg::X0)?;
        if let Some(addr) = Self::allocate(args.ldata, args.vcpu, args.vma, size as usize)? {
            Self::retval(args.vcpu, addr)
        } else {
            Self::retval(args.vcpu, 0)
        }
    }

    /// Stub for the `free` function.
    ///
    /// Doesn't actually do anything. Allocating linearly and letting the snapshot restoration
    /// system handle memory unmapping should be enough for this target.
    pub fn free(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
        Self::ret(args.vcpu)
    }

    /// Stub for the `realloc` function.
    pub fn realloc(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
        let old_mem = args.vcpu.get_reg(av::Reg::X0)?;
        let new_size = args.vcpu.get_reg(av::Reg::X1)?;
        let new_addr =
            if let Some(old_size) = args.ldata.allocs.get(&old_mem) {
                let mut data = vec![0u8; *old_size];
                args.vma.read(old_mem, &mut data)?;
                if let Some(addr) =
                    Self::allocate(args.ldata, args.vcpu, args.vma, new_size as usize)?
                {
                    args.vma.write(addr, &data)?;
                    addr
                } else {
                    0
                }
            } else if let Some(addr) =
                Self::allocate(args.ldata, args.vcpu, args.vma, new_size as usize)?
            {
                addr
            } else {
                0
            };
        Self::retval(args.vcpu, new_addr)
    }
}
