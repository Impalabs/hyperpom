//! Module responsible for everything related to memory management. It handles memory allocations,
//! slab allocations, page table management and virtual memory allocations.

use applevisor as av;
use applevisor::Mappable;
use bitfield::bitfield;
use rhexdump as rh;

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{hash_map::Entry, BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::io::prelude::*;
use std::path::Path;
use std::rc::{Rc, Weak};
use std::sync::{Arc, Mutex};

use crate::error::*;
use crate::exceptions::*;
use crate::utils::*;

// -----------------------------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------------------------

/// Rounds up an address to the next multiple of [`applevisor::PAGE_SIZE`].
#[macro_export]
macro_rules! round_phys_page {
    ( $addr: expr ) => {
        (($addr as u64) + (av::PAGE_SIZE as u64 - 1)) & !(av::PAGE_SIZE as u64 - 1)
    };
}

/// Truncates an address to a multiple of [`applevisor::PAGE_SIZE`].
#[macro_export]
macro_rules! align_phys_page {
    ( $addr: expr ) => {
        $addr & !(av::PAGE_SIZE as u64 - 1)
    };
}

/// Rounds up an address to the next multiple of [`VIRT_PAGE_SIZE`].
#[macro_export]
macro_rules! round_virt_page {
    ( $addr: expr ) => {
        (($addr as u64) + (VIRT_PAGE_SIZE as u64 - 1)) & !(VIRT_PAGE_SIZE as u64 - 1)
    };
}

/// Truncates an address to a multiple of [`VIRT_PAGE_SIZE`].
#[macro_export]
macro_rules! align_virt_page {
    ( $addr: expr ) => {
        $addr & !(VIRT_PAGE_SIZE as u64 - 1)
    };
}

// -----------------------------------------------------------------------------------------------
// Guest Physical Memory Allocator - Physical Memory
// -----------------------------------------------------------------------------------------------

/// Represents a guest physical memory range backed by a [`applevisor::Mapping`].
///
/// It can only be created when guest physical memory is allocated through a [`PhysMemAllocator`]
/// instance. When a mapping is created, it is not directly mapped and an explicit call to
/// `PhysMem::map` needs to be made. However, in most cases this will be transparent for the user
/// since it's handled directly by [`PhysMemAllocator`].
///
/// # Example
///
/// ```
/// use applevisor as av;
/// use applevisor::Mappable;
/// use hyperpom::memory::PhysMem;
///
/// // First we create an hypervisor virtual machine instance to allow memory management in the
/// // guest (there's only one per process).
/// let vm = applevisor::VirtualMachine::new().unwrap();
///
/// // We allocate a physical memory page of size 0x10000 (the page size on Apple Silicon systems).
/// let mut physmem = PhysMem::new(0x10000).unwrap();
///
/// // We can map our page at an arbitrary address.
/// println!("host_addr = {:#x}", physmem.get_host_addr() as u64);
/// physmem.map(0x100000, av::MemPerms::RWX).unwrap();
///
/// // We can change the protections that will be used by the hypervisor to allow or
/// // prevent access to a memory range from the guest.
/// physmem.protect(av::MemPerms::R).unwrap();
///
/// // Values can be written to it...
/// physmem.write(0x12340000, &[0, 1, 2, 3]).unwrap();
///
/// // ... and read from it.
/// let mut data = [0; 4];
/// physmem.read(0x12340000, &mut data).unwrap();
/// assert_eq!(data, [0, 1, 2, 3]);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct PhysMem {
    /// A reference to the allocator that allocated the object. Only used when we drop the object.
    allocator: Option<PhysMemAllocator>,
    /// The underlying [`applevisor::Mapping`].
    mem: av::Mapping,
    /// Determines if the mapping has been freed or not. Without this, there is a weird interaction
    /// where two references to a `PhysMem` would call [`PhysMemAllocator::_free_inner`] at the
    /// same time and panic the program.
    is_free: bool,
}

impl PhysMem {
    /// Creates a new physical memory range of size `size`.
    pub fn new(size: usize) -> Result<Self> {
        Ok(Self {
            allocator: None,
            mem: av::Mapping::new(size)?,
            is_free: false,
        })
    }

    /// Creates a new physical memory range of size `size` attached to a [`PhysMemAllocator`].
    /// Unless the design of your program requires it, you should not instanciate this object
    /// directly and let [`PhysMemAllocator`] handle it.
    pub fn with_pma(allocator: PhysMemAllocator, size: usize) -> Result<Self> {
        Ok(Self {
            allocator: Some(allocator),
            mem: av::Mapping::new(size)?,
            is_free: false,
        })
    }

    /// Maps a physical memory range at address `guest_addr` and with permissions `perms`.
    #[inline]
    pub fn map(&mut self, guest_addr: u64, perms: av::MemPerms) -> av::Result<()> {
        self.mem.map(guest_addr, perms)
    }

    /// Unmaps a physical memory range.
    #[inline]
    pub fn unmap(&mut self) -> av::Result<()> {
        self.mem.unmap()
    }

    /// Changes the permissions of a physical memory range used by a guest VM (i.e. reading and
    /// writing from the host won't be affected by these permissions).
    #[inline]
    pub fn protect(&mut self, perms: av::MemPerms) -> av::Result<()> {
        self.mem.protect(perms)
    }

    /// Reads bytes at address `guest_addr`. The size of `data` determines the number of bytes
    /// read.
    #[inline]
    pub fn read(&self, guest_addr: u64, data: &mut [u8]) -> av::Result<usize> {
        self.mem.read(guest_addr, data)
    }

    /// Writes the content of `data` into the guest at address `guest_addr`.
    #[inline]
    pub fn write(&mut self, guest_addr: u64, data: &[u8]) -> av::Result<usize> {
        self.mem.write(guest_addr, data)
    }

    /// Returns the pointer to the host allocation corresponding to this physical memory range.
    #[inline]
    pub fn get_host_addr(&self) -> *const u8 {
        self.mem.get_host_addr()
    }

    /// Returns the guest address corresponding to this physical memory range.
    #[inline]
    pub fn get_guest_addr(&self) -> Option<u64> {
        self.mem.get_guest_addr()
    }

    /// Returns the size of this physical memory range.
    #[inline]
    pub fn get_size(&self) -> usize {
        self.mem.get_size()
    }
}

impl std::ops::Drop for PhysMem {
    fn drop(&mut self) {
        if !self.is_free {
            PhysMemAllocator::_free_inner(self).expect("could not free physmem during drop");
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Guest Physical Memory Allocator - Buddy Allocator
// -----------------------------------------------------------------------------------------------

/// Inner structure for [`PhysMemAllocator`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct PhysMemAllocatorInner {
    /// The address space size.
    mem_size: usize,
    /// Allocation pools. There are `max_order - min_order` pools, each containing free chunks
    /// addresses grouped by their corresponding order.
    pools: Vec<Vec<u64>>,
    /// HashMap keeping track of allocations and their size.
    allocs: HashMap<u64, usize>,
}

impl PhysMemAllocatorInner {
    /// Returns the order of an allocation using its size.
    fn get_order(&self, size: usize) -> Result<usize> {
        if size < av::PAGE_SIZE || size > self.mem_size {
            Err(MemoryError::InvalidSize(size))?
        } else {
            Ok(log2(size) - log2(av::PAGE_SIZE))
        }
    }

    /// Returns the address of a chunk's buddy.
    fn get_buddy(&self, addr: u64, size: usize) -> Option<u64> {
        if size >= self.mem_size {
            return None;
        }
        if addr % (size as u64 * 2) == 0 {
            Some(addr + size as u64)
        } else {
            Some(addr - size as u64)
        }
    }
}

/// Physical memory allocator based on the Buddy System algorithm.
///
/// # Role of the Guest Physical Memory Allocator in the Fuzzer
///
/// The Apple hypervisor provides methods to its guest VM to manage a physical address space.
/// By mapping memory in the hypervisor we effectively create physical memory ranges that can be
/// accessed by the different guests. Just like a regular operating system, a single contiguous
/// range of physical pages can be used to create multiple isolated virtual address spaces, one
/// for each guest (or fuzzing [`Executor`](crate::core::Executor) in our case).
///
/// But in order to adapt to the specific needs of each guest and allocate physical pages
/// efficiently we need a way to manage these physical memory ranges. This is where this allocator
/// comes into play. Its goal is to carve out chunks of the physical address space and then merge
/// them back once they are no longer needed. In our case, the algorithm chosen to achieve this
/// is the Buddy System.
///
/// # Algorithm Overview
///
/// The allocator starts out with a single chunk of size `mem_size`, which is the maximum amount of
/// memory that can be allocated. `mem_size` needs to be expressed as a power of two and has to be
/// larger than `0x10000`, the page size on Apple Silicon systems.
///
/// We will take the example of a chunk of size 256KB.
///
/// ```text
///             256KB
/// ```
///
/// The buddy allocator then divides this chunk, and the subsequent ones, into two until it fines
/// the smallest chunk large enough to contain the requested allocation. For example, if we want
/// an allocation of size 50KB. We first divide 256KB by two and get two chunks of size 128KB. Then
/// we divide one of these 128KB chunks by two, to get two 64KB chunks. Repeating this process
/// would yield 32KB which are smaller than 50KB, so we return a 64KB chunk.
///
/// ```text
///             256KB
///           /       \
///       128KB       128KB
///      /    \
///    64KB  64KB
///    ^^^^
///     |
///     +--> allocated chunk returned
/// ```
///
/// The buddy allocator takes its name from the fact that all chunks (expect for the initial one)
/// have a buddy, the other half of the chunk they were split from.
///
/// ```text
///             256KB
///           /       \
///       128KB       128KB
///         |           |
///         +-----------+----> buddies
///      /    \
///    64KB  64KB
///     |      |
///     +------+----> buddies
/// ```
///
/// This is useful when a chunk is freed and needs to be merged back by the buddy allocator. The
/// allocator checks if the buddy of a chunk is allocated, and if it's not the case, it merges them
/// back together to create a bigger chunk.
///
/// ```text
///             256KB                     256KB
///           /       \                 /       \                   256KB
///       128KB       128KB   -->   128KB       128KB   -->       /       \         -->  256KB
///           \                    /    \                     128KB       128KB
///          64KB                64KB  64KB
///                              ^^^^
///                               |
///                               +--> freed chunk to merge
/// ```
///
/// This algorithm offers good performances when allocating and deallocating memory. It is simple
/// and there are tons of real-world implementations, such as in the Linux kernel, that can be
/// used as examples to refine the implementation and/or enhance performances.
///
/// It falls short when considering external fragmentation (e.g. allocating 32KB when 17KB are
/// requested). Hopefully, we can assume most of the fuzzed programs won't allocate a majority of
/// memory chunks that would maximize fragmentation.
///
/// # Example
///
/// ```
/// use applevisor as av;
/// use hyperpom::memory::PhysMemAllocator;
///
/// // First we create an hypervisor virtual machine instance to allow memory management in the
/// // guest (there's only one per process).
/// let vm = applevisor::VirtualMachine::new().unwrap();
///
/// // We create a new physical memory allocator over an address range of size 0x1000_0000.
/// let mut pma = PhysMemAllocator::new(0x1000_0000).unwrap();
///
/// // We allocate a physical memory range spanning over 3 physical pages.
/// let physmem = pma.alloc(0x30000, av::MemPerms::RWX).unwrap();
///
/// // We can either free it explicitly or simply wait for it to drop.
/// pma.free(physmem).unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct PhysMemAllocator {
    inner: Arc<Mutex<PhysMemAllocatorInner>>,
}

impl PhysMemAllocator {
    /// Instanciates a buddy allocator over an address space of size `mem_size`. The size needs to
    /// be expressed as a power of two and has to be larger than [`applevisor::PAGE_SIZE`].
    pub fn new(mem_size: usize) -> Result<Self> {
        // Makes sure `mem_size` is large enough and a power of two.
        if mem_size < av::PAGE_SIZE || mem_size & (mem_size - 1) != 0 {
            return Err(MemoryError::InvalidSize(mem_size))?;
        }
        // Creates an uninitialized buddy allocator.
        let mut ba = PhysMemAllocatorInner {
            mem_size,
            pools: vec![],
            allocs: HashMap::new(),
        };
        // Allocates the pools of free chunks.
        let nb_pools = 1 + ba.get_order(mem_size)?;
        ba.pools = vec![vec![]; nb_pools];
        // Puts an initial chunk of size `mem_size` at address 0 into the highest-order pool.
        ba.pools.last_mut().unwrap().push(0);
        // Returns the initialized allocator wrapped in a lock.
        Ok(Self {
            inner: Arc::new(Mutex::new(ba)),
        })
    }

    /// Uses the buddy allocator to create a [`PhysMem`] object of size `size` mapped with the
    /// permissions `perms`.
    pub fn alloc(&mut self, size: usize, perms: av::MemPerms) -> Result<PhysMem> {
        // Gets the lock on the allocator
        let mut inner = self.inner.lock().unwrap();
        // The allocation size needs to be page aligned.
        if size & (av::PAGE_SIZE - 1) != 0 {
            return Err(MemoryError::UnalignedSize(size))?;
        }
        // Computes the order of the current allocation to know in which pool it should be.
        let alloc_order = inner.get_order(size)?;
        // Starting from the pool of index `order`, it looks for the first pool of higher order
        // that contains at least one free chunk and returns its index.
        // Returns an OOM error if it can't find one.
        let mut free_order = alloc_order
            + inner
                .pools
                .iter()
                .skip(alloc_order)
                .position(|x| !x.is_empty())
                .ok_or(MemoryError::OutOfMemory)?;
        // Gets the free chunk we will make an allocation from.
        let alloc_addr = inner.pools[free_order].pop().unwrap();
        // Computes the chunk's size.
        let mut alloc_size = 1 << (free_order + log2(av::PAGE_SIZE) - 1);
        // Iterates over the pool of free chunks in reverse.
        while free_order > alloc_order {
            free_order -= 1;
            // Computes the address of the current chunk's buddy.
            let buddy_addr = alloc_addr + alloc_size;
            // Pushes it into the corresponding pool.
            inner.pools[free_order].push(buddy_addr);
            // Halves the size and reiterates the process.
            alloc_size >>= 1;
        }
        // Adds the chunk and its size to the HashMap in order to track current allocations.
        inner.allocs.insert(alloc_addr, size);
        // Creates a guest mapping that corresponds to the allocation and maps it.
        let mut mapping = PhysMem::with_pma(self.clone(), size)?;
        mapping.map(alloc_addr, perms)?;

        Ok(mapping)
    }

    /// Explicit free of a [`PhysMem`] object allocated through the buddy allocator
    /// (`PhysMem`s can also be freed by letting them go out of scope/dropping them).
    pub fn free(&self, mut mem: PhysMem) -> Result<()> {
        Self::_free_inner(&mut mem)
    }

    /// The inner function that unmaps a [`PhysMem`] object from the guest and merges back the
    /// corresponding physical memory chunk with the other freed chunks.
    fn _free_inner(mem: &mut PhysMem) -> Result<()> {
        // Return early if `mem` is not associated to a PhysMemAllocator.
        if mem.allocator.is_none() {
            return Ok(());
        }
        // It's safe to unwrap the allocator since we've checked above that it's not None.
        let allocator = mem.allocator.as_ref().unwrap();
        // Gets the lock on the allocator.
        let mut inner = allocator.inner.lock().unwrap();
        let mut chunk_addr = mem.get_guest_addr().unwrap();
        // Whether the mapping actually exists or not, we set `is_free` to true so that
        // `free_inner` is not called again - which would panic the program - when `mem` is
        // dropped.
        mem.is_free = true;
        // Unmaps the guest mapping.
        mem.mem.unmap()?;
        // Removes our chunk from the HashMap tracking allocations since we want to free it.
        if let Some(mut chunk_size) = inner.allocs.remove(&chunk_addr) {
            let mut order = inner.get_order(chunk_size)?;
            // This loop finds the chunk's buddy, merge them if it's free and reiterates the
            // process with the resulting merged chunk.
            while let Some(buddy_addr) = inner.get_buddy(chunk_addr, chunk_size) {
                // Checks if the buddy is not allocated.
                if inner.allocs.get(&buddy_addr).is_none() {
                    // Removes it from the free list.
                    if let Some(pos) = inner.pools[order].iter().position(|x| *x == buddy_addr) {
                        inner.pools[order].remove(pos);
                    } else {
                        break;
                    }
                    // Merges the chunk and its buddy into a new one of size `chunk_size*2` and at
                    // address `min(chunk_addr, buddy_addr)`.
                    chunk_size *= 2;
                    chunk_addr = std::cmp::min(chunk_addr, buddy_addr);
                    order += 1;
                } else {
                    break;
                }
            }
            inner.pools[order].push(chunk_addr);
        } else {
            return Err(MemoryError::UnallocatedMemoryAccess(chunk_addr))?;
        }
        Ok(())
    }
}

impl fmt::Display for PhysMemAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        writeln!(f)?;
        writeln!(f, "+-------+-------+")?;
        writeln!(f, "| Order | Count |")?;
        writeln!(f, "+-------+-------+")?;
        for (i, pool) in inner.pools.iter().enumerate() {
            writeln!(f, "| {:5} | {:5} |", i, pool.len())?;
        }
        writeln!(f, "+-------+-------+")
    }
}

impl PartialEq for PhysMemAllocator {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

// -----------------------------------------------------------------------------------------------
// Guest Physical Memory Allocator - Slab Allocator
// -----------------------------------------------------------------------------------------------

/// Slab allocator for allocations smaller than [`applevisor::PAGE_SIZE`].
///
/// # Role of the Slab Allocator in the Fuzzer.
///
/// On Apple Silicon, the size of a physical memory page is 64KB (or 0x10000 bytes). However,
/// a majority of targets still use a 4KB (or 0x1000 bytes) granule for physical memory pages.
/// Directly using a physical page from the hypervisor would be way too inefficient as it would
/// create a lot of unused space. A slab allocator solves this problem by servicing multiple 4KB
/// pages from a single 64KB hypervisor page, which can then be used the guest VMs transparently.
///
/// Note: this fuzzer only supports 4KB pages for the moment (but support for other granules
/// could be added relatively easily).
///
/// # Algorithm Overview
///
/// A slab is a contiguous space in memory from which are allocated objects of a specific size
/// (usually also the same type of objects). As hinted above, in our case the slabs are the 64KB
/// pages and the objects the 4KB ones, but the implementation can handle other sizes as well.
///
/// In this implementation slabs are represented by the structure [`Slab`] and objects by the
/// structure [`SlabObject`].
///
/// ```text
///                                       64KB
/// <------------------------------------------------------------------------------->
/// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
/// |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
/// |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
/// |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
/// +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
///           <---->
///            4KB
/// ```
///
/// A slab starts as empty, it's just one hypervisor physical page with no 4KB page allocated from
/// it yet.
///
/// When an allocation is requested, the allocator checks if there are partial slabs available.
/// These are slabs that still have some space left to service 4KB pages.
///
///  * If a partial slab is available, a pointer to the 4KB chunk is returned.
///    * If there is no space left after the allocation, the corresponding slab is marked as full.
///  * Otherwise, if no partial slab is available, a new one is created.
///
/// When a page is freed, the allocator checks from which slab it initially came from.
///
/// * If the initial slab is full, the corresponding 4KB chunk is marked as free and the slab is
///   put in the partial slabs list.
/// * If the 4KB page was the last chunk used in the initial slab, then the 64KB as a whole is
///   reclaimed and unmapped from the hypervisor.
///
/// # Example
///
/// ```
/// use applevisor as av;
/// use hyperpom::memory::{PhysMemAllocator, SlabAllocator};
///
/// // First we create an hypervisor virtual machine instance to allow memory management in the
/// // guest (there's only one per process).
/// let vm = applevisor::VirtualMachine::new().unwrap();
///
/// // We create a new physical memory allocator over an address range of size 0x1000_0000.
/// let mut pma = PhysMemAllocator::new(0x1000_0000).unwrap();
///
/// // We create a new slab allocator for objects of size 0x1000.
/// let mut slab_allocator = SlabAllocator::new(pma, 0x1000).unwrap();
///
/// // And we can now create and free slab objects of size 0x1000.
/// let object = slab_allocator.alloc().unwrap();
/// slab_allocator.free(object).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct SlabAllocator {
    /// Physical memory allocator from which slabs are allocated.
    pma: PhysMemAllocator,
    /// Size of the objects stored in this slab.
    object_size: usize,
    /// Numbers of objects per slab.
    objects_per_slab: usize,
    /// List of full slabs.
    full: VecDeque<SlabReference>,
    /// List of partial slabs.
    partial: VecDeque<SlabReference>,
}

impl SlabAllocator {
    /// Creates a new slab allocator containing objects of size `object_size`.
    pub fn new(pma: PhysMemAllocator, object_size: usize) -> Result<Self> {
        // Checks if the object would fit in a page.
        if object_size > av::PAGE_SIZE {
            return Err(MemoryError::InvalidSize(object_size))?;
        }
        Ok(SlabAllocator {
            pma,
            object_size,
            objects_per_slab: av::PAGE_SIZE / object_size,
            full: VecDeque::new(),
            partial: VecDeque::new(),
        })
    }

    /// Allocates a [`SlabObject`].
    pub fn alloc(&mut self) -> Result<SlabObject> {
        // Creates a new slab if there are no partial slabs available.
        if self.partial.is_empty() {
            // TODO: maybe pass perms as func args.
            let mem = self.pma.alloc(av::PAGE_SIZE, av::MemPerms::RWX)?;
            let slab = SlabReference::new(mem, self.object_size, self.objects_per_slab);
            self.partial.push_back(slab);
        }
        // At this point, we know there's at least one partial slab, so it's safe to just iterate
        // and take a reference to the first one encountered.
        let slab = self
            .partial
            .iter_mut()
            .next()
            .ok_or(MemoryError::CorruptedSlab)?;
        // We allocate an objects from the partial slab we found.
        let object = slab.alloc().ok_or(MemoryError::CorruptedSlab)?;
        // If after the allocation, the slab is full, then it's put in the list referencing the
        // other full slabs.
        if slab.is_full() {
            let slab = self.partial.pop_front().unwrap();
            self.full.push_back(slab);
        }
        Ok(object)
    }

    /// Frees a [`SlabObject`].
    pub fn free(&mut self, mut object: SlabObject) -> Result<()> {
        // Retrieves the slab this object was allocated from.
        let parent = object.parent.take();
        let mut slab = parent.ok_or(MemoryError::CorruptedSlab)?;
        // Checks if the slab is full before freeing the object. This tells us if we need to
        // move out the corresponding slab from the full slabs list and put it into the partial
        // slabs one.
        let is_full_slab = slab.is_full();
        // The object is freed.
        slab.free(object);
        // If the slab was full before we freed, then transfer it to the partial slabs list.
        if is_full_slab {
            let full_slab_pos = self
                .full
                .iter()
                .position(|x| *x == slab)
                .ok_or(MemoryError::CorruptedSlab)?;
            let full_slab = self.full.remove(full_slab_pos).unwrap();
            self.partial.push_front(full_slab);
        }
        // If the slab is now empty, remove it from the partial list (the underlying physical page
        // is unmapped once drop is called).
        if slab.is_empty() {
            let empty_slab_pos = self
                .partial
                .iter()
                .position(|x| *x == slab)
                .ok_or(MemoryError::CorruptedSlab)?;
            let _ = self.partial.remove(empty_slab_pos).unwrap();
        }
        Ok(())
    }
}

/// Represents a slab from which object of a given size can be allocated.
///
/// See [`SlabAllocator`] for more information on slabs.
#[derive(Clone, Debug, PartialEq)]
pub struct Slab {
    /// The underlying hypervisor physical memory page.
    mem: PhysMem,
    /// Number of objects stored in this slab.
    objects_per_slab: usize,
    /// The list of free [`SlabObject`]s that can be allocated from this slab.
    freelist: Vec<SlabObject>,
}

/// A reference to a slab.
///
/// When an object is allocated, it gets a `SlabReference` to the slab it belongs to. This
/// reference is deleted when the object is freed. Thus, when all objects from a slab are freed,
/// it's automatically deleted and unmapped from the hypervisor.
///
/// See [`SlabAllocator`] for more information on slabs.
#[derive(Clone, Debug, PartialEq)]
pub struct SlabReference(Rc<RefCell<Slab>>);

impl SlabReference {
    /// Creates a new slab backed by the `mem` allocation.
    pub fn new(mem: PhysMem, object_size: usize, objects_per_slab: usize) -> Self {
        let mut freelist = vec![];
        // Initializes the freelist by dividing the physical memory page into smaller chunks and
        // creating slab objects with each a pointer to their respective chunk.
        for i in (0..objects_per_slab).rev() {
            // SAFETY: `mem` is mapped and we made sure that it is large enough to contain
            //         `object_size * objects_per_slab` bytes. And since all objects have a
            //         reference to the slab, it won't get freed unless all slab objects are also
            //         freed.
            let object = SlabObject {
                host_addr: unsafe { mem.get_host_addr().add(i * object_size) },
                guest_addr: mem.get_guest_addr().unwrap() + (i * object_size) as u64,
                object_size,
                parent: None,
            };
            freelist.push(object);
        }
        Self(Rc::new(RefCell::new(Slab {
            mem,
            objects_per_slab,
            freelist,
        })))
    }

    /// Returns whether our slab is full or not.
    pub fn is_full(&self) -> bool {
        self.0.borrow().freelist.is_empty()
    }

    /// Returns whether our slab is empty or not.
    pub fn is_empty(&self) -> bool {
        self.0.borrow().freelist.len() == self.0.borrow().objects_per_slab
    }

    /// Allocates a new object from the current slab. Returns `None` if the slab is full.
    pub fn alloc(&mut self) -> Option<SlabObject> {
        if let Some(mut object) = self.0.borrow_mut().freelist.pop() {
            object.parent = Some(self.clone());
            // Objects are zeroed-out when allocated.
            // SAFETY: we can safely write `object_size` bytes into the object, since we
            //         know it's part of a an allocation that exists at least as long as the
            //         current object and with a fixed sized.
            unsafe { std::ptr::write_bytes(object.host_addr as *mut u8, 0, object.object_size) };
            Some(object)
        } else {
            None
        }
    }

    /// Frees an object by removing the reference to the slab it belongs to and adding it back to
    /// the freelist.
    pub fn free(&mut self, mut object: SlabObject) {
        let _ = object.parent.take();
        self.0.borrow_mut().freelist.push(object);
    }
}

/// A slab object.
///
/// See [`SlabAllocator`] for more information on slabs.
#[derive(Clone, Debug, PartialEq)]
pub struct SlabObject {
    /// The pointer in the host address space referencing the object's data.
    host_addr: *const u8,
    /// The pointer in the guest address space referencing the object's data.
    guest_addr: u64,
    /// The object size.
    object_size: usize,
    /// The reference to the slab it belongs to when the object is allocated.
    parent: Option<SlabReference>,
}

impl fmt::Display for SlabObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Slab object @Host {:#x} - @Guest {:#x}",
            self.host_addr as u64, self.guest_addr
        )?;
        // SAFETY: We made sure when initializing the slab, that all objects can be of size
        //         `object_size` and the underlying physical memory page is still there because
        //         we currently have at least one object that points to it.
        let data: &[u8] = unsafe { std::slice::from_raw_parts(self.host_addr, self.object_size) };
        let mut rhx = rhexdump::Rhexdump::default();
        rhx.display_duplicate_lines(false);
        write!(f, "{}", rhx.hexdump_offset(data, self.host_addr as u32))
    }
}

// -----------------------------------------------------------------------------------------------
// Guest Page Tables
// -----------------------------------------------------------------------------------------------

/// Page size in virtual address spaces.
pub const VIRT_PAGE_SIZE: usize = 0x1000;

/// Number of entries in a page table.
pub const PAGE_TABLE_NB_ENTRIES: usize = 0x200;

/// Page table size.
pub const PAGE_TABLE_SIZE: usize = PAGE_TABLE_NB_ENTRIES * std::mem::size_of::<u64>();

bitfield! {
    /// Level 0, 1 and 2 page table descriptor.
    ///
    ///  - **NS Table**: specifies the Security state for subsequent levels of lookup
    ///  - **AP Table**: access permissions limit for subsequent levels of lookup
    ///  - **UXN Table**: XN limit for subsequent levels of lookup
    ///  - **PXN Table**: PXN limit for subsequent levels of lookup
    ///
    /// # Example
    ///
    /// ```
    /// use hyperpom::memory::TableDescriptor;
    ///
    /// // Creates a descriptor for a table at address `0x1234000`.
    /// let descriptor = TableDescriptor::new(0x1234000);
    /// ```
    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    pub struct TableDescriptor(u64);
    impl Debug;
    get_valid, set_valid: 0;
    get_type, set_type: 1;
    get_addr, set_addr: 47, 12;
    get_pxntable, set_pxntable: 59;
    get_uxntable, set_uxntable: 60;
    get_aptable, set_aptable: 62, 61;
    get_nstable, set_nstable: 63;
}

impl TableDescriptor {
    /// Create a new table descriptor for levels 0, 1 and 2.
    ///
    /// Apart from the address field, all descriptors store the following permissions:
    ///
    ///  - **NS Table**: `true`, everything should be non-secure;
    ///  - **AP Table**: `0b00`, no limitations regarding access permissions;
    ///  - **UXN Table**: `false`, no limitations regarding user execution permissions;
    ///  - **PXN Table**: `false`, no limitations regarding privileged execution permissions.
    pub fn new(addr: u64) -> Self {
        let mut descriptor = TableDescriptor(0);
        descriptor.set_valid(true);
        descriptor.set_type(true);
        // Sets the next descriptor's address
        descriptor.set_addr(addr >> 12);
        // Disables PXN table bit
        descriptor.set_pxntable(false);
        // Disables UXN table bit
        descriptor.set_uxntable(false);
        // No effect on access permissions in subsequent levels of lookup
        descriptor.set_aptable(0b00);
        // Disables NS table bit
        descriptor.set_nstable(true);
        descriptor
    }
}

bitfield! {
    /// Level 3 page table descriptor.
    ///
    /// - **UXN:** Unprivileged execute-never field
    /// - **PXN:** Privilege execute-never field
    /// - **Contiguous:** A hint bit indicating that the translation table entry is one of a
    ///     contiguous set of entries
    /// - **DBM:** Dirty Bit Modifier
    /// - **nG:** Not Global Bit
    /// - **AF:** Access flag
    /// - **SH:** Shareability field
    /// - **AP:** Data Access Permissions bits
    /// - **NS:** Non-Secure bit
    /// - **AttrIndx:** Stage 1 memory attributes index field
    ///
    /// # Example
    ///
    /// ```
    /// use applevisor as av;
    /// use hyperpom::memory::PageDescriptor;
    ///
    /// // Creates a descriptor for a physical page at address `0x1234000` with RWX permissions.
    /// let descriptor = PageDescriptor::new(0x1234000, av::MemPerms::RWX, false);
    ///
    /// // It's also possible to create privileged mappings restricted to EL1. This is necessary
    /// // to create EL1 mappings that do not trigger PAN.
    /// let descriptor = PageDescriptor::new(0x1235000, av::MemPerms::RWX, true);
    ///
    /// // And a descriptor can also be transformed into its read-only version.
    /// let ro_descriptor = descriptor.read_only(true);
    /// ```
    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    pub struct PageDescriptor(u64);
    impl Debug;
    get_valid, set_valid: 0;
    get_type, set_type: 1;
    get_attrindx, set_attrindx: 4, 2;
    get_ns, set_ns: 5;
    get_ap, set_ap: 7, 6;
    get_sh, set_sh: 9, 8;
    get_af, set_af: 10;
    get_ng, set_ng: 11;
    get_addr, set_addr: 47, 12;
    get_dbm, set_dbm: 51;
    get_contiguous, set_contiguous: 52;
    get_pxn, set_pxn: 53;
    get_uxn, set_uxn: 54;
}

impl PageDescriptor {
    /// Create a new table descriptor for levels 0, 1 and 2.
    ///
    /// Other than the address, the AP flags and the UXN flag, all descriptors store the following
    /// permissions:
    ///
    ///  - **PXN:** `true`, EL1 can always execute code mapped at EL0;
    ///  - **nG:** `false`, ASIDs are not currently used;
    ///  - **AF:** `true`, otherwise nothing works for some reason;
    ///  - **SH:** `0b11`, we want the page to be *Inner Shareable*.
    ///  - **NS:** `true`, all pages are non-secure;
    ///  - **AttrIndx:** `0b000`, we use the same memory attributes for all pages as configured
    ///         by the register `MAIR_EL1` set in [`VirtMemAllocator::init`].
    pub fn new(addr: u64, perms: av::MemPerms, privileged: bool) -> Self {
        let mut descriptor = PageDescriptor(0xffff_ffff);
        descriptor.set_valid(true);
        descriptor.set_type(true);
        descriptor.set_attrindx(0b000);
        descriptor.set_ns(true);
        descriptor.set_ap(match privileged {
            true => 0b00,
            false => match perms {
                av::MemPerms::None | av::MemPerms::W | av::MemPerms::X | av::MemPerms::WX => 0b00,
                av::MemPerms::R | av::MemPerms::RX => 0b11,
                av::MemPerms::RW | av::MemPerms::RWX => 0b01,
            },
        });
        descriptor.set_sh(0b11);
        descriptor.set_af(true);
        descriptor.set_ng(false);
        // Sets the page descriptor's address
        descriptor.set_addr(addr >> 12);
        descriptor.set_pxn(false);
        descriptor.set_uxn(
            privileged
                | match perms {
                    av::MemPerms::None | av::MemPerms::W | av::MemPerms::R | av::MemPerms::RW => {
                        true
                    }
                    av::MemPerms::X | av::MemPerms::WX | av::MemPerms::RX | av::MemPerms::RWX => {
                        false
                    }
                },
        );
        descriptor
    }

    /// Gets the read-only version of a page descriptor.
    ///
    /// This method is primarily used to detect dirty pages:
    ///
    ///  * we first map writable pages as read-only;
    ///  * when the guest tries to write to it, we generate a fault;
    ///  * we mark the page as dirty;
    ///  * we then remap it as writable;
    ///  * finally we resume the execution and retry the instruction.
    pub fn read_only(&self, privileged: bool) -> Self {
        // Using the access permissions table from the ARM documentation, for a set of given
        // permissions we want the corresponding read-only AP.
        // We can simplify the mapping a bit using the following truth table.
        //
        // ```text
        // +============+======++=======+
        // | PRIVILEGED |  AP  || AP_RO |
        // +============+======++=======+
        // |      0     | 0  0 ||  0 0  |
        // |      0     | 0  1 ||  1 1  |
        // |      0     | 1  0 ||  1 0  |
        // |      0     | 1  1 ||  1 1  |
        // |      1     | 0  0 ||  1 0  |
        // |      1     | 0  1 ||  1 1  |
        // |      1     | 1  0 ||  1 0  |
        // |      1     | 1  1 ||  1 1  |
        // +============+======++=======+
        // ```
        //
        // The final expression can therefore be written as:
        //
        // ```text
        // ((PRIVILEGED | AP[1] | AP[0]) << 1) | AP[0]
        // ```
        let mut descriptor_ro = *self;
        let ap0 = self.get_ap() & 1;
        let ap1 = (self.get_ap() >> 1) & 1;
        let privileged = privileged as u64;
        let ap_ro = ((privileged | ap1 | ap0) << 1) | ap0;
        descriptor_ro.set_ap(ap_ro);
        descriptor_ro
    }
}

/// Represents a *Page Global Directory*.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct PageGlobalDirectory {
    /// The slab object pointing to memory that contains the raw descriptors.
    entries: SlabObject,
    /// A hashmap mapping the descriptor's index to the corresponding PUD object.
    /// It's a more convenient way to handle page table components rather than manually parsing and
    /// changing descriptors in memory.
    objects: HashMap<usize, PageUpperDirectory>,
}

impl PageGlobalDirectory {
    /// Creates a new PGD.
    pub fn new(entries: SlabObject) -> Self {
        Self {
            entries,
            objects: HashMap::new(),
        }
    }
}

/// Represents a *Page Upper Directory*.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct PageUpperDirectory {
    /// Descriptor storing the information and permissions of the current PUD.
    descriptor: TableDescriptor,
    /// The slab object pointing to memory that contains the raw descriptors.
    entries: SlabObject,
    /// A hashmap mapping the descriptor's index to the corresponding PMD object.
    /// It's a more convenient way to handle page table components rather than manually parsing and
    /// changing descriptors in memory.
    objects: HashMap<usize, PageMiddleDirectory>,
}

impl PageUpperDirectory {
    /// Creates a new PUD.
    pub fn new(entries: SlabObject) -> Self {
        Self {
            descriptor: TableDescriptor::new(entries.guest_addr),
            entries,
            objects: HashMap::new(),
        }
    }
}

/// Represents a *Page Middle Directory*.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct PageMiddleDirectory {
    /// Descriptor storing the information and permissions of the current PMD.
    descriptor: TableDescriptor,
    /// The slab object pointing to memory that contains the raw descriptors.
    entries: SlabObject,
    /// A hashmap mapping the descriptor's index to the corresponding PT object.
    /// It's a more convenient way to handle page table components rather than manually parsing and
    /// changing descriptors in memory.
    objects: HashMap<usize, Rc<RefCell<PageTable>>>,
}

impl PageMiddleDirectory {
    /// Creates a new PMD.
    pub fn new(entries: SlabObject) -> Self {
        Self {
            descriptor: TableDescriptor::new(entries.guest_addr),
            entries,
            objects: HashMap::new(),
        }
    }
}

/// Represents a *Page Table*.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct PageTable {
    /// Descriptor storing the information and permissions of the current PT.
    descriptor: TableDescriptor,
    /// The slab object pointing to memory that contains the raw descriptors.
    entries: SlabObject,
    /// A hashmap mapping the descriptor's index to the corresponding Page object.
    /// It's a more convenient way to handle page table components rather than manually parsing and
    /// changing descriptors in memory.
    objects: HashMap<usize, Rc<RefCell<Page>>>,
}

impl PageTable {
    /// Creates a new PT.
    pub fn new(entries: SlabObject) -> Self {
        Self {
            descriptor: TableDescriptor::new(entries.guest_addr),
            entries,
            objects: HashMap::new(),
        }
    }
}

/// Represents a guest physical memory page.
///
/// See [`PageTableManager`] for more information.
#[derive(Clone, Debug)]
pub struct Page {
    /// Descriptor storing the original information and permissions of the page.
    descriptor: PageDescriptor,
    /// Descriptor currently stored in the page table. This field exists to handle dirty
    /// pages.
    descriptor_in_use: PageDescriptor,
    /// Field used for dirty bit emulation and set when a page is written to.
    dirty: bool,
    /// Page memory permissions.
    perms: av::MemPerms,
    /// Defines if it's a privileged mapping.
    privileged: bool,
    /// The slab object storing the page data.
    ///
    /// Stored as an `Option` because `Page`s are manipulated by the virtual address space through
    /// `RefCell`s. This allows us to take out the underlying `SlabObject` and pass it to the
    /// `free` function of the `SlabAllocator` while it's borrowed.
    data: Option<SlabObject>,
    /// Reference to the parent page table.
    ///
    /// When tracking the dirty bit, finding the page table that corresponds to a page can be
    /// costly. Having a weak reference directly in the object will provide better performances.
    parent: Weak<RefCell<PageTable>>,
}

impl Page {
    /// Creates a new guest physical memory page.
    pub fn new(
        data: SlabObject,
        perms: av::MemPerms,
        privileged: bool,
        parent: Weak<RefCell<PageTable>>,
    ) -> Self {
        let descriptor = PageDescriptor::new(data.guest_addr, perms, privileged);
        Self {
            descriptor,
            descriptor_in_use: descriptor.read_only(privileged),
            perms,
            privileged,
            dirty: false,
            data: Some(data),
            parent,
        }
    }
}

/// Implements the paging model that allows mapping virtual addresses to physical ones.
///
/// # Role of the Page Table Manager in the Fuzzer
///
/// Using unique virtual address spaces for each guests gives us a better control over memory
/// accessible to them and also prevents inadvertent accesses to each other's memory while fuzzing
/// (e.g. an OOB that goes undetected because the access was on a page allocated for another guest).
/// But to create this virtual address space, we must use translation tables that map virtual
/// addresses to physical ones.
///
/// # Page Tables Implementation
///
/// ## Addressable Virtual Memory
///
/// When we're fuzzing a userland application, even though we're only testing non-privileged code,
/// there are still some privileged operations that need to take place: cache maintenance,
/// exceptions handling, etc. Handling these operations requires to have dedicated code available
/// at fixed addresses in memory and we need to make sure that they don't collide with the
/// program's address ranges.
///
/// To solve this problem, based on the assumption that most userland binaries expect to be mapped
/// at lower addresses, this fuzzer splits a guest address space into two virtual address ranges.
///
///  * The lower address range for non-privileged mappings. It is translated using `TTBR0_EL1` and
///    spans from `0x0000_0000_0000_0000` to `0x0000_ffff_ffff_ffff` by setting `TCR_EL1.T0SZ`
///    to 16.
///  * The upper address range for privileged mappings. It is translated using `TTBR1_EL1` and
///    spans from `0xffff_0000_0000_0000` to `0xffff_ffff_ffff_ffff` by setting `TCR_EL1.T1SZ`
///    to 16.
///
/// ```text
///  0xffff_ffff_ffff_ffff  +---------------------+
///                         |                     |
///                         |      TTBR1_EL1      |
///                         |       REGION        |
///                         |                     |
///  0xffff_0000_0000_0000  +---------------------+  ----> TCR_EL1.T1SZ == 16
///                         |  /////////////////  |
///                         |  /////////////////  |
///                         |  /////////////////  |
///                         |                     |
///                         |  ACCESSES GENERATE  |
///                         |  TRANSLATION FAULT  |
///                         |                     |
///                         |  /////////////////  |
///                         |  /////////////////  |
///                         |  /////////////////  |
///  0x0000_ffff_ffff_ffff  +---------------------+  ----> TCR_EL1.T0SZ == 16
///                         |                     |
///                         |      TTBR0_EL1      |
///                         |       REGION        |
///                         |                     |
///  0x0000_0000_0000_0000  +---------------------+
///
/// ```
///
/// **Note:** While it's possible to have privileged mappings in lower addresses and non-privileged
///           in higher ones, keep in mind that some addresses in the upper virtual address range
///           are reserved by the fuzzer. If you wish to map addresses in the upper VA, make sure
///           they don't overlap or alter existing mappings.
///
/// ## Paging Model
///
/// We'll use two separate page tables for each region: one referenced by `TTBR0_EL1` and the other
/// by `TTBR1_EL1`. But before we move on to the actual implementation, we need to determine the
/// number of page table levels necessary based on our requirements. In the rest of this section,
/// we'll explain the reasoning for the region covered by `TTBR0_EL1`, but the same applies to its
/// counterpart.
///
/// One of our requirements is to have regions with a total size of addressable memory of
/// `0x0001_0000_0000_0000` bytes, which means that a virtual address in these regions is 48-bit
/// long. The second requirement is that the granule size is 4KB.
///
/// With a 4KB granule size, the last 12 bits of the address are directly used as an offset into
/// the corresponding physical page and they don't need to be taken into account during the
/// translation process. But we still need to determine how to split the remaining 36 bits.
///
/// Since the granule size is 4KB, page tables are also 4KB long. And because the descriptors we
/// store in these tables are 8-byte long, this means that we can store at most 512 descriptors.
/// Therefore there are 9 address bits resolved in one level of lookup. If you need more convicing,
/// you can take the example of the last level of a page table lookup starting at address 0. The
/// 512 descriptors it contains spans from the page corresponding to address 0 to the one
/// corresponding to address 0x1ff000, with 0x1ff being 9-bit long.
///
/// All in all, if one level of lookup resolves 9 bits and we need to resolve 36 of them, it means
/// that our page table should have 4 levels.
///
/// ```text
/// Input Address -> 48 bits
///     +--> Level 0: bits [47:39]
///         +--> Level 1: bits [38:30]
///             +--> Level 2: bits [29:21]
///                 +--> Level 3: bits [20:12]
///                     +--> Page offset: bits [11:0]
/// ```
///
/// To address these four levels in the fuzzer, we shamelessly stole Linux's naming convention:
///
/// * [`PageGlobalDirectory`] at level 0;
/// * [`PageUpperDirectory`] at level 1;
/// * [`PageMiddleDirectory`] at level 2;
/// * [`PageTable`] at level 3;
///
/// In each of these structures, there is a [`SlabObject`] that points to the physical memory
/// region that contains the descriptors used during memory translation as well as a hashmap
/// to get a convenient mapping between the descriptor's index and the object it corresponds to
/// (e.g. in a page upper directory, the hashmap stores a mapping with page middle directories).
/// We now need to figure out how to fill these objects to actually map a virtual address.
///
/// ## Mapping a Virtual Address
///
/// If we want to map, for example, a memory page at address 0xdead_beef_c000, we first extract the
/// indices into the page table levels from the input virtual address:
///
/// ```text
/// Input Address -> 0xdead_beef_cafe
///     +--> Level 0: bits [47:39] = (0xdead_beef_cafe >> 39) & 0x1ff = 0x1bd
///         +--> Level 1: bits [38:30] = (0xdead_beef_cafe >> 30) & 0x1ff = 0xb6
///             +--> Level 2: bits [29:21] = (0xdead_beef_cafe >> 21) & 0x1ff = 0x1f7
///                 +--> Level 3: bits [20:12] = (0xdead_beef_cafe >> 12) & 0x1ff = 0xfc
/// ```
///
/// Then, we check if the entries exists in the corresponding levels, starting with the page
/// global directory:
///
///  * if an entry exists in [`PageGlobalDirectory`]'s hashmap for index `0x1bd`, we get the
///    the corresponding [`PageUpperDirectory`] entry and continue.
///  * otherwise, it the entry doesn't exist yet, we create a new `PageUpperDirectory` object, add
///    the PUD descriptor in the physical memory page of the `PageGlobalDirectory` at index `0x1bd`
///    and insert the PUD object into the PGD's hashmap.
///
/// We repeat this process for the [`PageUpperDirectory`] and [`PageMiddleDirectory`].
///
/// When we reach the [`PageTable`] level, there should be no entry at index `0xfc`, otherwise
/// we return a [`MemoryError::AlreadyMapped`] error. We can now create a [`Page`] object, add it
/// to the [`PageTable`]'s hashmap as well as its descriptor into the PT's memory page.
///
/// ```text
///       +-----------+
///       | TTBR0_EL1 |
///       +-----------+
///             |
///             |
///             v
/// +-----------------------+
/// | Page Global Directory |
/// +-----------------------+
///     |
///     +--> Index 0x000: [...]
///     •
///     •
///     •                 +----------------------+
///     +--> Index 0x1bd: | Page Upper Directory |
///     •                 +----------------------+
///                           |
///                           +--> Index 0x000: [...]
///                           •
///                           •
///                           •                 +-----------------------+
///                           +--> Index 0x0b6: | Page Middle Directory |
///                           •                 +-----------------------+
///                                                 |
///                                                 +--> Index 0x000: [...]
///                                                 •
///                                                 •
///                                                 •                 +------------+
///                                                 +--> Index 0x1f7: | Page Table |
///                                                 •                 +------------+
///                                                                       |
///                                                                       +--> Index 0x000: [...]
///                                                                       •
///                                                                       •
///                                                                       •
///                                                                       +--> Index 0x0fc: Page
///                                                                       •
/// ```
///
/// The MMU can now use our page tables to resolve the physical page that corresponds to the
/// the virtual address `0xdead_beef_c000`.
///
/// At this stage, even if we need a bit more abstraction to create a real virtual memory allocator
/// that maps memory, performs read/writes operations, etc., most of the heavy lifting is done
/// by the `PageTableManager`.
///
/// You can refer to [`VirtMemAllocator`] for more information about the virtual memory allocator
/// used by the fuzzer.
///
/// ## Handling Dirty Bits
///
/// Another useful feature that we want for our virtual memory management is the ability to detect
/// pages that have been modified. This is especially important for a fuzzer because it allows us
/// between to only restore the pages that have been modified thus reducing the downtime between
/// every iteration.
///
/// Revision v8.1 of the ARM architecture introduces a hardware dirty state manager, where a page
/// descriptor is modified directly by the processor when the page is modified. However, this
/// feature is not implemented on Apple Silicon chips, according to the `ID_AA64MMFR1_EL1`
/// register.
///
/// ```text
/// // Value read from the CPU
/// ID_AA64MMFR1_EL1 = 0x11212000
///
/// ID_AA64MMFR1_EL1[3:0] = 0b0000
///     -> HAFDBS-> bits [3:0]: Hardware updates to Access flag and Dirty state in translation
///                             tables.
///         -> 0b0000: Hardware update of the Access flag and dirty state are not supported.
/// ```
///
/// But since we still want this feature, we'll have to emulate it in software. To achieve this,
/// we simply remap writable pages to read-only ones (using [`PageDescriptor::read_only`]) and
/// store a copy of the original writable mapping descriptor.
///
/// When the page is written to for the first time, it will raise a data abort exception. If the
/// page descriptor currently in use differs from the saved one, it means that it is a page that
/// was remapped with read-only permissions for the purpose of detecting write accesses to it. In
/// that case, the page is remapped with the original intended permissions, the fault handler then
/// resumes the execution on the faulting address and retry the access.
///
/// This time around, if an exception occurs again, we know it's not related to the
/// handling of dirty states, but an actual exception that needs to be propagated to the
/// corresponding handler.
#[derive(Clone, Debug)]
pub struct PageTableManager {
    pub(crate) slab: SlabAllocator,
    pub(crate) pgd: PageGlobalDirectory,
    pub(crate) allocs: BTreeMap<u64, Rc<RefCell<Page>>>,
}

impl PageTableManager {
    /// Creates a new page table manager using `pma` as the physical memory page provider.
    pub fn new(pma: PhysMemAllocator) -> Result<Self> {
        let mut slab = SlabAllocator::new(pma, PAGE_TABLE_SIZE)?;
        let pgd = PageGlobalDirectory::new(slab.alloc()?);
        Ok(Self {
            slab,
            pgd,
            allocs: BTreeMap::new(),
        })
    }

    /// Maps the virtual address range of size `size` and starting at virtual address `addr` with
    /// permissions `perms`. `privileged` determines if the mapping should be privileged or not
    /// (i.e. whether or not instructions running at EL0 can access it).
    pub fn map(
        &mut self,
        addr: u64,
        size: usize,
        perms: av::MemPerms,
        privileged: bool,
    ) -> Result<()> {
        // Makes sure the range's start address is page-aligned.
        if addr & (VIRT_PAGE_SIZE as u64 - 1) != 0 {
            return Err(MemoryError::UnalignedAddress(addr))?;
        }
        // Makes sure the range's size is page-aligned.
        if size & (VIRT_PAGE_SIZE - 1) != 0 {
            return Err(MemoryError::UnalignedSize(size))?;
        }
        // Computes the start and end of the address range.
        let range_start = addr;
        let range_end = round_virt_page!(addr
            .checked_add(size as u64)
            .ok_or(MemoryError::Overflow(addr, size))?);
        // Iterates over the address of each page boundary and adds them to the page table.
        for addr in (range_start..range_end).step_by(VIRT_PAGE_SIZE) {
            let pud_idx = (addr >> 39 & 0x1ff) as usize;
            // Adds a new PUD if one doesn't already exist at index `pud_idx`.
            if let Entry::Vacant(e) = self.pgd.objects.entry(pud_idx) {
                let pud = PageUpperDirectory::new(self.slab.alloc()?);
                Self::add_entry(pud.descriptor.0, pud_idx, &mut self.pgd.entries)?;
                e.insert(pud);
            }
            // We've made sure that an entry exists here, so it's safe to unwrap.
            let pud = self.pgd.objects.get_mut(&pud_idx).unwrap();

            let pmd_idx = (addr >> 30 & 0x1ff) as usize;
            // Adds a new PMD if one doesn't already exist at index `pmd_idx`.
            if let Entry::Vacant(e) = pud.objects.entry(pmd_idx) {
                let pmd = PageMiddleDirectory::new(self.slab.alloc()?);
                Self::add_entry(pmd.descriptor.0, pmd_idx, &mut pud.entries)?;
                e.insert(pmd);
            }
            // We've made sure that an entry exists here, so it's safe to unwrap.
            let pmd = pud.objects.get_mut(&pmd_idx).unwrap();

            let pt_idx = (addr >> 21 & 0x1ff) as usize;
            // Adds a new PT if one doesn't already exist at index `pt_idx`.
            if let Entry::Vacant(e) = pmd.objects.entry(pt_idx) {
                let pt = PageTable::new(self.slab.alloc()?);
                Self::add_entry(pt.descriptor.0, pt_idx, &mut pmd.entries)?;
                e.insert(Rc::new(RefCell::new(pt)));
            }
            // We've made sure that an entry exists here, so it's safe to unwrap.
            let pt_cell = pmd.objects.get_mut(&pt_idx).unwrap();

            let page_idx = (addr >> 12 & 0x1ff) as usize;
            // Adds a new page entry if one doesn't already exist at index `page_idx`.
            let pt_mut = &mut *pt_cell.borrow_mut();
            let pt_entries = &mut pt_mut.entries;
            let pt_objects = &mut pt_mut.objects;
            if let Entry::Vacant(e) = pt_objects.entry(page_idx) {
                let page = Page::new(
                    self.slab.alloc()?,
                    perms,
                    privileged,
                    Rc::downgrade(pt_cell),
                );
                Self::add_entry(page.descriptor_in_use.0, page_idx, pt_entries)?;
                let page_ref = Rc::new(RefCell::new(page));
                e.insert(page_ref.clone());
                self.allocs.insert(addr, page_ref);
            } else {
                return Err(MemoryError::AlreadyMapped(addr))?;
            }
        }
        Ok(())
    }

    /// Unmaps the virtual address range of size `size` and starting at address `addr`.
    pub fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        // Makes sure the range's start address is page-aligned.
        if addr & (VIRT_PAGE_SIZE as u64 - 1) != 0 {
            return Err(MemoryError::UnalignedAddress(addr))?;
        }
        // Makes sure the range's size is page-aligned.
        if size & (VIRT_PAGE_SIZE - 1) != 0 {
            return Err(MemoryError::UnalignedSize(size))?;
        }
        // Computes the start and end of the address range.
        let range_start = addr;
        let range_end = round_virt_page!(addr
            .checked_add(size as u64)
            .ok_or(MemoryError::Overflow(addr, size))?);
        // Iterates over the address of each page boundary and removes them from the page table.
        for addr in (range_start..range_end).step_by(VIRT_PAGE_SIZE) {
            let pud_idx = (addr >> 39 & 0x1ff) as usize;
            let pud = self
                .pgd
                .objects
                .get_mut(&pud_idx)
                .ok_or(MemoryError::UnallocatedMemoryAccess(addr))?;
            let pmd_idx = (addr >> 30 & 0x1ff) as usize;
            let pmd = pud
                .objects
                .get_mut(&pmd_idx)
                .ok_or(MemoryError::UnallocatedMemoryAccess(addr))?;
            let pt_idx = (addr >> 21 & 0x1ff) as usize;
            let pt_cell = pmd
                .objects
                .get_mut(&pt_idx)
                .ok_or(MemoryError::UnallocatedMemoryAccess(addr))?;
            let page_idx = (addr >> 12 & 0x1ff) as usize;
            let mut pt = pt_cell.borrow_mut();
            let page = pt
                .objects
                .remove(&page_idx)
                .ok_or(MemoryError::UnallocatedMemoryAccess(addr))?;
            self.allocs.remove(&addr);
            let mut page_ref = page.borrow_mut();
            let page_data = page_ref.data.take().unwrap();
            Self::del_entry(page_idx, &mut pt.entries)?;
            self.slab.free(page_data)?;
            // Checks if the page table is empty after removing the page.
            let is_pt_object_empty = pt.objects.is_empty();
            // Drops unused references to please the borrow checker.
            drop(pt);
            if is_pt_object_empty {
                Self::del_entry(pt_idx, &mut pmd.entries)?;
                // It's ok to unwrap here since we've checked that the entry exists.
                let pt_rc = pmd.objects.remove(&pt_idx).unwrap();
                // We can unwrap here, because the parent PMD is the only object with a strong
                // reference to pt_rc and we know that it still exists because it always outlives
                // its children.
                let pt_cell = Rc::try_unwrap(pt_rc).expect("could not unwrap pt_rc");
                let pt = pt_cell.into_inner();
                self.slab.free(pt.entries)?;
            }
            if pmd.objects.is_empty() {
                Self::del_entry(pmd_idx, &mut pud.entries)?;
                // It's ok to unwrap here since we've checked that the entry exists.
                let pmd = pud.objects.remove(&pmd_idx).unwrap();
                self.slab.free(pmd.entries)?;
            }
            if pud.objects.is_empty() {
                Self::del_entry(pud_idx, &mut self.pgd.entries)?;
                // It's ok to unwrap here since we've checked that the entry exists.
                let pud = self.pgd.objects.remove(&pud_idx).unwrap();
                self.slab.free(pud.entries)?;
            }
        }
        Ok(())
    }

    /// Finds a [`Page`] by its address and returns a reference to it.
    pub fn get_page_by_addr(&self, addr: u64) -> Result<Rc<RefCell<Page>>> {
        match self.allocs.get(&addr) {
            Some(r) => Ok(r.clone()),
            None => Err(MemoryError::UnallocatedMemoryAccess(addr))?,
        }
    }

    /// This function is called when a data abort exception occurs. Since we handle dirty states by
    /// remapping pages with read-only permissions, it's possible that the data abort exception
    /// comes from a write access that we want to detect to set the page as dirty.
    ///
    /// This function will try to remap the page with its original permissions stored in the
    /// [`Page`]'s `descriptor` field and set it as dirty. If the page has already been marked as
    /// dirty or if the page was originally read-only, the exception needs to be propagated.
    ///
    /// # Return value
    ///
    /// This functions returns:
    ///
    ///  * `Ok(true)` if a remapping occured because `descriptor_in_use` and `descriptor` differ.
    ///  * `Ok(false)` if no remapping occured since the descriptors were the same.
    ///
    /// This value is used by the data abort exception handler to decide whether it needs to retry
    /// the faulting exception after a remapping or if it should propagate the exception to the
    /// actual data abort handler.
    fn dirty_bit_handler(&mut self, addr: u64) -> Result<bool> {
        let addr = align_virt_page!(addr);
        let mut page = self
            .allocs
            .get(&addr)
            .ok_or(MemoryError::UnallocatedMemoryAccess(addr))?
            .borrow_mut();
        let pt_cell = page.parent.upgrade().unwrap();
        let mut pt = pt_cell.borrow_mut();
        let page_idx = (addr >> 12 & 0x1ff) as usize;
        // If the descriptor differs, it means that the page should be remapped as writable and
        // the dirty bit should be set.
        if page.descriptor_in_use != page.descriptor {
            Self::add_entry(page.descriptor.0, page_idx, &mut pt.entries)?;
            page.descriptor_in_use = page.descriptor;
            page.dirty = true;
            // We return true to signal that we should retry the instruction that caused the
            // exception.
            Ok(true)
        } else {
            // We return false to signal that the exception does not come from the dirty bit and
            // should be handled by the appropriate function.
            Ok(false)
        }
    }

    /// Adds a descriptor `desc` at index `idx` into the [`SlabObject`] `ents` that corresponds to
    /// a page table level.
    #[inline]
    fn add_entry(desc: u64, idx: usize, ents: &mut SlabObject) -> Result<()> {
        if idx > PAGE_TABLE_NB_ENTRIES {
            return Err(MemoryError::InvalidIndex(idx))?;
        }
        // SAFETY: we know that `host_addr` is mapped as long as the `ents` exists and we made sure
        //         that `idx` is not out of bounds.
        unsafe {
            std::ptr::write(ents.host_addr.add(idx * 8) as *mut u64, desc);
        };
        Ok(())
    }

    /// Removes the descriptor at index `idx` from the [`SlabObject`] `ents` that corresponds to
    /// a page table level.
    #[inline]
    pub fn del_entry(idx: usize, ents: &mut SlabObject) -> Result<()> {
        Self::add_entry(0, idx, ents)
    }
}

impl fmt::Display for PageTableManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\nPGD @{:#x}", self.pgd.entries.host_addr as u64)?;
        for (pud_idx, pud) in self.pgd.objects.iter() {
            let desc =
                unsafe { std::ptr::read(self.pgd.entries.host_addr.add(pud_idx * 8) as *mut u64) };
            writeln!(
                f,
                "+-- PUD #{} @{:#x} ({:x})",
                pud_idx, pud.entries.host_addr as u64, desc
            )?;
            for (pmd_idx, pmd) in pud.objects.iter() {
                let desc =
                    unsafe { std::ptr::read(pud.entries.host_addr.add(pmd_idx * 8) as *mut u64) };
                writeln!(
                    f,
                    "  +-- PMD #{} @{:#x} ({:x})",
                    pmd_idx, pmd.entries.host_addr as u64, desc
                )?;
                for (pt_idx, pt_cell) in pmd.objects.iter() {
                    let desc = unsafe {
                        std::ptr::read(pmd.entries.host_addr.add(pt_idx * 8) as *mut u64)
                    };
                    let pt = pt_cell.borrow();
                    writeln!(
                        f,
                        "    +-- PT #{} @{:#x} ({:x})",
                        pt_idx, pt.entries.host_addr as u64, desc
                    )?;
                    for (page_idx, page) in pt.objects.iter() {
                        // SAFETY: we know that `host_addr` is mapped as long as `pt` exists and we
                        //         made sure, when writing the descriptor in memory and storing it
                        //         into the hashmap, that `page_idx` is not out of bounds.
                        let desc = unsafe {
                            std::ptr::read(pt.entries.host_addr.add(page_idx * 8) as *mut u64)
                        };
                        let page = page.borrow();
                        writeln!(
                            f,
                            "      +-- PAGE #{} @{:#x} ({:#x})",
                            page_idx,
                            page.data.as_ref().unwrap().host_addr as u64,
                            desc
                        )?;
                    }
                }
            }
        }
        writeln!(f)
    }
}

// -----------------------------------------------------------------------------------------------
// Guest Virtual Memory Allocator
// -----------------------------------------------------------------------------------------------

/// Virtual memory allocator.
///
/// # Role of the Virtual Memory Allocator in the Fuzzer
///
/// [`PhysMemAllocator`] and [`PageTableManager`] provides the necessary building blocks to create
/// multiple independant virtual address spaces over a shared physical one.
///
/// The role of this allocator is to provide an abstraction over [`PageTableManager`], to easily
/// allocate and access virtual memory inside a guest VM, but also to initialize the different
/// ARM system registers used for memory management (e.g. `TTBR0_EL1/TTBR1_EL1`, `SCTRL_EL1`,
/// `MAIR_EL1`, etc.). It also provides fuzzing specific function, such as the ability to restore
/// a virtual address space from a snapshot.
///
/// Each fuzzing [`Executor`](crate::core::Executor) has at least one instance of this allocator to
/// manage its virtual memory ranges.
///
/// # Example
///
/// ```
/// use applevisor as av;
/// use hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};
///
/// // First we create an hypervisor virtual machine instance to allow memory management in the
/// // guest (there's only one per process).
/// let vm = applevisor::VirtualMachine::new().unwrap();
///
/// // We create a new physical memory allocator over an address range of size 0x1000_0000.
/// let mut pma = PhysMemAllocator::new(0x1000_0000).unwrap();
///
/// // We create a new virtual memory allocator using `pma` as the physical page provider.
/// let mut vma = VirtMemAllocator::new(pma).unwrap();
///
/// // We can now map a virtual memory range starting at address `0x1234_0000`.
/// vma.map(0x1234_0000, 0x1000, av::MemPerms::RWX).unwrap();
///
/// // We can clone the virtual address space.
/// let vma_snapshot = vma.clone();
///
/// // We can write to it.
/// vma.write_qword(0x0000_0000_1000_0000, 0xdead_beef_dead_beef).unwrap();
///
/// // We can read from it.
/// assert_eq!(vma.read_qword(0x0000_0000_1000_0000), Ok(0xdead_beef_dead_beef));
///
/// // We can restore the virtual address space from a snapshot.
/// vma.restore_from_snapshot(&vma_snapshot).unwrap();
/// ```
///
/// Now it's also possible to map code and make the cpu execute arbitrary programs.
///
/// ```
/// use applevisor as av;
/// use keystone as ks;
/// use hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};
///
/// // Creates a new hypervisor virtual machine for this process.
/// let vm = av::VirtualMachine::new().unwrap();
///
/// // Creates an address space of size 0x1000_0000.
/// let pma = PhysMemAllocator::new(0x1000_0000).unwrap();
///
/// // Creates a virtual memory allocator.
/// let mut vma = VirtMemAllocator::new(pma.clone()).unwrap();
///
/// // Creates a new Vcpu.
/// let mut vcpu = av::Vcpu::new().unwrap();
///
/// // Initializes Vcpu system registers.
/// vma.init(&mut vcpu, true).unwrap();
///
/// // Maps an executable page at address 0x10_0000.
/// vma.map(0x10_0000, 0x1000, av::MemPerms::RX).unwrap();
///
/// // We compile a small program using the keystone engine.
/// let ks = ks::Keystone::new(keystone::Arch::ARM64, keystone::Mode::LITTLE_ENDIAN)
///     .expect("Could not initialize Keystone engine");
/// let asm = String::from(
///     "mov x0, #0x0000
///     movk x0, #0x20, lsl #16
///     blr x0
///     brk #0",
/// );
/// let entry_func = ks.asm(asm, 0).expect("could not assemble");
///
/// // We write the function at address 0x10_0000.
/// vma.write(0x10_0000, &entry_func.bytes).unwrap();
///
/// // We create a mapping and write a second function (that will be called by the first one) at
/// // address 0x20_0000.
/// vma.map(0x20_0000, 0x1000, av::MemPerms::RX).unwrap();
/// let asm = String::from(
///     "mov x0, #0x42
///     ret",
/// );
/// let func = ks.asm(asm, 0).expect("could not assemble");
/// vma.write(0x200000, &func.bytes).unwrap();
///
/// // Sets PC to the entry point address.
/// vcpu.set_reg(av::Reg::PC, 0x10_0000).unwrap();
///
/// // Runs the program
/// vcpu.run().unwrap();
///
/// // Checks that the value stored after the program execution is 0x42.
/// assert_eq!(vcpu.get_reg(av::Reg::X0), Ok(0x42));
///
/// // Checks that the Vcpu stopped its execution after an exception was raised when hitting
/// // the breakpoint.
/// let exit = vcpu.get_exit_info();
/// assert_eq!(exit.reason, av::ExitReason::EXCEPTION);
/// assert_eq!(exit.exception.syndrome, 0xf2000000);
/// ```
pub struct VirtMemAllocator {
    /// Page table for the upper virtual address range.
    pub(crate) upper_table: PageTableManager,
    /// Page table for the lower virtual address range.
    pub(crate) lower_table: PageTableManager,
}

impl Clone for VirtMemAllocator {
    fn clone(&self) -> Self {
        // Retrieves the physical memory allocator from the SlabAllocator in PageTableManager.
        let pma = self.upper_table.slab.pma.clone();
        let mut vma =
            VirtMemAllocator::new(pma).expect("error occured while cloning VirtMemAllocator");
        // Iterates over each allocated page in the page table for the lower virtual address range.
        for (&addr, page) in self.lower_table.allocs.iter() {
            let page = page.borrow();
            // If it exists, map the page in the cloned address space.
            vma.lower_table
                .map(addr, VIRT_PAGE_SIZE, page.perms, page.privileged)
                .expect("could not clone the lower memory mapping to the new address space");
            // Creates an array `data` that contains a copy of the page content.
            // SAFETY: the pointer to the page's data is valid as long as `page` exists and we
            //         know that all pages have a size of `VIRT_PAGE_SIZE`.
            let data = unsafe {
                std::slice::from_raw_parts(page.data.as_ref().unwrap().host_addr, VIRT_PAGE_SIZE)
            };
            // Writes `data` into the newly mapped page.
            vma.write(addr, data)
                .expect("could not copy the memory mapping the new address space");
        }
        // Iterates over each allocated page in the page table for the upper virtual address range.
        for (&addr, page) in self.upper_table.allocs.iter() {
            let page = page.borrow();
            // If it exists, map the page in the cloned address space.
            vma.upper_table
                .map(addr, VIRT_PAGE_SIZE, page.perms, page.privileged)
                .expect("could not clone the upper memory mapping to the new address space");
            // Creates an array `data` that contains a copy of the page content.
            // SAFETY: the pointer to the page's data is valid as long as `page` exists and we
            //         know that all pages have a size of `VIRT_PAGE_SIZE`.
            let data = unsafe {
                std::slice::from_raw_parts(page.data.as_ref().unwrap().host_addr, VIRT_PAGE_SIZE)
            };
            // Writes `data` into the newly mapped page.
            vma.write(addr, data)
                .expect("could not copy the memory mapping the new address space");
        }
        vma
    }
}

impl VirtMemAllocator {
    /// Creates a new virtual memory allocator over the physical memory allocator `pma`.
    pub fn new(pma: PhysMemAllocator) -> Result<Self> {
        let upper_table = PageTableManager::new(pma.clone())?;
        let lower_table = PageTableManager::new(pma)?;
        Ok(Self {
            upper_table,
            lower_table,
        })
    }

    /// Modifies different system registers to:
    ///
    ///  * set the page memory attributes;
    ///  * set the granule size;
    ///  * set the size of the upper and lower virtual address ranges;
    ///  * set the page table address of the upper and lower virtual address ranges;
    ///  * enable caches and the MMU;
    ///  * disable SIMD and FP registers access trapping;
    ///  * set the current exception level to EL0;
    ///  * unmask interrupts;
    ///  * initialize the [`Exceptions`] vector table;
    ///  * enable debug features for the hypervisor.
    ///
    /// The `map_exceptions` argument determines if we need to remap the exception vector table
    /// in the current address space. This argument should be set to `false` if the function
    /// is called after restoring from a snapshot.
    pub fn init(&mut self, vcpu: &mut av::Vcpu, map_exceptions: bool) -> Result<()> {
        // MAIR_EL1: 0booooiiii = 0xff
        //  - 0b11RWiiii -> Normal memory, Outer Write-Back Non-transient (Allocate / Allocate)
        //  - 0boooo11RW -> Normal memory, Inner Write-Back Non-transient (Allocate / Allocate)
        vcpu.set_sys_reg(av::SysReg::MAIR_EL1, 0xff)?;
        vcpu.set_sys_reg(av::SysReg::MAIR_EL1, 0x44)?;
        // TCR_EL1
        //  - T0SZ: Size offset of the memory region addressed by TTBR0_EL1.
        //      16 -> Lower address space size = 2^48
        //  - TG0: Granule size for TTBR0_EL1.
        //      0  -> 4KB
        //  - T1SZ: Size offset of the memory region addressed by TTBR1_EL1.
        //      16 -> Upper address space size = 2^48
        //  - TG1: Granule size for TTBR1_EL1.
        //      2  -> 4KB
        //  - HA: Hardware Access flag update in stage 1 translations from EL0 and EL1.
        //      1  -> Stage 1 Access flag update enabled.
        //  - HD: Hardware management of dirty state in stage 1 translations from EL0 and EL1.
        //      1  -> Stage 1 hardware management of dirty state enabled, only if the HA bit is
        //            also set to 1.
        vcpu.set_sys_reg(
            av::SysReg::TCR_EL1,
            0x10 | (0x10 << 16) | (0b10 << 30) | (1 << 39) | (1 << 40),
        )?;
        // TTBRX_EL1
        //  - BADDR: stage 1 translation table base address
        self.set_trans_table_base_registers(vcpu)?;
        // SCTRL_EL1
        //  - Defaults to `0x30100180`.
        //  - I: Stage 1 instruction access Cacheability control, for accesses at EL0 and EL1.
        //  - C: Stage 1 Cacheability control, for data accesses.
        //  - M: MMU enable for EL1&0 stage 1 address translation.
        vcpu.set_sys_reg(av::SysReg::SCTLR_EL1, 0x1005)?;
        // CPACR_EL1
        //  - FPEN: This control does not cause execution of any instructions that access the
        //          Advanced SIMD and floating-point registers to be trapped.
        vcpu.set_sys_reg(av::SysReg::CPACR_EL1, 0x3 << 20)?;
        // CPSR
        //  - M: 0b0000 -> User mode.
        //  - F: FIQ unmasked.
        //  - I: RIQ unmasked.
        //  - A: SError unmasked.
        vcpu.set_reg(av::Reg::CPSR, 0x3c0).unwrap();
        if map_exceptions {
            // Maps and sets VBAR_EL1
            Exceptions::init(vcpu, self)?;
        }
        // Enables debug features for the hypervisor
        vcpu.set_trap_debug_exceptions(true)?;
        vcpu.set_trap_debug_reg_accesses(true)?;
        Ok(())
    }

    /// Sets TTBR0_EL1 and TTBR1_EL1 to the addresses of the current virtual address space page
    /// tables.
    pub fn set_trans_table_base_registers(&self, vcpu: &av::Vcpu) -> Result<()> {
        vcpu.set_sys_reg(
            av::SysReg::TTBR1_EL1,
            self.upper_table.pgd.entries.guest_addr,
        )?;
        vcpu.set_sys_reg(
            av::SysReg::TTBR0_EL1,
            self.lower_table.pgd.entries.guest_addr,
        )?;
        Ok(())
    }

    /// Maps a non-privileged virtual address range of size `size`, starting at address `addr` and
    /// with permissions `perms`.
    #[inline]
    pub fn map(&mut self, addr: u64, size: usize, perms: av::MemPerms) -> Result<()> {
        // Determines which page table should be used based on the region the address is from.
        match addr >> 0x30 {
            0x0000 => self.lower_table.map(addr, size, perms, false),
            0xffff => self.upper_table.map(addr, size, perms, false),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Maps a privileged virtual address range of size `size`, starting at address `addr` and
    /// with permissions `perms`.
    ///
    /// This function exists mainly because PAN is enabled by default on Apple Silicon. Therefore,
    /// all code that runs at EL1 (cache maintenance, exception handling, etc.) should be mapped
    /// using this function, otherwise it will trigger an exception.
    #[inline]
    pub fn map_privileged(&mut self, addr: u64, size: usize, perms: av::MemPerms) -> Result<()> {
        // Determines which page table should be used based on the region the address is from.
        match addr >> 0x30 {
            0x0000 => self.lower_table.map(addr, size, perms, true),
            0xffff => self.upper_table.map(addr, size, perms, true),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Unmaps a virtual address range of size `size` and starting at address `addr`.
    #[inline]
    pub fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        // Determines which page table should be used based on the region the address is from.
        match addr >> 0x30 {
            0x0000 => self.lower_table.unmap(addr, size),
            0xffff => self.upper_table.unmap(addr, size),
            _ => Err(MemoryError::InvalidAddress(addr))?,
        }
    }

    /// Checks if the page fault was due to dirty state detection, and handles it accordingly, or
    /// if it's a legitimate data abort exception that needs to be propagated.
    pub fn page_fault_dirty_state_handler(&mut self, far: u64) -> Result<bool> {
        // Determines which page table should be used based on the region the address is from.
        match far >> 0x30 {
            0x0000 => self.lower_table.dirty_bit_handler(far),
            0xffff => self.upper_table.dirty_bit_handler(far),
            _ => Err(MemoryError::InvalidAddress(far))?,
        }
    }

    /// Restores the current virtual address space from a snapshot.
    pub fn restore_from_snapshot(&mut self, snapshot: &VirtMemAllocator) -> Result<()> {
        enum RestoreOperation {
            Map(u64, Rc<RefCell<Page>>),
            Unmap(u64),
        }
        let mut operations = vec![];
        let mut lower_curr_iter = self.lower_table.allocs.iter();
        let mut lower_snap_iter = snapshot.lower_table.allocs.iter();
        let mut lower_curr_elem = lower_curr_iter.next();
        let mut lower_snap_elem = lower_snap_iter.next();
        // Allocations in the current address space and in the snapshot are sorted.
        // This loop iterates over the allocations of both `VirtMemAllocator` objects and maps,
        // unmaps or restores mapping depending on the conditions below.
        //
        //  - If the iterator over the current address space yields an allocation with an address
        //    smaller than the one returned by the snapshot iterator, it means the allocation only
        //    exists in the current address space. We unmap this allocation and take the next
        //    allocation from the iterator over the current address space.
        //
        //    Current VMA  -> [0x1000, 0x2000, 0x3000] => yields 0x1000
        //    Snapshot VMA -> [0x2000, 0x3000]         => yields 0x2000
        //
        //      -> The mapping at address 0x1000 was created during the execution of the testcase
        //         and needs to be unmapped.
        //
        //  - If the iterator over the current address space yields an allocation with an address
        //    greater than the one returned by the snapshot iterator, it means the allocation only
        //    exists in the snapshot. We remap this allocation in the current address space and
        //    take the next allocation from the snapshot iterator.
        //
        //    Current VMA  -> [0x2000, 0x3000]          => yields 0x2000
        //    Snapshot VMA -> [0x1000, 0x2000, 0x3000]  => yields 0x1000
        //
        //      -> The mapping at address 0x1000 was removed during the execution of the testcase
        //         and needs to be remapped.
        //
        //  - If both iterators returns an allocation with the same address, we need to check if
        //    it was modified during the execution of the testcase using the dirty bit. If the
        //    dirty bit is set, then the allocation in the current address space needs to be
        //    restored using data from the snapshot.
        //
        //    Current VMA  -> [0x1000, 0x2000, 0x3000]  => yields 0x1000 with dirty bit set
        //    Snapshot VMA -> [0x1000, 0x2000, 0x3000]  => yields 0x1000
        //
        //      -> The mapping at address 0x1000 is restored using data from the mapping at address
        //         0x1000 in the snapshot.
        while lower_curr_elem.is_some() || lower_snap_elem.is_some() {
            let (src_addr, src_page) = if let Some(lower_snap_val) = lower_snap_elem.as_mut() {
                (*lower_snap_val.0, Some(&lower_snap_val.1))
            } else {
                // If there are no more allocations in the snapshot, returns the minimum address
                // in case we need to unmap an allocation from the current address space.
                (u64::MIN, None)
            };
            let (dst_addr, dst_page) = if let Some(lower_curr_val) = lower_curr_elem.as_mut() {
                (*lower_curr_val.0, Some(&lower_curr_val.1))
            } else {
                // If there are no more allocations in the current address space, returns the
                // maximum address in case we need to map an allocation from the snapshot.
                (u64::MAX, None)
            };
            match dst_addr.cmp(&src_addr) {
                // If the address is only mapped in the current address space, but not the snapshot
                // it means that the page was created during the execution of a testcase and needs
                // to be removed.
                Ordering::Less => {
                    operations.push(RestoreOperation::Unmap(dst_addr));
                    lower_curr_elem = lower_curr_iter.next();
                }
                // If the page exists in the snapshot but not in the current address space, it
                // means that it was removed during the execution of a testcase and needs to be
                // remapped.
                Ordering::Greater => {
                    operations.push(RestoreOperation::Map(
                        src_addr,
                        Rc::clone(src_page.unwrap()),
                    ));
                    lower_snap_elem = lower_snap_iter.next();
                }
                // If the address is mapped in both address spaces...
                Ordering::Equal => {
                    let mut dst_page = dst_page.unwrap().borrow_mut();
                    // ... and it's been modified, then we need to restore it.
                    if dst_page.dirty {
                        let src_page = src_page.unwrap().borrow();
                        unsafe {
                            std::ptr::copy(
                                src_page.data.as_ref().unwrap().host_addr,
                                dst_page.data.as_ref().unwrap().host_addr as *mut u8,
                                VIRT_PAGE_SIZE,
                            )
                        };
                        // If a page has been modified and its dirty bit set, we need to reset
                        // the descriptor used so that the dirty bit can be tracked in
                        // subsequent iterations.
                        let pt_cell = dst_page.parent.upgrade().unwrap();
                        let mut pt = pt_cell.borrow_mut();
                        let page_idx = (src_addr >> 12 & 0x1ff) as usize;
                        // Resets the page descriptor in the page object.
                        dst_page.descriptor_in_use = src_page.descriptor_in_use;
                        dst_page.descriptor = src_page.descriptor;
                        // Resets the page descriptor in the page table.
                        PageTableManager::add_entry(
                            dst_page.descriptor_in_use.0,
                            page_idx,
                            &mut pt.entries,
                        )?;
                        // Resets the page as clean.
                        dst_page.dirty = false;
                    }
                    lower_curr_elem = lower_curr_iter.next();
                    lower_snap_elem = lower_snap_iter.next();
                }
            }
        }
        // Performs the remaining map/unmap operations.
        for op in operations.into_iter() {
            match op {
                RestoreOperation::Map(src_addr, page) => {
                    let src_page = page.borrow();
                    self.lower_table.map(
                        src_addr,
                        VIRT_PAGE_SIZE,
                        src_page.perms,
                        src_page.privileged,
                    )?;
                    let data = unsafe {
                        std::slice::from_raw_parts(
                            src_page.data.as_ref().unwrap().host_addr,
                            VIRT_PAGE_SIZE,
                        )
                    };
                    self.write(src_addr, data)?;
                }
                RestoreOperation::Unmap(dst_addr) => {
                    self.lower_table.unmap(dst_addr, VIRT_PAGE_SIZE)?
                }
            }
        }

        let mut operations = vec![];
        let mut upper_curr_iter = self.upper_table.allocs.iter();
        let mut upper_snap_iter = snapshot.upper_table.allocs.iter();
        let mut upper_curr_elem = upper_curr_iter.next();
        let mut upper_snap_elem = upper_snap_iter.next();
        // This loop uses the same algorithm than the one detailed above for the lower region
        // allocations.
        while upper_curr_elem.is_some() || upper_snap_elem.is_some() {
            let (src_addr, src_page) = if let Some(upper_snap_val) = upper_snap_elem.as_mut() {
                (*upper_snap_val.0, Some(&upper_snap_val.1))
            } else {
                // If there are no more allocations in the snapshot, returns the minimum address
                // in case we need to unmap an allocation from the current address space.
                (u64::MIN, None)
            };
            let (dst_addr, dst_page) = if let Some(upper_curr_val) = upper_curr_elem.as_mut() {
                (*upper_curr_val.0, Some(&upper_curr_val.1))
            } else {
                // If there are no more allocations in the current address space, returns the
                // maximum address in case we need to map an allocation from the snapshot.
                (u64::MAX, None)
            };
            match dst_addr.cmp(&src_addr) {
                // If the address is only mapped in the current address space, but not the snapshot
                // it means that the page was created during the execution of a testcase and needs
                // to be removed.
                Ordering::Less => {
                    operations.push(RestoreOperation::Unmap(dst_addr));
                    upper_curr_elem = upper_curr_iter.next();
                }
                // If the page exists in the snapshot but not in the current address space, it
                // means that it was removed during the execution of a testcase and needs to be
                // remapped.
                Ordering::Greater => {
                    operations.push(RestoreOperation::Map(
                        src_addr,
                        Rc::clone(src_page.unwrap()),
                    ));
                    upper_snap_elem = upper_snap_iter.next();
                }
                // If the address is mapped in both address spaces...
                Ordering::Equal => {
                    let mut dst_page = dst_page.unwrap().borrow_mut();
                    // ... and it's been modified, then we need to restore it.
                    if dst_page.dirty {
                        let src_page = src_page.unwrap().borrow();
                        unsafe {
                            std::ptr::copy(
                                src_page.data.as_ref().unwrap().host_addr,
                                dst_page.data.as_ref().unwrap().host_addr as *mut u8,
                                VIRT_PAGE_SIZE,
                            )
                        };
                        // If a page has been modified and its dirty bit set, we need to reset
                        // the descriptor used so that the dirty bit can be tracked in
                        // subsequent iterations.
                        let pt_cell = dst_page.parent.upgrade().unwrap();
                        let mut pt = pt_cell.borrow_mut();
                        let page_idx = (src_addr >> 12 & 0x1ff) as usize;
                        // Resets the page descriptor in the page object.
                        dst_page.descriptor_in_use = src_page.descriptor_in_use;
                        dst_page.descriptor = src_page.descriptor;
                        // Resets the page descriptor in the page table.
                        PageTableManager::add_entry(
                            dst_page.descriptor_in_use.0,
                            page_idx,
                            &mut pt.entries,
                        )?;
                        // Resets the page as clean.
                        dst_page.dirty = false;
                    }
                    upper_curr_elem = upper_curr_iter.next();
                    upper_snap_elem = upper_snap_iter.next();
                }
            }
        }
        // Performs the remaining map/unmap operations.
        for op in operations.into_iter() {
            match op {
                RestoreOperation::Map(src_addr, page) => {
                    let src_page = page.borrow();
                    self.upper_table.map(
                        src_addr,
                        VIRT_PAGE_SIZE,
                        src_page.perms,
                        src_page.privileged,
                    )?;
                    let data = unsafe {
                        std::slice::from_raw_parts(
                            src_page.data.as_ref().unwrap().host_addr,
                            VIRT_PAGE_SIZE,
                        )
                    };
                    self.write(src_addr, data)?;
                }
                RestoreOperation::Unmap(dst_addr) => {
                    self.upper_table.unmap(dst_addr, VIRT_PAGE_SIZE)?
                }
            }
        }

        Ok(())
    }

    /// Reads from virtual address `addr` into the slice `buf`. The number of bytes read is the
    /// size of `buf`.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        let mut read_size = 0;
        let mut addr = addr;
        let end_addr = addr
            .checked_add(buf.len() as u64)
            .ok_or(MemoryError::Overflow(addr, buf.len()))?;
        // Loops over each page in the virtual range we're trying to read from.
        loop {
            // Computes the beginning and end address of the virtual page the current address is
            // in.
            let page_start = align_virt_page!(addr);
            let page_end = page_start
                .checked_add(VIRT_PAGE_SIZE as u64)
                .ok_or(MemoryError::Overflow(page_start, VIRT_PAGE_SIZE))?;
            // Computes the start and end offset in the current page based on the number of
            // bytes remaining.
            let offset_start = (addr - page_start) as usize;
            let offset_end = if page_end >= end_addr {
                (end_addr - page_start) as usize
            } else {
                VIRT_PAGE_SIZE
            };
            // Determines which page table should be used based on the region the address is from.
            let page = match page_start >> 0x30 {
                0x0000 => self.lower_table.get_page_by_addr(page_start),
                0xffff => self.upper_table.get_page_by_addr(page_start),
                _ => Err(MemoryError::InvalidAddress(addr))?,
            }?;
            // Reads from the current page into the corresponding slice of `buf`.
            // SAFETY: because we have a reference to the page, we know that it exists, that it's
            //         currently mapped and we made sure above that reading
            //         `offset_end - offset_start` bytes from offset `offset_start` will not
            //         result in an out of bound access.
            unsafe {
                std::ptr::copy(
                    page.borrow()
                        .data
                        .as_ref()
                        .unwrap()
                        .host_addr
                        .add(offset_start),
                    buf.as_mut_ptr().add(read_size),
                    offset_end - offset_start,
                );
            }
            // Updates the number of bytes we've read so far.
            read_size += offset_end - offset_start;
            // Go to the next page if there is still data to write or break if we're done here.
            addr = page_end;
            if page_end >= end_addr {
                break;
            }
        }

        Ok(buf.len())
    }

    /// Reads one byte at virtual address `addr`.
    #[inline]
    pub fn read_byte(&self, addr: u64) -> Result<u8> {
        let mut data = [0u8; 1];
        self.read(addr, &mut data)?;
        Ok(data[0])
    }

    /// Reads one word at virtual address `addr`.
    #[inline]
    pub fn read_word(&self, addr: u64) -> Result<u16> {
        let mut data = [0u8; 2];
        self.read(addr, &mut data)?;
        Ok(u16::from_le_bytes(data[..2].try_into().unwrap()))
    }

    /// Reads one dword at virtual address `addr`.
    #[inline]
    pub fn read_dword(&self, addr: u64) -> Result<u32> {
        let mut data = [0u8; 4];
        self.read(addr, &mut data)?;
        Ok(u32::from_le_bytes(data[..4].try_into().unwrap()))
    }

    /// Reads one qword at virtual address `addr`.
    #[inline]
    pub fn read_qword(&self, addr: u64) -> Result<u64> {
        let mut data = [0u8; 8];
        self.read(addr, &mut data)?;
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }

    /// Reads a C-string at virtual address `addr`.
    #[inline]
    pub fn read_cstring(&self, addr: u64) -> Result<String> {
        let mut chars = vec![];
        let mut c = self.read_byte(addr)?;
        let mut offset = 0;
        while c != 0 {
            chars.push(c);
            offset += 1;
            c = self.read_byte(addr + offset)?;
        }
        Ok(String::from_utf8_lossy(&chars).to_string())
    }

    /// Inner function that writes to virtual address `addr` from the slice `buf` and changes the
    /// dirty bit.
    fn write_inner(&mut self, addr: u64, buf: &[u8], dirty: bool) -> Result<usize> {
        let mut written_size = 0;
        let mut addr = addr;
        let end_addr = addr
            .checked_add(buf.len() as u64)
            .ok_or(MemoryError::Overflow(addr, buf.len()))?;
        // Loops over each page in the virtual range we're trying to write to.
        loop {
            // Computes the beginning and end address of the virtual page the current address is
            // in.
            let page_start = align_virt_page!(addr);
            let page_end = page_start
                .checked_add(VIRT_PAGE_SIZE as u64)
                .ok_or(MemoryError::Overflow(page_start, VIRT_PAGE_SIZE))?;
            // Computes the start and end offset in the current page based on the number of
            // bytes remaining.
            let offset_start = (addr - page_start) as usize;
            let offset_end = if page_end >= end_addr {
                (end_addr - page_start) as usize
            } else {
                VIRT_PAGE_SIZE
            };
            // Determines which page table should be used based on the region the address is from.
            let page = match page_start >> 0x30 {
                0x0000 => self.lower_table.get_page_by_addr(page_start),
                0xffff => self.upper_table.get_page_by_addr(page_start),
                _ => Err(MemoryError::InvalidAddress(addr))?,
            }?;
            // Writes into the current page the corresponding slice of `buf`.
            // SAFETY: because we have a reference to the page, we know that it exists, that it's
            //         currently mapped and we made sure above that writting
            //         `offset_end - offset_start` bytes from offset `offset_start` will not
            //         result in an out of bound access.
            let mut page_b = page.borrow_mut();
            unsafe {
                if dirty {
                    page_b.dirty = true;
                }
                std::ptr::copy(
                    buf.as_ptr().add(written_size),
                    page_b.data.as_ref().unwrap().host_addr.add(offset_start) as *mut u8,
                    offset_end - offset_start,
                );
            }
            // Updates the number of bytes we've written so far.
            written_size += offset_end - offset_start;
            // Go to the next page if there is still data to write or break if we're done here.
            addr = page_end;
            if page_end >= end_addr {
                break;
            }
        }

        Ok(buf.len())
    }

    /// Writes to virtual address `addr` from the slice `buf`. The number of bytes written is the
    /// size of `buf`.
    #[inline]
    pub fn write(&mut self, addr: u64, buf: &[u8]) -> Result<usize> {
        self.write_inner(addr, buf, false)
    }

    /// Writes one byte at virtual address `addr`.
    #[inline]
    pub fn write_byte(&mut self, addr: u64, data: u8) -> Result<usize> {
        self.write(addr, &[data])
    }

    /// Writes one word at virtual address `addr`.
    #[inline]
    pub fn write_word(&mut self, addr: u64, data: u16) -> Result<usize> {
        self.write(addr, &data.to_le_bytes())
    }

    /// Writes one dword at virtual address `addr`.
    #[inline]
    pub fn write_dword(&mut self, addr: u64, data: u32) -> Result<usize> {
        self.write(addr, &data.to_le_bytes())
    }

    /// Writes one qword at virtual address `addr`.
    #[inline]
    pub fn write_qword(&mut self, addr: u64, data: u64) -> Result<usize> {
        self.write(addr, &data.to_le_bytes())
    }

    /// Writes a C-string at virtual address `addr`.
    #[inline]
    pub fn write_cstring(&mut self, addr: u64, s: &str) -> Result<usize> {
        for (i, c) in s.chars().enumerate() {
            self.write_byte(addr + i as u64, c as u8)?;
        }
        self.write_byte(addr + s.len() as u64, 0)?;
        Ok(s.len())
    }

    /// Writes to virtual address `addr` from the slice `buf`. The number of bytes written is the
    /// size of `buf`. Sets the dirty bit.
    #[inline]
    pub fn write_dirty(&mut self, addr: u64, buf: &[u8]) -> Result<usize> {
        self.write_inner(addr, buf, true)
    }

    /// Writes one byte at virtual address `addr`. Sets the dirty bit.
    #[inline]
    pub fn write_byte_dirty(&mut self, addr: u64, data: u8) -> Result<usize> {
        self.write_dirty(addr, &[data])
    }

    /// Writes one word at virtual address `addr`. Sets the dirty bit.
    #[inline]
    pub fn write_word_dirty(&mut self, addr: u64, data: u16) -> Result<usize> {
        self.write_dirty(addr, &data.to_le_bytes())
    }

    /// Writes one dword at virtual address `addr`. Sets the dirty bit.
    #[inline]
    pub fn write_dword_dirty(&mut self, addr: u64, data: u32) -> Result<usize> {
        self.write_dirty(addr, &data.to_le_bytes())
    }

    /// Writes one qword at virtual address `addr`. Sets the dirty bit.
    #[inline]
    pub fn write_qword_dirty(&mut self, addr: u64, data: u64) -> Result<usize> {
        self.write_dirty(addr, &data.to_le_bytes())
    }

    /// Writes a C-string at virtual address `addr`. Sets the dirty bit.
    #[inline]
    pub fn write_cstring_dirty(&mut self, addr: u64, s: &str) -> Result<usize> {
        for (i, c) in s.chars().enumerate() {
            self.write_byte_dirty(addr + i as u64, c as u8)?;
        }
        self.write_byte_dirty(addr + s.len() as u64, 0)?;
        Ok(s.len())
    }

    /// Dumps the current virtual memory content in hex into a file.
    pub fn mem_hexdump(&self, outfile: impl AsRef<Path>) -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(outfile)?;
        for (addr, _) in self.lower_table.allocs.iter() {
            let mut data = vec![0; VIRT_PAGE_SIZE];
            self.read(*addr, &mut data)?;
            writeln!(f, "{:#x}", *addr)?;
            writeln!(f, "{}", rh::hexdump_offset(&data, *addr as u32))?;
        }
        for (addr, _) in self.upper_table.allocs.iter() {
            let mut data = vec![0; VIRT_PAGE_SIZE];
            self.read(*addr, &mut data)?;
            writeln!(f, "{:#x}", *addr)?;
            writeln!(f, "{}", rh::hexdump_offset(&data, *addr as u32))?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_page_round_align() {
        assert_eq!(round_phys_page!(0x1234567), 0x1240000);
        assert_eq!(align_phys_page!(0x1234567), 0x1230000);
        assert_eq!(round_virt_page!(0x1234567), 0x1235000);
        assert_eq!(align_virt_page!(0x1234567), 0x1234000);
    }

    // -------------------------------------------------------------------------------------------
    // Guest Page Tables

    #[test]
    fn page_table_table_descriptor() {
        let mut td = TableDescriptor(0);
        td.set_aptable(2);
        assert_eq!(td.0, 2 << 61);
    }

    #[test]
    fn page_table_read_only_descriptor() {
        let ro_ap = vec![0, 3, 2, 3, 2, 3, 2, 3];
        for (i, expected_ap) in ro_ap.into_iter().enumerate() {
            let ap = (i & 3) as u64;
            let privileged = if (i >> 2) & 1 == 1 { true } else { false };
            let mut d = PageDescriptor(0);
            d.set_ap(ap);
            let ro = d.read_only(privileged);
            assert_eq!(expected_ap, ro.get_ap());
        }
    }
}
