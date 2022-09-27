use applevisor as av;
use eyre;
use goblin as gb;

use hyperpom::core::*;
use hyperpom::corpus::*;
use hyperpom::coverage::*;
use hyperpom::crash::*;
use hyperpom::error::*;
use hyperpom::loader::*;
use hyperpom::memory::*;
use hyperpom::tracer::*;
use hyperpom::utils::*;
use hyperpom::*;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::stubs::*;

// -------------------------------------------------------------------------------------------
// ELF Loader - Main ELF object

/// Represents the ELF binary we want to load and contains the information we need to map it in
/// memory.
#[derive(Clone)]
pub struct Elf {
    /// ELF name (i.e. the path basename).
    name: String,
    /// ELF memory range in the fuzzer's address space.
    range: Range<u64>,
    /// ELF header.
    header: gb::elf::header::Header,
    /// ELF sections ready to be mapped in the fuzzer's address space.
    sections: Vec<Section>,
    /// List of symbols in the ELF file.
    symbols: Vec<ElfSymbol>,
}

impl Elf {
    /// Creates a new object representing an ELF binary.
    pub fn new(path: impl AsRef<Path>, addr: u64) -> eyre::Result<Self> {
        // Extracts the filename from the path
        let name = path
            .as_ref()
            .file_name()
            .ok_or_else(|| eyre::eyre!("error while getting the ELF's name"))?
            .to_str()
            .ok_or_else(|| eyre::eyre!("error while getting the ELF's name"))?
            .to_string();
        // Parses the ELF binary
        let mut file = File::open(&path)?;
        let mut binary = Vec::new();
        file.read_to_end(&mut binary)?;
        let elf = match gb::Object::parse(&binary)? {
            gb::Object::Elf(elf) => elf,
            _ => {
                return Err(eyre::eyre!(
                    "Unsupported file type: {}",
                    path.as_ref().display()
                ))
            }
        };
        // First retrieves the mapped ELF sections from the binary to get the data that will be
        // mapped in the fuzzer.
        let sections = Self::get_sections(&elf, &binary)?;
        // Retrieves the symbols defined in this ELF as well as those imported.
        let symbols = Self::get_symbols(&elf)?;
        // Computes the virtual memory range occupied by this ELF.
        let mapped_elf_size = sections
            .iter()
            .max_by(|a, b| a.range.start.cmp(&b.range.start))
            .unwrap()
            .range
            .end;
        // Rounds up the total ELF size.
        let total_mapped_elf_size = round_virt_page!(mapped_elf_size);
        // Defines the memory range that this binary will occupy in the virtual address space.
        let range = addr..addr + total_mapped_elf_size;
        Ok(Self {
            name,
            header: elf.header,
            range,
            sections,
            symbols,
        })
    }

    /// Retrieves sections information from the ELF binary as well as the data they contain.
    fn get_sections(elf: &gb::elf::Elf, data: &[u8]) -> eyre::Result<Vec<Section>> {
        elf.section_headers
            .iter()
            .enumerate()
            .filter(|(_, section)| section.sh_size != 0 && Section::is_mapped(section))
            .map(|(idx, section)| -> eyre::Result<Section> {
                Section::new(section, idx, elf, data)
            })
            .collect()
    }

    /// Retrieves all symbols defined in the current ELF.
    fn get_symbols(elf: &gb::elf::Elf) -> eyre::Result<Vec<ElfSymbol>> {
        let mut symbols = vec![];
        // Gets static symbols.
        symbols.append(
            &mut elf
                .syms
                .to_vec()
                .into_iter()
                .enumerate()
                .map(|(idx, s)| -> eyre::Result<ElfSymbol> {
                    ElfSymbol::new(&s, idx, &elf.strtab, SymbolTable::Static)
                })
                .collect(),
        );
        // Gets dynamic symbols.
        symbols.append(
            &mut elf
                .dynsyms
                .to_vec()
                .into_iter()
                .enumerate()
                .map(|(idx, s)| -> eyre::Result<ElfSymbol> {
                    ElfSymbol::new(&s, idx, &elf.dynstrtab, SymbolTable::Dynamic)
                })
                .collect(),
        );
        symbols.into_iter().collect()
    }

    /// Finds an ELF section mapped by our loader using its name.
    pub fn get_section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }
}

// -------------------------------------------------------------------------------------------
// ELF Loader - Sections

/// Contains information about a section from the ELF.
#[derive(Clone, Debug)]
pub struct Section {
    /// Section index.
    idx: usize,
    /// Section name
    name: String,
    /// Section virtual address range.
    range: Range<u64>,
    /// Section permissions.
    perms: av::MemPerms,
    /// Section content.
    data: Vec<u8>,
}

impl Section {
    /// Creates a new section object from a raw ELF section.
    pub fn new(
        section: &gb::elf::section_header::SectionHeader,
        idx: usize,
        elf: &gb::elf::Elf,
        data: &[u8],
    ) -> eyre::Result<Self> {
        let vm_range = if !section.vm_range().is_empty() && section.vm_range().len() < 8 {
            section.vm_range().start..section.vm_range().start + 8
        } else {
            section.vm_range()
        };
        let file_range = if let Some(range) = section.file_range() {
            if !range.is_empty() && range.len() < 8 {
                Some(range.start..range.start + 8)
            } else {
                Some(range)
            }
        } else {
            None
        };
        let sh_size = if section.sh_size > 0 && section.sh_size < 8 {
            8
        } else {
            section.sh_size
        };
        Ok(Self {
            idx,
            name: Self::get_name(section, elf)?,
            range: vm_range.start as u64..vm_range.end as u64,
            perms: match (section.is_writable(), section.is_executable()) {
                (false, false) => av::MemPerms::R,
                (false, true) => av::MemPerms::RX,
                (true, false) => av::MemPerms::RW,
                (true, true) => av::MemPerms::RWX,
            },
            data: if let Some(range) = file_range {
                data[range].to_vec()
            } else {
                vec![0; sh_size as usize]
            },
        })
    }

    /// Checks if the section is actually mapped and used once the binary is loaded.
    pub fn is_mapped(section: &gb::elf::SectionHeader) -> bool {
        section.is_alloc()
    }

    /// Retrieves a section's name from the corresponding strtab.
    pub fn get_name(
        section: &gb::elf::section_header::SectionHeader,
        elf: &gb::elf::Elf,
    ) -> eyre::Result<String> {
        Ok(elf
            .shdr_strtab
            .get_at(section.sh_name)
            .ok_or_else(|| eyre::eyre!("unknown section: {:?}", section))?
            .to_string())
    }

    /// Search for a section in the ELF binary using its name.
    pub fn get_by_name<'a>(
        elf: &'a gb::elf::Elf,
        name: &str,
    ) -> Option<&'a gb::elf::SectionHeader> {
        for section in elf.section_headers.iter() {
            if let Some(sec_name) = elf.shdr_strtab.get_at(section.sh_name) {
                if name == sec_name {
                    return Some(section);
                }
            }
        }
        None
    }
}

// -------------------------------------------------------------------------------------------
// ELF Loader - Symbols

/// Represents the table type a symbol is from. This tells us which table to look into when using
/// the symbol's index.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SymbolTable {
    /// Symbol corresponds to the static table.
    Static,
    /// Symbol corresponds to the dynamic table.
    Dynamic,
}

/// Represents an ELF symbol.
#[derive(Clone, Debug, Hash)]
pub struct ElfSymbol {
    /// Index into the corresponding strtab (table type is determined using `table`).
    idx: usize,
    /// Symbol name.
    name: String,
    /// Symbol type.
    stype: u8,
    /// Symbol binding types.
    bind: u8,
    /// Symbol visibility.
    other: u8,
    /// Symbol section header index.
    shndx: usize,
    /// Symbol value (either an offset into a section or an address).
    value: u64,
    /// Symbol size.
    size: u64,
    /// Table the symbol's name can be found in.
    table: SymbolTable,
    /// Set to `true` if the symbol is exported.
    exported: bool,
    /// Set to `true` if the symbol is imported.
    imported: bool,
}

impl ElfSymbol {
    /// Creates a new ELF symbol object.
    pub fn new(
        sym: &gb::elf::sym::Sym,
        idx: usize,
        strtab: &gb::strtab::Strtab,
        table: SymbolTable,
    ) -> eyre::Result<Self> {
        Ok(Self {
            idx,
            name: Self::get_name(sym, strtab)?,
            stype: sym.st_type(),
            bind: sym.st_bind(),
            other: sym.st_other,
            shndx: sym.st_shndx,
            value: sym.st_value,
            size: sym.st_size,
            table,
            exported: Self::is_exported(sym),
            imported: Self::is_imported(sym),
        })
    }

    /// Retrieves the name of a symbol using `shndx` and `table`.
    #[inline]
    fn get_name(sym: &gb::elf::sym::Sym, strtab: &gb::strtab::Strtab) -> eyre::Result<String> {
        Ok(strtab
            .get_at(sym.st_name)
            .ok_or_else(|| eyre::eyre!("unknown symbol: {:?}", sym))?
            .to_string())
    }

    /// Determines if the symbol is exported.
    #[inline]
    fn is_exported(sym: &gb::elf::sym::Sym) -> bool {
        let bind = sym.st_bind();
        (bind == gb::elf::sym::STB_GLOBAL || bind == gb::elf::sym::STB_WEAK) && sym.st_value != 0
    }

    /// Determines if the symbol is imported.
    #[inline]
    fn is_imported(sym: &gb::elf::sym::Sym) -> bool {
        sym.is_import()
    }
}

// -------------------------------------------------------------------------------------------
// ELF Loader - Loader object

#[derive(Clone)]
pub struct PngLoader {
    /// Currently loaded ELF binary.
    elf: Elf,
    /// Current testcase size.
    testcase_size: usize,
    /// Program entry point.
    entry: u64,
}

unsafe impl Send for PngLoader {}

impl PngLoader {
    /// EL0 stack's base address (grows towards 0).
    pub const STACK_ADDR: u64 = 0x0000_ffff_0000_0000;
    /// Stack size.
    pub const STACK_SIZE: usize = 0x0010_0000;
    /// Maximum size of a PNG.
    pub const TESTCASE_MAX_SIZE: usize = 0x10000;
    /// Address in the targeted program's memory of the input buffers.
    pub const PARAMS_ADDR: u64 = 0x0000_fffe_0000_0000;
    /// Size of the input buffers.
    pub const PARAMS_SIZE: usize = 8 + Self::TESTCASE_MAX_SIZE;
    /// Heap address.
    pub const HEAP_ADDR: u64 = 0x0000_fffc_0000_0000;
    /// Heap size.
    pub const HEAP_SIZE: usize = 0x1000;

    /// Creates a new PngLoader object.
    ///
    /// For each of the ELFs provided (the binary and its libraries) it parses it and extracts
    /// its mapped sections data, its relocations and its symbols. It also calls
    /// [`PngLoader::patch_relocations`] to apply the relocations to the binary.
    pub fn new(binary_filepath: PathBuf) -> eyre::Result<Self> {
        // Parses the targeted ELF.
        let elf = Elf::new(binary_filepath, 0)?;
        // Resolves the entry point of the program.
        let entry = Self::find_symbol_address(&elf, "upng_decode").unwrap();
        Ok(Self {
            elf,
            testcase_size: 0,
            entry,
        })
    }

    /// Returns a symbol address in a given ELF.
    fn get_symbol_address(symbol: &ElfSymbol, elf: &Elf) -> Option<u64> {
        if elf.header.e_type == gb::elf::header::ET_REL {
            Some(
                elf.sections
                    .iter()
                    .find(|s| s.idx == symbol.shndx)?
                    .range
                    .start
                    + symbol.value
                    + elf.range.start,
            )
        } else {
            Some(elf.range.start + symbol.value)
        }
    }

    /// Finds the symbol object named `name`.
    fn find_symbol_address(elf: &Elf, name: &str) -> Option<u64> {
        if name == "_GLOBAL_OFFSET_TABLE_" {
            // We unwrap here because our ELF is supposed to have a GOT.
            return Some(elf.range.start + elf.get_section_by_name(".got").unwrap().range.start);
        }
        if let Some(symb) = elf.symbols.iter().find(|s| s.name == name && s.exported) {
            return Self::get_symbol_address(symb, elf);
        }
        if let Some(symb) = elf.symbols.iter().find(|s| {
            s.name == name
                && (s.stype != gb::elf::sym::STT_NOTYPE || s.bind != gb::elf::sym::STB_GLOBAL)
        }) {
            return Self::get_symbol_address(symb, elf);
        }
        None
    }
}

// -------------------------------------------------------------------------------------------
// Shared test objects & functions

/// Global data shared between all fuzzing workers.
#[derive(Clone)]
pub struct GlobalData {
    pub path: Option<PathBuf>,
}

impl GlobalData {
    pub fn new<P: ?Sized + AsRef<Path>>(path: Option<&P>) -> Self {
        if let Some(path) = path {
            // Removes the current trace file.
            let _trace = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .unwrap();
        };
        Self {
            path: path.map(|p| p.as_ref().to_owned()),
        }
    }
}

/// Local data passed around in a unique fuzzing worker.
#[derive(Clone)]
pub struct LocalData {
    pub heap_offset: usize,
    pub heap_size: usize,
    pub allocs: HashMap<u64, usize>,
}

impl LocalData {
    pub fn new() -> Self {
        Self {
            heap_offset: 0,
            heap_size: 0,
            allocs: HashMap::new(),
        }
    }
}

impl Default for LocalData {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------------------------------
// ELF Loader - Loader trait implementation

impl Loader for PngLoader {
    type LD = LocalData;
    type GD = GlobalData;

    // Creates the mapping needed for the binary and writes the instructions extracted from the
    // ELFs into it.
    fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        // Maps the different sections of the ELF we want to load.
        let mut perms: HashMap<u64, av::MemPerms> = HashMap::new();
        for section in self.elf.sections.iter() {
            let start = align_virt_page!(self.elf.range.start + section.range.start);
            let end = round_virt_page!(self.elf.range.start + section.range.end);
            for page_addr in (start..end).step_by(VIRT_PAGE_SIZE) {
                match perms.entry(page_addr) {
                    // If everything went as expected, we simply continue.
                    Entry::Vacant(entry) => {
                        entry.insert(section.perms);
                    }
                    Entry::Occupied(mut entry) => {
                        *entry.get_mut() = *entry.get() | section.perms;
                    }
                }
            }
        }
        for section in self.elf.sections.iter() {
            let start = align_virt_page!(self.elf.range.start + section.range.start);
            let end = round_virt_page!(self.elf.range.start + section.range.end);
            for page_addr in (start..end).step_by(VIRT_PAGE_SIZE) {
                // We can unwrap here because we've already iterated over page addresses and
                // we've made sure that an entry exists for the current page address.
                let page_perms = perms.get(&page_addr).unwrap();
                match executor
                    .vma
                    .borrow_mut()
                    .map(page_addr, VIRT_PAGE_SIZE, *page_perms)
                {
                    // If everything went as expected, we simply continue.
                    Ok(()) => {}
                    // Sections can share the same page, if it's already mapped it's ok, it
                    // means we've already took care of it earlier.
                    Err(Error::Memory(MemoryError::AlreadyMapped(_))) => {}
                    // Otherwise return the error.
                    e => return e,
                }
            }
            executor
                .vma
                .borrow_mut()
                .write(self.elf.range.start + section.range.start, &section.data)?;
        }
        // Maps the stack at the end of the address space.
        executor
            .vma
            .borrow_mut()
            .map(Self::STACK_ADDR, Self::STACK_SIZE, av::MemPerms::RW)?;
        // Maps the testcase and the parameters at `PARAMS_ADDR`.
        executor.vma.borrow_mut().map(
            Self::PARAMS_ADDR,
            round_virt_page!(Self::PARAMS_SIZE) as usize,
            av::MemPerms::RW,
        )?;
        Ok(())
    }

    /// Defines the hooks to apply once memory has been initialized and before pre-execution
    /// initialization occurs.
    fn hooks(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        executor.add_function_hook("malloc", Stub::malloc)?;
        executor.add_function_hook("realloc", Stub::realloc)?;
        executor.add_function_hook("free", Stub::free)?;
        Ok(())
    }

    /// Once the virtual memory space has been created and hooks have been placed, we set the
    /// initial state of the target program and make it ready to be fuzzed. This is the last
    /// function executed before the content of the virtual address space and the values of all
    /// registers are snapshotted. Afterwards, every time the fuzzer finishes an iteration, it
    /// will reset to this state.
    fn pre_snapshot(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        // Sets SP to the base of the stack.
        executor.vcpu.set_sys_reg(
            av::SysReg::SP_EL0,
            Self::STACK_ADDR + Self::STACK_SIZE as u64,
        )?;

        Ok(())
    }

    /// We now enter the iteration loop where the first step is to load the testcase mutated by the
    /// fuzzer.
    fn load_testcase(
        &mut self,
        executor: &mut Executor<Self, Self::LD, Self::GD>,
        testcase: &[u8],
    ) -> Result<LoadTestcaseAction> {
        self.testcase_size = std::cmp::min(Self::TESTCASE_MAX_SIZE, testcase.len());
        executor
            .vma
            .borrow_mut()
            .write_qword(Self::PARAMS_ADDR, self.testcase_size as u64)?;
        // Writes the testcase into the program's address space.
        executor
            .vma
            .borrow_mut()
            .write(Self::PARAMS_ADDR + 8, &testcase[..self.testcase_size])?;
        Ok(LoadTestcaseAction::NewAndReset)
    }

    /// Before running the program, we call `upng_new_from_bytes` that initializes a `upng_t`
    /// structure from our testcase and set PC to the entry point `upng_decode`.
    fn pre_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<ExitKind> {
        // upng_t* upng_new_from_bytes(const unsigned char* buffer, unsigned long size)
        let ret = call_func!(
            executor,
            "upng_new_from_bytes",
            Self::PARAMS_ADDR + 8,
            executor.vma.borrow().read_qword(Self::PARAMS_ADDR)?
        )?;
        if ret.0 == 0 || ret.1 != ExitKind::Exit {
            return Ok(ret.1);
        }
        // Sets PC to `upng_decode`.
        executor.vcpu.set_reg(av::Reg::PC, self.entry)?;
        Ok(ExitKind::Continue)
    }

    /// Once the program returned, we reset the heap state.
    fn post_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<ExitKind> {
        executor.ldata = LocalData::new();
        Ok(ExitKind::Continue)
    }

    /// Returns the list of code ranges that can be instrumented by the fuzzer.
    fn code_ranges(&self) -> Result<Vec<CodeRange>> {
        Ok(self
            .elf
            .sections
            .iter()
            .filter(|s| s.perms == av::MemPerms::RX)
            .map(|s| {
                CodeRange::new(
                    self.elf.range.start + s.range.start,
                    self.elf.range.start + s.range.end,
                )
            })
            .collect::<Vec<_>>())
    }

    /// Returns the list of code ranges that can be used by the fuzzer to compute coverage.
    fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
        Ok(self
            .elf
            .sections
            .iter()
            .filter(|s| s.perms == av::MemPerms::RX)
            .map(|s| {
                CoverageRange::new(
                    self.elf.range.start + s.range.start,
                    self.elf.range.start + s.range.end,
                )
            })
            .collect::<Vec<_>>())
    }

    /// Returns the list of code ranges that can be traced by the fuzzer.
    fn trace_ranges(&self) -> Result<Vec<TraceRange>> {
        Ok(self
            .elf
            .sections
            .iter()
            .filter(|s| s.perms == av::MemPerms::RX)
            .map(|s| {
                TraceRange::new(
                    self.elf.range.start + s.range.start,
                    self.elf.range.start + s.range.end,
                )
            })
            .collect::<Vec<_>>())
    }

    /// Returns the vector of symbols from this binary.
    fn symbols(&self) -> Result<Symbols> {
        let symbols = self
            .elf
            .symbols
            .iter()
            .filter_map(|s| {
                if s.size == 0 {
                    return None;
                }
                Self::find_symbol_address(&self.elf, &s.name)
                    .map(|addr| Symbol::new(&s.name, &self.elf.name, addr, s.size))
            })
            .collect::<Vec<_>>();
        Ok(Symbols::from_vec(symbols))
    }
    // fn display_info(&self, _info: &HyperPomInfo) {}
}
