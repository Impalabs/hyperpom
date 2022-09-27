use hyperpom::config::*;
use hyperpom::core::*;
use hyperpom::corpus::*;
use hyperpom::coverage::*;
use hyperpom::crash::*;
use hyperpom::error::*;
use hyperpom::hooks::*;
use hyperpom::loader::*;
use hyperpom::memory::*;
use hyperpom::tracer::*;
use hyperpom::utils::*;
use hyperpom::*;

use hyperpom::applevisor as av;

use std::fs::File;
use std::io::prelude::*;

// Defines the global and local data structure, even though we won't use them here.
#[derive(Clone)]
struct GlobalData;
#[derive(Clone)]
struct LocalData;

#[derive(Clone)]
struct SimpleLoader {
    /// The executable's name.
    executable_name: String,
    /// The content of the targeted binary.
    binary: Vec<u8>,
}

impl SimpleLoader {
    /// The targeted binary path.
    const BINARY_PATH: &'static str = "bin/simple_program";
    /// The program's address in memory.
    const BINARY_ADDR: u64 = 0x10_0000;
    /// The stack address.
    const STACK_ADDR: u64 = 0x1_0000_0000;
    /// The stack size.
    const STACK_SIZE: usize = 0x1000;
    /// The address in memory where the testcase should be loaded.
    const TESTCASE_ADDR: u64 = 0x20_0000;
    /// Maximum size of a testcase
    const MAX_TESTCASE_SIZE: usize = 0x20;

    /// Creates a new simple loader object.
    ///
    /// This simply retrieves the information we need about the binary. In this specific case,
    /// the binary is just composed of raw instructions, but with real-world targets, it's much
    /// more likely you'll have to parse executable formats such as Mach-O or ELF.
    fn new() -> Result<Self> {
        // Reads the binary.
        let mut file = File::open(&Self::BINARY_PATH)?;
        let mut binary = Vec::new();
        file.read_to_end(&mut binary)?;
        Ok(Self {
            executable_name: "simple_program".to_string(),
            binary: binary.to_vec(),
        })
    }
}

impl Loader for SimpleLoader {
    type LD = LocalData;
    type GD = GlobalData;

    /// An optional step we can start with, is to define the symbols found in the binary. In this
    /// specific case, it is relatively easy because there are only a few of them. On larger
    /// binaries without any debug information, things get a bit more complicated.
    /// Symbols are not required for the fuzzer to work, but they make things easier when we want
    /// to place hooks or retrieve the address of a specific function.
    ///
    /// Note: if you recompile the program, the offsets might change.
    fn symbols(&self) -> Result<Symbols> {
        Ok(Symbols::from_vec(vec![
            Symbol::new("main", &self.executable_name, Self::BINARY_ADDR, 0x7c),
            Symbol::new(
                "hex2long",
                &self.executable_name,
                Self::BINARY_ADDR + 0x7c,
                0xe4 - 0x7c,
            ),
            Symbol::new(
                "init",
                &self.executable_name,
                Self::BINARY_ADDR + 0xe4,
                0x140 - 0xe4,
            ),
            Symbol::new(
                "strlen",
                &self.executable_name,
                Self::BINARY_ADDR + 0x140,
                0x180 - 0x140,
            ),
            Symbol::new(
                "process",
                &self.executable_name,
                Self::BINARY_ADDR + 0x180,
                0x26c - 0x180,
            ),
            Symbol::new(
                "sum",
                &self.executable_name,
                Self::BINARY_ADDR + 0x26c,
                0x2c4 - 0x26c,
            ),
            Symbol::new(
                "strcmp",
                &self.executable_name,
                Self::BINARY_ADDR + 0x2c4,
                0x340 - 0x2c4,
            ),
        ]))
    }

    /// Once our binary has been parsed and we've retrieved all the information we needed from it
    /// when the loader was instanciated, we can start initializing the address space of the fuzzer
    /// by mapping the binary into it.
    fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        // Maps memory to load the binary's instructions.
        executor.vma.map(
            // The mapping for the binary needs to be page-aligned.
            align_virt_page!(Self::BINARY_ADDR),
            // The mapping size needs to be rounded up to the next page.
            round_virt_page!(self.binary.len()) as usize,
            // Since we're mapping code, the mapping is readable and executable.
            av::MemPerms::RX,
        )?;
        // Writes the content of the binary into the address space of the fuzzer.
        executor.vma.write(Self::BINARY_ADDR, &self.binary)?;
        // Maps the data section of the binary, which is right after the code.
        executor.vma.map(
            align_virt_page!(Self::BINARY_ADDR) + round_virt_page!(self.binary.len()),
            VIRT_PAGE_SIZE,
            // Since we're mapping data, the mapping is readable and writable.
            av::MemPerms::RW,
        )?;
        // Stack mapping.
        executor.vma.borrow_mut().map(
            // Since the stack grows towards the lower addresses, the highest stack address,
            // `STACK_ADDR`, is its base and we need to map it from its top, which is the
            // lowest address.
            Self::STACK_ADDR - Self::STACK_SIZE as u64,
            Self::STACK_SIZE,
            // The stack contains data that should not be executable and is therefore mapped as
            // read-write.
            av::MemPerms::RW,
        )?;
        // Finally, we reserve memory for our testcase.
        executor.vma.borrow_mut().map(
            Self::TESTCASE_ADDR,
            round_virt_page!(Self::MAX_TESTCASE_SIZE as u64) as usize,
            av::MemPerms::RW,
        )?;
        Ok(())
    }

    /// We can now define the hooks that we will apply to the binary.
    /// The function we might want to hook is `sum`, which is found at offset `0x26c` in the
    /// binary. It requires specific inputs to allow the program to continue and is just there as
    /// a verification system, so it doesn't hurt to simply hook it and make it return the expected
    /// value.
    /// Another function that we can hook is strcmp, found at offset `0x2c4`. Currently the fuzzer
    /// is unable to distinguish between an iteration that matched 10 characters during a string
    /// comparison or only one. This hook will add additional paths in the coverage data structure
    /// each time a new character is matched.
    fn hooks(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        // We define the hook we will apply on the `sum` function at offset `0x26c` (which
        // corresponds to address self.binary_address + 0x26c once the binary is mapped).
        fn sum_hook(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
            // We place in the `X0` register the value we want to return, which is 0x9db.
            args.vcpu.set_reg(av::Reg::X0, 0x9db)?;
            // We retrieve the LR register...
            let lr = args.vcpu.get_reg(av::Reg::LR)?;
            // ... and set PC to it, to return from function and effectively ignore it.
            args.vcpu.set_reg(av::Reg::PC, lr)?;
            // The return value of the function is set to `ExitKind::EarlyFunctionReturn`, because
            // as its name suggests, we returned from the function before it did on its own.
            // This specific value is there mostly when a crash occurs and the backtrace is
            // computed. Backtrace hooks are place on `ret` instructions to know that we've
            // returned from the function and update the backtrace accordingly. Although, when we
            // hook a function and return manually, the fuzzer can't know we've returned earlier
            // unless we tell him explicitly.
            Ok(ExitKind::EarlyFunctionReturn)
        }
        // The hook is placed at the start of the `sum` function.
        executor.add_function_hook("sum", sum_hook)?;
        // We then define the hook we will apply on the `strcmp` function at offset `0x2c4` (which
        // corresponds to address self.binary_address + 0x2c4 once the binary is mapped).
        fn strcmp_hook(args: &mut HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
            let s1 = args.vcpu.get_reg(av::Reg::X0)?;
            let s2 = args.vcpu.get_reg(av::Reg::X1)?;
            let mut i = 0;
            let mut c1;
            let mut c2;
            loop {
                c1 = args.vma.read_byte(s1 + i)? as u64;
                c2 = args.vma.read_byte(s2 + i)? as u64;
                i += 1;
                if c1 == 0 || c2 == 0 || c1 != c2 {
                    break;
                }
                let pc = (i as u128) << 0x40 | args.addr as u128;
                args.cdata.set.insert(pc);
            }
            args.vcpu.set_reg(av::Reg::X0, c1 - c2)?;
            let lr = args.vcpu.get_reg(av::Reg::LR)?;
            args.vcpu.set_reg(av::Reg::PC, lr)?;
            Ok(ExitKind::EarlyFunctionReturn)
        }
        // The hook is placed at the start of the `strcmp` function.
        executor.add_function_hook("strcmp", strcmp_hook)?;
        Ok(())
    }

    /// Once the virtual memory space has been created and hooks have been placed, we set the
    /// initial state of the target program and make it ready to be fuzzed. This is the last
    /// function executed before the content of the virtual address space and the values of all
    /// registers are snapshotted. Afterwards, every time the fuzzer finishes an iteration, it
    /// will reset to this state.
    fn pre_snapshot(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        // Sets SP to the base of the stack.
        executor
            .vcpu
            .set_sys_reg(av::SysReg::SP_EL0, Self::STACK_ADDR)?;
        // We call the init function and pass the magic value to it. This will set the variable
        // `g_state` to the correct value and will allow us to go further into the `process`
        // function.
        let ret = call_func!(executor, "init", 0xdead_beef)?;
        // We make sure that we returned from the function without a crash or another error.
        assert_eq!(ret.1, ExitKind::Exit);
        // We search for the address of the `process` function, since it will already have been
        // defined in the executor by the time this function is called.
        let process = executor
            .symbols
            .symbols
            .iter()
            .find(|(_, s)| &s.name == "process")
            .map(|(_, s)| s)
            .unwrap();
        // We set the entry point of the fuzzer to the `process` function.
        executor.vcpu.set_reg(av::Reg::PC, process.addr)?;
        Ok(())
    }

    /// We now enter the iteration loop where the first step is to load the testcase mutated by the
    /// fuzzer.
    fn load_testcase(
        &mut self,
        executor: &mut Executor<Self, Self::LD, Self::GD>,
        testcase: &[u8],
    ) -> Result<LoadTestcaseAction> {
        // We write the content of the testcase into the fuzzer's address space.
        executor.vma.write(Self::TESTCASE_ADDR, testcase)?;
        // We also set the argument of the function to the address of the testcase and its size.
        executor.vcpu.set_reg(av::Reg::X0, Self::TESTCASE_ADDR)?;
        executor.vcpu.set_reg(av::Reg::X1, testcase.len() as u64)?;
        // The return value of this function tells the fuzzer whether we want to discard the
        // current testcase and reset the memory and cpu state. This feature is implemented because
        // we might want to do multiple iterations with a single testcase, where we consume it
        // partially every loop, until it's empty and we want another one. This can be useful for
        // programs that rely on a state machine.
        Ok(LoadTestcaseAction::NewAndReset)
    }

    /// This method defines the code ranges where instruction hooks can be applied.
    /// They are optional, but keep in mind that they need to be defined when instruction hooks
    /// are applied, otherwise nothing will happen, even though `add_instruction_hook` returned
    /// successfully.
    fn code_ranges(&self) -> Result<Vec<CodeRange>> {
        Ok(vec![CodeRange::new(
            Self::BINARY_ADDR,
            Self::BINARY_ADDR + self.binary.len() as u64,
        )])
    }

    /// This method defines the code ranges where coverage hooks can be applied.
    /// They are optional, but keep in mind that they need to be defined when coverage hooks
    /// are applied, otherwise there won't be any coverage on the target.
    fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
        Ok(vec![CoverageRange::new(
            Self::BINARY_ADDR,
            Self::BINARY_ADDR + self.binary.len() as u64,
        )])
    }

    /// This method defines the code ranges where tracing hooks can be applied.
    /// They are optional, but keep in mind that they need to be defined when tracing hooks
    /// are applied, otherwise the tracer won't return anything.
    fn trace_ranges(&self) -> Result<Vec<TraceRange>> {
        Ok(vec![TraceRange::new(
            Self::BINARY_ADDR,
            Self::BINARY_ADDR + self.binary.len() as u64,
        )])
    }
}

fn main() {
    // Instanciates global and local data.
    let gdata = GlobalData;
    let ldata = LocalData;
    // Creates a loader for the target binary.
    let loader = SimpleLoader::new().expect("could not create the loader");
    // Creates a config for the fuzzer.
    let config = FuzzConfig::<_, _>::builder(0x1000_0000, "tmp/work", "tmp/corpus")
        .nb_workers(4)
        .seed(0xdeadbeefdeadbeef)
        .max_nb_mutations(10)
        .max_testcase_size(SimpleLoader::MAX_TESTCASE_SIZE)
        .timeout(std::time::Duration::new(60, 0))
        .comparison_unrolling(true)
        .build();
    // Creates an instance of the fuzzer.
    let mut hp =
        HyperPom::<_, _, _>::new(config, loader, ldata, gdata).expect("could not create fuzzer");
    // Start fuzzing!
    hp.fuzz().expect("an error occured while fuzzing");
}
