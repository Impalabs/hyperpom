use hyperpom::applevisor as av;
use hyperpom::config::*;
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

// Empty global data.
#[derive(Clone)]
pub struct GlobalData;
// Empty local data.
#[derive(Clone)]
pub struct LocalData;

// A simple loader that maps a binary at virtual address `0x100000`.
#[derive(Clone)]
pub struct SimpleLoader {
    binary: Vec<u8>,
    entry_point: u64,
}

impl SimpleLoader {
    // Creates a new SimpleLoader object.
    fn new(binary: &[u8]) -> Result<Self> {
        Ok(Self {
            binary: binary.to_vec(),
            entry_point: 0x100000,
        })
    }
}

impl Loader for SimpleLoader {
    type LD = LocalData;
    type GD = GlobalData;

    // Creates the mapping needed for the binary and writes the instructions into it.
    fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        executor.vma.map(
            self.entry_point,
            round_virt_page!(self.binary.len()) as usize,
            av::MemPerms::RX,
        )?;
        executor.vma.write(self.entry_point, &self.binary)?;
        Ok(())
    }

    // Sets PC to the entry point.
    fn pre_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<ExitKind> {
        executor.vcpu.set_reg(av::Reg::PC, self.entry_point)?;
        Ok(ExitKind::Continue)
    }

    // Unused
    fn load_testcase(
        &mut self,
        _executor: &mut Executor<Self, LocalData, GlobalData>,
        _testcase: &[u8],
    ) -> Result<LoadTestcaseAction> {
        Ok(LoadTestcaseAction::NewAndReset)
    }

    // Unused
    fn symbols(&self) -> Result<Symbols> {
        Ok(Symbols::new())
    }

    // Unused
    fn code_ranges(&self) -> Result<Vec<CodeRange>> {
        Ok(vec![])
    }

    // Unused
    fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
        Ok(vec![])
    }

    // Unused
    fn trace_ranges(&self) -> Result<Vec<TraceRange>> {
        Ok(vec![])
    }
}

fn main() {
    // Creates the virtual machine instance needed to access the hypervisor features.
    // This is handled automatically when fuzzing, but needs to be done manually when using an
    // Executor.
    let _vm = av::VirtualMachine::new();
    // Unused, but necessary global and local data structures.
    let gdata = GlobalData;
    let ldata = LocalData;
    // Test binary
    let asm = String::from(
        "mov x0, #0x10
        mov x1, 4
        mul x0, x0, x1
        add x0, x0, 2
        ret",
    );
    // Assembled using the `KSE` keystone engine instance provided by Hyperpom.
    let binary = KSE.with(|ks| ks.asm(asm, 0).expect("could not assemble"));
    // Instanciates the test loader with our assembled instructions.
    let loader = SimpleLoader::new(&binary.bytes).expect("could not create loader");
    // Builds a default configuration for the executor with an address space size of, at most,
    // 0x10000000 bytes.
    let config = ExecConfig::builder(0x10000000).build();
    // Instanciates the executor with the values above.
    let mut executor =
        Executor::<_, _, _>::new(config, loader, ldata, gdata).expect("could not create executor");
    // Initializes the executor's address space and registers.
    // This is handled automatically when fuzzing, but needs to be done manually when using an
    // Executor.
    executor.init().expect("could not init executor");
    // Runs the executor. It will stop automatically when the `ret` instruction is executed.
    executor.run(None).expect("execution failed");
    // Makes sure that we obtained the expected result of 0x42.
    println!("X0 = {:#x}", executor.vcpu.get_reg(av::Reg::X0).unwrap());
    assert_eq!(executor.vcpu.get_reg(av::Reg::X0), Ok(0x42));
}
