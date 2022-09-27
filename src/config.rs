//! Implements the fuzzer configuration builder.

use std::path::{Path, PathBuf};
use std::time::Duration;

use time::OffsetDateTime;

use crate::hooks::*;

/// Structure that contains the different configuration options for the fuzzer.
///
///  * If you're fuzzing with [`HyperPom`](crate::core::HyperPom), use a [`FuzzConfig`]
///    configuration object.
///  * If you're running arbitrary code with an [`Executor`](crate::core::Executor), use an
///    [`ExecConfig`] configuration object.
#[derive(Clone)]
pub struct Config<LD, GD> {
    /// Size of the physical memory address space shared between all virtual memory address spaces.
    pub(crate) as_size: usize,
    /// Number of workers (fuzzing threads) spawned by the main process.
    pub(crate) nb_workers: u32,
    /// Path to the working directory.
    pub(crate) working_directory: Option<PathBuf>,
    /// Path to the corpus.
    pub(crate) corpus_directory: Option<PathBuf>,
    /// Duration after which the execution of a testcase can be considered as having timed out.
    pub(crate) timeout: Duration,
    /// Number of testcases executed by one worker thread. Runs indefinitely if set to `None`.
    pub(crate) iterations: Option<u64>,
    /// Seed used for random generation.
    pub(crate) seed: u64,
    /// Enables coverage if set to `true`.
    pub(crate) coverage: bool,
    /// Enables instruction tracing if set to `true`.
    pub(crate) tracer: bool,
    /// Sets the tracing hook.
    pub(crate) tracer_hook: Option<HookFn<LD, GD>>,
    /// Enables crash saving if set to `true`.
    pub(crate) save_crashes: bool,
    /// Enables timeout saving if set to `true`.
    pub(crate) save_timeouts: bool,
    /// Enables corpus loading at startup if set to `true` (this will run each corpus' testcases
    /// to populate the global coverage structure).
    pub(crate) load_corpus_at_init: bool,
    /// The maximum size of a testcase.
    pub(crate) max_testcase_size: usize,
    /// The maximum number of mutations per iteration.
    pub(crate) max_nb_mutations: usize,
    /// The number of iterations needed before a crash is considered stable.
    pub(crate) crash_verif_iterations: usize,
    /// Removes coverage hooks when a new path is hit if set to `true`.
    /// This makes the fuzzer converges to almost no overhead (apart from backtrace and
    /// user-defined custom hooks), however it might end up getting stuck on some hard paths
    /// (e.g. 4-byte comparisons made in a loop, the first iteration is easy since comparison
    /// unrolling is still active, however the subsequent ones wont benefit from it because it gets
    /// removed).
    //
    //  TODO: Maybe add a mode that deletes regular coverage hooks but keep the ones used for
    //        comparison unrolling.
    pub(crate) remove_coverage_hooks_on_hit: bool,
    /// Enables comparison unrolling if set to `true`.
    pub(crate) comparison_unrolling: bool,
}

/// Represents the type of configuration that the builder should return.
enum ConfigType {
    // A configuration for an [`Executor`](crate::core::Executor) object.
    Executor,
    // A configuration for a [`Worker`](crate::core::Worker) object.
    Fuzzer,
}

/// Actual configuration data returned by the builder.
pub enum ConfigData<LD, GD> {
    // Configuration data for an [`Executor`](crate::core::Executor) object.
    Executor(Config<LD, GD>),
    // Configuration data for a [`Worker`](crate::core::Worker) object.
    Fuzzer(Config<LD, GD>),
}

/// Configuration object used when running an [`HyperPom`](crate::core::HyperPom) fuzzer.
///
/// # Example
///
/// ```
/// use hyperpom::config::FuzzConfig;
/// use hyperpom::core::HyperPom;
///
/// // User-defined worker-local data structure.
/// pub struct Ld {
///     // [...]
/// }
///
/// // User-defined fuzzer-wide shared data structure.
/// pub struct Gd {
///     // [...]
/// }
///
/// // Binary loader.
/// pub struct DummyLoader {
///     // [...]
/// }
///
/// // Creates a new configuration for the fuzzer with a `0x100000`-byte address space,
/// // `/tmp/hyperpom/` as the working directory and `/tmp/corpus/` as the corpus directory.
/// let c = FuzzConfig::<Ld, Gd>::builder(0x100000, "/tmp/hyperpom/", "/tmp/corpus/")
///     .nb_workers(64)                             // Spawns 64 fuzzing workers.
///     .seed(0xdeadbeef)                           // The random generator is initialized with
///                                                 // the seed 0xdeadbeef.
///     .timeout(std::time::Duration::new(60, 0))   // A testcase will timeout after 60 seconds.
///     .iterations(Some(1000))                     // Each worker will execute 1000 testcases
///                                                 // before stopping.
///     .build();                                   // Builds the configuration.
///
/// // Creates an instance of the fuzzer.
/// let mut hp = HyperPom::<_, _, _>::new(config, loader, ldata, gdata)
///     .expect("could not create fuzzer");
#[derive(Clone)]
pub struct FuzzConfig<LD, GD> {
    phantom_ld: std::marker::PhantomData<LD>,
    phantom_gd: std::marker::PhantomData<GD>,
}

impl<LD, GD> FuzzConfig<LD, GD> {
    /// Creates a new builder instance for the fuzzer's configuration.
    pub fn builder(
        as_size: usize,
        working_dir: impl AsRef<Path>,
        corpus_dir: impl AsRef<Path>,
    ) -> ConfigBuilder<LD, GD> {
        ConfigBuilder::<LD, GD>::new(
            as_size,
            Some(working_dir),
            Some(corpus_dir),
            ConfigType::Fuzzer,
        )
    }
}

/// Configuration object used when running an [`Executor`](crate::core::Executor).
///
/// # Example
///
/// ```
/// use hyperpom::config::ExecConfig;
/// use hyperpom::core::Executor;
///
/// // User-defined worker-local data structure.
/// pub struct Ld {
///     // [...]
/// }
///
/// // User-defined fuzzer-wide shared data structure.
/// pub struct Gd {
///     // [...]
/// }
///
/// // Binary loader.
/// pub struct DummyLoader {
///     // [...]
/// }
///
/// // Instanciates the virtual machine for the executor.
/// let _vm = av::VirtualMachine::new();
///
/// // Creates a new configuration for the executor with a `0x100000`-byte address space
/// let c = ExecConfig::<Ld, Gd>::builder(0x100000).build();
///
/// // Creates an executor instance.
/// let mut hp = Executor::<_, _, _>::new(config, loader, ldata, gdata)
///     .expect("could not create fuzzer");
#[derive(Clone)]
pub struct ExecConfig<LD, GD> {
    phantom_ld: std::marker::PhantomData<LD>,
    phantom_gd: std::marker::PhantomData<GD>,
}

impl<LD, GD> ExecConfig<LD, GD> {
    /// Creates a new builder instance for the executor's configuration.
    pub fn builder(as_size: usize) -> ConfigBuilder<LD, GD> {
        ConfigBuilder::<LD, GD>::new(
            as_size,
            None::<&std::path::Path>,
            None::<&std::path::Path>,
            ConfigType::Executor,
        )
    }
}

/// Generic configuration builder.
pub struct ConfigBuilder<LD, GD> {
    /// The types of configuration the builder ends up instanciating.
    config_type: ConfigType,
    /// The inner configuration object.
    config: Config<LD, GD>,
}

impl<LD, GD> ConfigBuilder<LD, GD> {
    /// Creates a new configuration builder.
    fn new(
        as_size: usize,
        working_dir: Option<impl AsRef<Path>>,
        corpus_dir: Option<impl AsRef<Path>>,
        config_type: ConfigType,
    ) -> Self {
        Self {
            config_type,
            config: Config {
                as_size,
                nb_workers: 1,
                working_directory: working_dir.map(|d| d.as_ref().to_owned()),
                corpus_directory: corpus_dir.map(|d| d.as_ref().to_owned()),
                timeout: Duration::new(3, 0),
                iterations: None,
                seed: OffsetDateTime::now_utc().nanosecond() as u64,
                coverage: true,
                tracer: false,
                tracer_hook: None,
                save_crashes: true,
                save_timeouts: true,
                load_corpus_at_init: true,
                max_testcase_size: 0x1000,
                max_nb_mutations: 10,
                crash_verif_iterations: 3,
                remove_coverage_hooks_on_hit: true,
                comparison_unrolling: false,
            },
        }
    }

    /// Returns the [`Config`] object wrapper built with the current [`ConfigBuilder`].
    pub fn build(self) -> ConfigData<LD, GD> {
        match self.config_type {
            ConfigType::Fuzzer => ConfigData::Fuzzer(self.config),
            ConfigType::Executor => ConfigData::Executor(self.config),
        }
    }

    /// Sets the the address space size.
    pub fn as_size(mut self, as_size: usize) -> Self {
        self.config.as_size = as_size;
        self
    }

    /// Sets the number of fuzzing worker.
    pub fn nb_workers(mut self, nb_workers: u32) -> Self {
        self.config.nb_workers = nb_workers;
        self
    }

    /// Sets the path to the fuzzer's working directory.
    pub fn working_directory(mut self, working_directory: impl AsRef<Path>) -> Self {
        self.config.working_directory = Some(working_directory.as_ref().to_owned());
        self
    }

    /// Sets the path to the corpus directory.
    pub fn corpus_directory(mut self, corpus_directory: impl AsRef<Path>) -> Self {
        self.config.corpus_directory = Some(corpus_directory.as_ref().to_owned());
        self
    }

    /// Sets the duration before a testcase can be considered as having timed out.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Sets the number of testcases to execute per worker.
    pub fn iterations(mut self, iterations: Option<u64>) -> Self {
        self.config.iterations = iterations;
        self
    }

    /// Sets the seed used by the random number generator.
    pub fn seed(mut self, seed: u64) -> Self {
        self.config.seed = seed;
        self
    }

    /// Enables coverage if set to `true`.
    pub fn coverage(mut self, coverage: bool) -> Self {
        self.config.coverage = coverage;
        self
    }

    /// Enables tracing if set to `true`.
    pub fn tracer(mut self, tracer: bool) -> Self {
        self.config.tracer = tracer;
        self
    }

    /// Enables tracing by setting the tracer hook.
    pub fn tracer_hook(mut self, tracer_hook: HookFn<LD, GD>) -> Self {
        self.config.tracer_hook = Some(tracer_hook);
        self
    }

    /// Enables crash saving if set to `true`.
    pub fn save_crashes(mut self, save_crashes: bool) -> Self {
        self.config.save_crashes = save_crashes;
        self
    }

    /// Enables timeout saving if set to `true`.
    pub fn save_timeouts(mut self, save_timeouts: bool) -> Self {
        self.config.save_timeouts = save_timeouts;
        self
    }

    /// Enables corpus loading at startup if set to `true` (this will run once every testcase in
    /// the corpus to populate the global coverage structure).
    pub fn load_corpus_at_init(mut self, load_corpus_at_init: bool) -> Self {
        self.config.load_corpus_at_init = load_corpus_at_init;
        self
    }

    /// Sets the maximum size of a testcase.
    pub fn max_testcase_size(mut self, max_testcase_size: usize) -> Self {
        self.config.max_testcase_size = max_testcase_size;
        self
    }

    /// Sets the maximum number of mutations per fuzzing iteration.
    pub fn max_nb_mutations(mut self, max_nb_mutations: usize) -> Self {
        self.config.max_nb_mutations = max_nb_mutations;
        self
    }

    /// Sets number of iterations needed before a crash is considered stable.
    pub fn crash_verif_iterations(mut self, crash_verif_iterations: usize) -> Self {
        self.config.crash_verif_iterations = 1 + crash_verif_iterations;
        self
    }

    /// Enables crash saving if set to `true`.
    pub fn remove_coverage_hooks_on_hit(mut self, remove_coverage_hooks_on_hit: bool) -> Self {
        self.config.remove_coverage_hooks_on_hit = remove_coverage_hooks_on_hit;
        self
    }

    /// Enables comparison unrolling if set to `true`.
    pub fn comparison_unrolling(mut self, comparison_unrolling: bool) -> Self {
        self.config.comparison_unrolling = comparison_unrolling;
        self
    }
}
