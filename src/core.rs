//! The core components that setup and manage the fuzzer.

use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::simd;
use std::sync::mpsc::{channel, sync_channel, Sender, SyncSender};
use std::sync::{Arc, Barrier, RwLock};
use std::thread;
use std::time;

use applevisor as av;
use regex as re;

use crate::backtrace::*;
use crate::caches::*;
use crate::config::*;
use crate::corpus::*;
use crate::coverage::*;
use crate::crash::*;
use crate::error::*;
use crate::exceptions::*;
use crate::hooks::*;
use crate::loader::*;
use crate::memory::*;
use crate::mutator::*;
use crate::tracer::*;
use crate::utils::*;

thread_local!(
    /// A per-thread global keystone instance used to assemble ARM instructions.
    pub static KSE: keystone_engine::Keystone = keystone_engine::Keystone::new(
        keystone_engine::Arch::ARM64,
        keystone_engine::Mode::LITTLE_ENDIAN,
    )
    .expect("Could not initialize Keystone engine");
    /// A per-thread global capstone instance used to disassemble ARM instructions.
    pub static CSE: capstone::Capstone = capstone::Capstone::new_raw(
        capstone::Arch::ARM64,
        capstone::Mode::Arm,
        capstone::NO_EXTRA_MODE,
        Some(capstone::Endian::Little),
    )
    .expect("Could not initialize Capstone engine");
);

/// Structure that contains runtime information from the fuzzer.
pub struct HyperPomInfo {
    /// The time at which the fuzzer started.
    pub start_time: time::Instant,
    /// The number of testcases.
    pub nb_testcases: u64,
    /// The number of crashes.
    pub nb_crashes: u64,
    /// The number of unique crashes.
    pub nb_uniq_crashes: u64,
    /// The number of timeouts.
    pub nb_timeouts: u64,
    /// The number of coverage paths.
    pub nb_paths: u64,
}

impl HyperPomInfo {
    /// Creates a new object info.
    pub fn new() -> Self {
        Self {
            start_time: time::Instant::now(),
            nb_testcases: 0,
            nb_crashes: 0,
            nb_uniq_crashes: 0,
            nb_timeouts: 0,
            nb_paths: 0,
        }
    }
}

impl Default for HyperPomInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Add<WorkerInfo> for HyperPomInfo {
    type Output = Self;

    fn add(self, other: WorkerInfo) -> Self {
        Self {
            start_time: self.start_time,
            nb_testcases: self.nb_testcases + other.nb_testcases,
            nb_crashes: self.nb_crashes + other.nb_crashes,
            nb_uniq_crashes: self.nb_uniq_crashes + other.nb_uniq_crashes,
            nb_timeouts: self.nb_timeouts + other.nb_timeouts,
            nb_paths: self.nb_paths + other.nb_paths,
        }
    }
}

impl std::ops::AddAssign<WorkerInfo> for HyperPomInfo {
    fn add_assign(&mut self, other: WorkerInfo) {
        *self = Self {
            start_time: self.start_time,
            nb_testcases: self.nb_testcases + other.nb_testcases,
            nb_crashes: self.nb_crashes + other.nb_crashes,
            nb_uniq_crashes: self.nb_uniq_crashes + other.nb_uniq_crashes,
            nb_timeouts: self.nb_timeouts + other.nb_timeouts,
            nb_paths: self.nb_paths + other.nb_paths,
        };
    }
}

// -----------------------------------------------------------------------------------------------
// Hyperpom - Main Object
// -----------------------------------------------------------------------------------------------

/// The main fuzzer object.
///
/// # HyperPom
///
/// This structure offers the main interface to start and interact with the fuzzer. A new instance
/// can be created using [`HyperPom::new`] and expects four arguments.
///
///  * A [`crate::config::Config`] object that contains the parameters used to configure the
///    fuzzer (the number of workers to instanciate, the path to the corpus directory, the seed for
///    the PRNG, etc.).
///  * An implementation of the [`crate::loader::Loader`] trait, to give the necessary tools and
///    information to the fuzzer so that workers can load the targeted program.
///  * A *Global Data* structure, which is a generic type used by the fuzzer to share data between
///    all workers.
///  * A *Local Data* structure, which is a generic type that gets cloned passed to each workers so
///    they can store local data.
///
/// Once the different objects needed have been instanciated, the fuzzer can be run using
/// [`HyperPom::fuzz`]. It will create as many threads as defined by the configuration and
/// instanciate one worker in it. Each worker run independently while occasionally sharing some
/// information (coverage, global data, corpus, etc.).
///
/// For more information about fuzzing workers, refer to [`Worker`].
///
/// # Example
///
/// ```
/// use hyperpom::config::Config;
/// use hyperpom::core::HyperPom;
/// use hyperpom::loader::Loader;
///
/// #[derive(Clone)]
/// pub struct GlobalData(u32);
///
/// #[derive(Clone)]
/// pub struct LocalData(u32);
///
/// #[derive(Clone)]
/// pub struct DummyLoader;
///
/// impl Loader for DummyLoader {
///     // [...]
/// }
///
/// // We instanciate a global data object.
/// let gdata = GlobalData(0);
/// // We instanciate a local data object.
/// let ldata = LocalData(0);
///
/// // `loader` contains the methods that will load and map the program from the file `binary`.
/// let loader = DummyLoader::new("./binary");
///
/// // We create a configuration for the fuzzer.
/// let config = Config::builder(0x10000000, "/tmp/hyperpom/", "/tmp/corpus/")
///     .nb_workers(64)
///     .seed(0xdeadbeef)
///     .timeout(std::time::Duration::new(60, 0))
///     .iterations(Some(1))
///     .build();
///
/// // We instanciate the fuzzer and pass the previous arguments to it.
/// let mut hp = HyperPom::<DummyLoader, LocalData, GlobalData>::new(config, loader, ldata, gdata)
///     .unwrap();
///
/// // The fuzzer can now be started.
/// hp.fuzz().expect("fuzzing failed");
/// ```
pub struct HyperPom<L: 'static + Loader, LD, GD> {
    /// Object that contains the different hooks applied to the fuzzed binary.
    hooks: Hooks<LD, GD>,
    /// Data local to a [`Worker`] that cannot be shared with other [`Worker`] instances.
    ldata: LD,
    /// Global data shared between all [`Worker`] instances.
    gdata: Arc<RwLock<GD>>,
    /// Global coverage data aggregating all workers coverage and allowing to decide if a testcase
    /// should be kept or not.
    global_coverage: GlobalCoverage,
    /// User-defined binary loader responsible for mapping the binary and initializing the
    /// fuzzer's state (registers, heap, stack, etc.).
    loader: L,
    /// Number of [`Worker`]s spawned by the fuzzer.
    nb_workers: u32,
    /// Global physical memory vma for the hypervisor.
    /// More information can be found in the documentation for [`PhysMemAllocator`].
    pma: PhysMemAllocator,
    /// The fuzzer's working directory.
    working_directory: PathBuf,
    /// The fuzzer's random generator.
    rand: Random,
    /// The corpus manager shared between all workers.
    corpus: Corpus,
    /// A copy of the initial configuration structure.
    config: Config<LD, GD>,
    /// The Apple hypervisor's virtual machine instance for the current process.
    _vm: av::VirtualMachine,
}

impl<
        L: 'static + Loader + Loader<LD = LD> + Loader<GD = GD>,
        LD: 'static + Clone + Send,
        GD: 'static + Clone + Send + Sync,
    > HyperPom<L, LD, GD>
{
    /// Creates a new instance of the fuzzer.
    pub fn new(config: ConfigData<LD, GD>, loader: L, ldata: LD, gdata: GD) -> Result<Self> {
        // Checks the number of fuzzing workers to spawn.
        let max = Self::max_worker_count()?;
        let config = if let ConfigData::Fuzzer(inner_config) = config {
            inner_config
        } else {
            return Err(CoreError::InvalidConfiguration)?;
        };
        if config.nb_workers > max {
            // Returns an error if the user tries to spawn more workers than authorized by the
            // hypervisor.
            return Err(CoreError::TooManyWorkers(max))?;
        }
        // Initializes the random number generator using the user-provided seed.
        let mut rand = Random::new(config.seed);
        // Creates the main corpus object.
        let mut corpus = Corpus::new(
            rand.split(),
            // We can unwrap here because we made sure that a fuzzer configuration was passed to
            // the function which can't have its corpus directory be None.
            config.corpus_directory.as_ref().unwrap(),
            // We can unwrap here because we made sure that a fuzzer configuration was passed to
            // the function which can't have its working directory be None.
            config.working_directory.as_ref().unwrap(),
            config.load_corpus_at_init,
        )?;
        // Loads the corpus from a user-provided directory
        corpus.load_from_dir(config.max_testcase_size)?;
        Ok(Self {
            hooks: Hooks::<LD, GD>::new(),
            ldata,
            gdata: Arc::new(RwLock::new(gdata)),
            global_coverage: GlobalCoverage::new(loader.coverage_ranges()?),
            loader,
            nb_workers: config.nb_workers,
            pma: PhysMemAllocator::new(config.as_size)?,
            // We can unwrap here because we made sure that a fuzzer configuration was passed to
            // the function which can't have its corpus directory be None.
            working_directory: config.working_directory.as_ref().unwrap().clone(),
            rand,
            corpus,
            config,
            _vm: av::VirtualMachine::new()?,
        })
    }

    /// Returns the maximum number of [`Worker`]s that can be instanciated for the fuzzer
    /// (i.e. the number of [`applevisor::Vcpu`] that can be created).
    pub fn max_worker_count() -> Result<u32> {
        Ok(av::Vcpu::get_max_count()?)
    }

    /// Starts the fuzzer.
    ///
    /// This function creates one thread per [`Worker`].
    /// Each [`Worker`] gets:
    ///
    ///  * a copy of the [`Config`];
    ///  * a copy of the [`Loader`];
    ///  * a copy of the [`Hooks`];
    ///  * a local data instance;
    ///  * a shared reference to the global data;
    ///  * a shared reference to the corpus;
    ///
    /// [`Worker`]s also get a reference to the global physical memory `pma`, so that each
    /// instance can set up its own virtual address space backed by a single [`PhysMemAllocator`].
    ///
    /// # Panic
    ///
    /// [`Worker`]s are expected to be resilient and responsible for handling their own errors. If
    /// an error cannot be handled, the thread should panic.
    pub fn fuzz(&mut self) -> Result<()> {
        // Creates the fuzzer working directory.
        fs::create_dir_all(&self.working_directory)?;
        // This channel is used by the worker threads to push `WorkerInfo` objects back to the
        // main thread. This object contains information about the number of testcases and crashes
        // created over a given time interval.
        let (msg_tx, msg_rx) = channel::<WorkerInfo>();
        // Barrier to make workers wait before the initial corpus has been loaded and the global
        // coverage info updated.
        let barrier = Arc::new(Barrier::new(self.nb_workers as usize));
        // Loop that creates the worker threads.
        // Worker handles contain information about a fuzzing thread (thread handle, latest thread
        // heartbeat to detect timeouts) and are identified by their VcpuInstance.
        let mut worker_handles = (0..self.nb_workers)
            .map(|i| {
                // Since the Vcpu is created inside the thread, this channel is used to
                // retrieve its corresponding VcpuInstance. Having access to the VcpuInstance
                // from the main thread is necessary to be able to stop a Vcpu from the main
                // thread when it times out.
                let (instance_tx, instance_rx) = sync_channel::<av::VcpuInstance>(0);
                // All the necessary information is cloned before being moved into the spawned
                // thread.
                let worker_name = format!("worker_{:02}", i);
                let pma = self.pma.clone();
                let loader = self.loader.clone();
                let ldata = self.ldata.clone();
                let gdata = self.gdata.clone();
                let hooks = self.hooks.clone();
                let corpus = self.corpus.clone();
                let global_coverage = self.global_coverage.clone();
                let tx = msg_tx.clone();
                let rand = self.rand.split();
                let working_directory = self.working_directory.join(&worker_name);
                let iterations = self.config.iterations;
                let config = self.config.clone();
                let barrier = Arc::clone(&barrier);
                // Spawns the worker thread.
                let handle = thread::Builder::new()
                    .name(worker_name)
                    .spawn(move || -> Result<()> {
                        // Creates a new fuzzing worker.
                        let mut worker = Worker::new(
                            av::Vcpu::new()?,
                            pma,
                            loader,
                            hooks,
                            ldata,
                            gdata,
                            global_coverage,
                            tx,
                            instance_tx,
                            rand,
                            corpus,
                            working_directory,
                            config,
                            barrier,
                        )?;
                        // Initializes the workers address space, its state, maps the binary and
                        // applies hooks.
                        worker.init()?;
                        // Starts the fuzzing process. The first worker is responsible for running
                        // the testcases in the corpus and initialize the global coverage paths.
                        worker.run(i == 0, iterations)?;
                        Ok(())
                    })
                    .expect("An error occured while spawning a worker thread");
                // Receives the VcpuInstance of the thread we've just created.
                let instance = instance_rx.recv().unwrap();
                let handle = WorkerHandle::new(handle);
                (instance, handle)
            })
            .collect::<HashMap<_, _>>();

        // Stats variables.
        let mut info = HyperPomInfo::new();
        let mut corpus_loaded = false;

        loop {
            // Iterates over the messages sent from the threads containing information about the
            // number of testcases and crashes that where generated over a given time interval.
            while let Some(wi) = msg_rx.try_iter().next() {
                if let Some(handle) = worker_handles.get_mut(&wi.instance) {
                    if !corpus_loaded {
                        corpus_loaded = true;
                        info.start_time = time::Instant::now();
                    }
                    handle.latest_ping = time::Instant::now();
                    info += wi;
                }
            }
            if corpus_loaded {
                // Displays the current fuzzers statistics.
                self.loader.display_info(&info);
            }
            // Iterates over thread handles to see if they timed out or if we need to join
            // terminated threads.
            worker_handles.retain(|instance, handle| {
                // If there is still an handle associated to this thread...
                if let Some(join_handle) = handle.join_handle.as_mut() {
                    // ... and the thread has finished running...
                    if join_handle.is_finished() {
                        // ... then join the thread.
                        if let Some(h) = handle.join_handle.take() {
                            h.join()
                                .expect("An error occured while joining threads")
                                .expect("thread panicked");
                        }
                        false
                    } else {
                        // ... otherwise check if it has timed out and stop the Vcpu if that's the
                        // case. The worker will resume execution from a sane point on its own.
                        if time::Instant::now() - handle.latest_ping > self.config.timeout {
                            av::Vcpu::stop(&[*instance]).expect("could not stop Vcpu");
                        }
                        true
                    }
                } else {
                    false
                }
            });
            // If no more threads are present in `worker_handles` then break out from the loop and
            // return from the function.
            if worker_handles.is_empty() {
                break;
            }
            // TODO: Maybe add a setting for this.
            thread::sleep(std::time::Duration::new(0, 1000));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------------------------
// Hyperpom - Worker
// -----------------------------------------------------------------------------------------------

/// Stores the thread handle associated to a worker as well as the latest time the worker gave a
/// sign of life.
pub struct WorkerHandle {
    /// Handle to the worker's underlying thread.
    join_handle: Option<thread::JoinHandle<Result<()>>>,
    /// Time when the thread last sent a message to the main thread. This is used to detect
    /// timeouts to reset the corresponding worker.
    latest_ping: time::Instant,
}

impl WorkerHandle {
    /// Creates a new worker handle object.
    fn new(handle: thread::JoinHandle<Result<()>>) -> Self {
        Self {
            join_handle: Some(handle),
            latest_ping: time::Instant::now(),
        }
    }
}

/// Stores information about the number of testcases, crashes and timeouts that occured during a
/// given time interval.
///
/// This object is sent from worker threads back to the main one through an [`std::sync::mpsc`]
/// channel and then aggregated to generate statistics about the current fuzzing campain.
#[derive(Debug)]
pub struct WorkerInfo {
    /// [`VcpuInstance`](crate::applevisor::VcpuInstance) of the associated thread.
    instance: av::VcpuInstance,
    /// The number of testcases.
    nb_testcases: u64,
    /// The number of crashes.
    nb_crashes: u64,
    /// The number of unique crashes.
    nb_uniq_crashes: u64,
    /// The number of timeouts.
    nb_timeouts: u64,
    /// The number of paths.
    nb_paths: u64,
}

impl WorkerInfo {
    /// Creates a new object containing information about a worker's results.
    fn new(instance: av::VcpuInstance) -> Self {
        Self {
            instance,
            nb_testcases: 0,
            nb_crashes: 0,
            nb_uniq_crashes: 0,
            nb_timeouts: 0,
            nb_paths: 0,
        }
    }
}

/// A fuzzing worker
///
/// # Role of Fuzzing Workers in the Fuzzer
///
/// Workers are core components of the fuzzing process and each of them operates in its own
/// dedicated thread. A worker primarily setup and manages fuzzing-related operations, but the
/// actual execution is handled by an [`Executor`] instance.
///
/// ```text
///
///                                     +--------------------+
///                                     |                    |
///                                     |      HYPERPOM      |
///                                     |                    |
///                                     +---------++---------+
///                                               ||
///                                               ||
///           +-----------------------+-----------++-----------+-----------------------+
///           |                       |                        |                       |
///           |                       |                        |                       |
///  +--------+--------+     +--------+--------+      +--------+--------+     +--------+--------+
///  |     WORKER      |     |     WORKER      |      |     WORKER      |     |     WORKER      |
///  |                 |     |                 |      |                 |     |                 |
///  | +-------------+ |     | +-------------+ |      | +-------------+ |     | +-------------+ |
///  | |             | |     | |             | |      | |             | |     | |             | |
///  | |  EXECUTOR   | |     | |  EXECUTOR   | |      | |  EXECUTOR   | |     | |  EXECUTOR   | |
///  | |             | |     | |             | |      | |             | |     | |             | |
///  | +-------------+ |     | +-------------+ |      | +-------------+ |     | +-------------+ |
///  +-----------------+     +-----------------+      +-----------------+     +-----------------+
/// ```
///
/// Before fuzzing actually starts, workers go through an initialization phase that performs the
/// following operations:
///
///  * creation of the worker's working directory;
///  * calling the [`Executor::init`] function (sets up the initial address space, registers,
///    etc.);
///  * loading the initial corpus.
///
/// Then, when [`Worker::run`] is called, the following operations are performed in a loop:
///
///  * restoring registers and the virtual address space using snapshots;
///  * resetting coverage and backtrace information;
///  * loading a testcase and mutates it;
///  * running the [`Loader::pre_exec`](crate::loader::Loader::pre_exec) hook;
///  * running the testcase using [`Executor::vcpu_run`];
///  * running the [`Loader::post_exec`](crate::loader::Loader::post_exec) hook;
///  * checking if a crash or a timeout occured;
///     * if a crash occured, rerun the testcase with the backtrace hooks enabled and check if the
///       crash is already known;
///     * if it's a new crash, store it;
///  * checking if new paths have been covered by the current testcase;
///     * if new paths have been covered, update the
///       [`GlobalCoverage`](crate::coverage::GlobalCoverage) object and add the testcase to the
///       corpus.
///
/// # Switching Between Coverage and Backtrace Hooks
///
/// Handling a hook is very expensive because of the context switch between the guest VM and the
/// hypervisor. The fewer number of hooks we have to handle, the better the performances will be.
///
/// Hyperpom implements different hook types, with each their own drawbacks that may or may not be
/// mitigable.
///
///  * Tracer hooks are not taken into account here, because we are not expecting tracing to be
///    enabled while fuzzing.
///  * Exit hooks stop the execution altogether, so it's essentially 0 cost.
///  * Custom hooks have to be executed everytime, there's not much we can do here.
///  * Coverage hooks is one of the most expensive hook type, because it is applied to branch and
///    comparison instructions on the whole binary. As explained in
///    [`GlobalCoverage`](crate::coverage::GlobalCoverage), to reduce the performance hit, these
///    hooks are removed as soon as the path is covered, making them effectively one-shot hooks
///    that won't impact subsequent iterations.
///
/// Which leaves us with backtrace hooks. These hooks are also expensive since they are placed on
/// function entries and exits. However, we don't need them for every iteration, we're only
/// interested in getting the backtrace when a crash occurs.
///
/// The solution implemented in this fuzzer is to use two separate address spaces. Both have the
/// same target binary loaded, the custom hooks applied, etc. But only one has the covrage hooks,
/// while the other has the backtrace hooks. During normal execution, the address space with
/// coverage hooks is used, but when a crash occurs, we switch to the one with the backtrace hooks.
/// We compute the backtrace and see if the crash is stable, before switch back to coverage hooks.
///
/// The obvious downside is how much memory we're using. Since we have two address spaces and their
/// corresponding snapshots, we're essentially mutliplying memory usage by four for a single
/// worker. However, we don't need to apply and remove hooks at every crash occurence, which can
/// become costly, especially for large binaries. Hopefully, binaries that require huge memory
/// allocations are uncommon enough that the chosen solution won't be a limitation.
#[allow(rustdoc::private_intra_doc_links)]
pub struct Worker<L: Loader, LD, GD> {
    /// The [`Executor`] instance for this worker.
    executor: Executor<L, LD, GD>,
    /// The [`applevisor::Vcpu`] instance for this worker.
    instance: av::VcpuInstance,
    /// [`std::sync::mpsc`] channel used to send statistics from the worker to [`HyperPom`].
    channel_tx: Sender<WorkerInfo>,
    /// A shared reference to the global corpus.
    corpus: Corpus,
    /// An instance of the mutation engine.
    mutator: Mutator,
    /// The working directory of the current worker.
    working_directory: PathBuf,
    /// An instance to the crash handling object.
    crash_handler: CrashHandler,
    /// A synchronization barrier used during the initialization of the fuzzer. It makes all
    /// workers wait for the worker responsible for loading the corpus.
    barrier: Arc<Barrier>,
}

impl<L: Loader + Loader<LD = LD> + Loader<GD = GD>, LD: Clone, GD: Clone> Worker<L, LD, GD> {
    /// Creates a new instance of a fuzzing worker.
    #[allow(clippy::too_many_arguments)]
    fn new(
        vcpu: av::Vcpu,
        pma: PhysMemAllocator,
        loader: L,
        hooks: Hooks<LD, GD>,
        ldata: LD,
        gdata: Arc<RwLock<GD>>,
        global_coverage: GlobalCoverage,
        channel_tx: Sender<WorkerInfo>,
        instance_tx: SyncSender<av::VcpuInstance>,
        mut rand: Random,
        corpus: Corpus,
        working_directory: PathBuf,
        config: Config<LD, GD>,
        barrier: Arc<Barrier>,
    ) -> Result<Self> {
        let instance = vcpu.get_instance();
        instance_tx.send(instance).unwrap();
        let crash_handler = CrashHandler::new(working_directory.join("crashes"), rand.split())?;
        let mutator = Mutator::new(rand.split());
        Ok(Self {
            executor: Executor::new_hyperpom(
                vcpu,
                pma,
                loader,
                hooks,
                ldata,
                gdata,
                global_coverage,
                config,
            )?,
            instance,
            channel_tx,
            corpus,
            mutator,
            working_directory,
            crash_handler,
            barrier,
        })
    }

    /// Initializes the worker thread by setting up its working directory, its registers and
    /// address space before taking snapshots.
    fn init(&mut self) -> Result<()> {
        // Creates the thread's working directory.
        fs::create_dir_all(&self.working_directory)?;
        // Initializes the executor.
        self.executor.init()?;
        Ok(())
    }

    /// Loads the initial testcases found in the user provided corpus directory as well as
    /// testcases from past runs if there are any.
    fn load_corpus(&mut self, wi: &mut WorkerInfo) -> Result<()> {
        println!("Loading corpus...");
        let inner = self.corpus.inner.read().unwrap();
        for (_, testcase) in inner.testcases.iter() {
            // If we have default testcases (i.e. empty testcases that were created as a starting
            // point for the mutation process), they won't have a path because they weren't loaded
            // from the disk. We can just skip them because they won't bring much in terms of
            // coverage.
            if testcase.path.is_none() {
                continue;
            }
            // We can unwrap here because we've checked that path is not None.
            println!("Loading: {}", &testcase.path.as_ref().unwrap().display());
            let _ = self.executor.run(Some(testcase))?;
            // Updates the global coverage.
            if let Some(new_paths) = self
                .executor
                .global_coverage
                .update_new_coverage(&self.executor.cdata)
            {
                wi.nb_paths += new_paths;
            }
            // Restores memory and registers.
            self.executor.restore_snapshot(SnapshotAction::Restore)?;
            // Resets coverage and backtrace information for the next iteration.
            self.executor.cdata.clear();
            self.executor.bdata.clear();
        }
        println!("Corpus loaded!");
        Ok(())
    }

    /// If a testcase caused a crash, rerun it a second time with backtrace hooks. If the resulting
    /// backtrace is not already known, the crash is stored. This function can also be used to
    /// verify if a crash is stable by running it `crash_verif_iterations` times and making sure
    /// the resulting backtrace is always the same.
    fn get_crash_backtrace(&mut self, crash: &Testcase) -> Result<Option<u64>> {
        self.executor
            .restore_snapshot(SnapshotAction::SwitchToBacktrace)?;
        // Switch to the address space where the backtrace hooks were applied.
        let mut saved_hash = None;
        for _ in 0..self.executor.config.crash_verif_iterations {
            // Resets coverage and backtrace information for the next iteration.
            self.executor.cdata.clear();
            self.executor.bdata.clear();
            // Restores memory and registers.
            self.executor.restore_snapshot(SnapshotAction::Restore)?;
            // Runs the testcase.
            match self.executor.run(Some(crash))? {
                ExitKind::Crash(_) => {
                    if let Some(hash) = saved_hash {
                        // If hashes differ from one execution to the next, the crash is unstable
                        // and can be ignored.
                        if Backtrace::get_crash_hash(&self.executor.bdata) != hash {
                            return Ok(None);
                        } else {
                            continue;
                        }
                    } else {
                        saved_hash = Some(Backtrace::get_crash_hash(&self.executor.bdata));
                        continue;
                    }
                }
                _ => return Ok(None),
            }
        }
        Ok(saved_hash)
    }

    /// Starts the fuzzing loop.
    #[allow(clippy::never_loop)]
    fn run(&mut self, init_corpus: bool, mut iterations: Option<u64>) -> Result<()> {
        let mut latest_ping = time::Instant::now();
        let mut worker_info = WorkerInfo::new(self.instance);
        let mut reset = false;
        let mut keep_testcase = false;
        // Corpus loading.
        if init_corpus {
            self.load_corpus(&mut worker_info)
                .expect("could not load corpus");
        }
        self.barrier.wait();
        // Cloning the loader for borrowing-related reasons, not optimal but it should not be too
        // much of an issue.
        let mut loader = self.executor.loader.clone();
        let mut testcase = self.corpus.get_testcase();
        let mut seed = self.mutator.mutate(
            &loader,
            testcase.get_data_mut(),
            self.executor.config.max_testcase_size,
            self.executor.config.max_nb_mutations,
        );
        let mut prev_cov = Coverage::new();
        loop {
            // If the number of paths in the global coverage is greater than the latest one we
            // saved, it means new paths have been added and we need to removes coverage hooks
            // for the new paths.
            if self.executor.config.remove_coverage_hooks_on_hit
                && prev_cov.count() < self.executor.global_coverage.count()
            {
                let inner = self.executor.global_coverage.inner.read().unwrap();
                // For each new paths in the global coverage, we remove the associated hook in the
                // virtual address space.
                for addr in inner.coverage.set.difference(&prev_cov.set) {
                    self.executor.hooks.revert_coverage_hooks(
                        *addr as u64,
                        &mut self.executor.vma.borrow_mut(),
                        &mut self.executor.vma.borrow_snapshot_mut(),
                    )?;
                }
                // Our reference coverage is updated with the current global values.
                prev_cov = self.executor.global_coverage.cloned();
            }
            'reset: loop {
                if reset {
                    // Restores the virtual address space and the registers using our snapshotted
                    // values.
                    self.executor.restore_snapshot(SnapshotAction::Restore)?;
                }
                if !keep_testcase {
                    // Resets backtrace information for the next iteration.
                    self.executor.bdata.clear();
                    // Gets a new testcase from the corpus and mutates it.
                    testcase = self.corpus.get_testcase();
                    seed = self.mutator.mutate(
                        &loader,
                        testcase.get_data_mut(),
                        self.executor.config.max_testcase_size,
                        self.executor.config.max_nb_mutations,
                    );
                }
                loop {
                    match loader.load_testcase(&mut self.executor, testcase.get_data())? {
                        // The next iteration will fetch a new testcase without resetting the
                        // fuzzer's state.
                        LoadTestcaseAction::New => {
                            keep_testcase = false;
                            reset = false;
                        }
                        // The next iteration will fetch a new testcase and reset the fuzzer's
                        // state.
                        LoadTestcaseAction::NewAndReset => {
                            keep_testcase = false;
                            reset = true;
                        }
                        // The next iteration will keep the current testcase without resetting the
                        // fuzzer's state.
                        LoadTestcaseAction::Keep => {
                            keep_testcase = true;
                            reset = false;
                        }
                        // The next iteration will keep the current testcase and reset the fuzzer's
                        // state.
                        LoadTestcaseAction::KeepAndReset => {
                            keep_testcase = true;
                            reset = true;
                        }
                        // The current testcase could not be loaded by the fuzzer, we fetch a new
                        // one and retry without resetting the fuzzer's state.
                        LoadTestcaseAction::Invalid => {
                            keep_testcase = false;
                            reset = false;
                            continue 'reset;
                        }
                        // The current testcase could not be loaded by the fuzzer, we fetch a new
                        // one and retry after resetting the fuzzer's state.
                        LoadTestcaseAction::InvalidAndReset => {
                            keep_testcase = false;
                            reset = true;
                            continue 'reset;
                        }
                    }
                    break;
                }
                break;
            }
            let exec_time_start = time::Instant::now();
            let ek = {
                // Executes our pre execution hook before we start fuzzing.
                let pre_exec_ret = loader.pre_exec(&mut self.executor)?;
                // Checks if the pre execution hook worked.
                if let ExitKind::Continue = pre_exec_ret {
                    // Sets the return address to an unmapped address in order to detect when the
                    // program returns. Not sure if it's a good idea to have the fuzzer do it
                    // instead of the user, but we'll see.
                    self.executor.vcpu.set_reg(av::Reg::LR, END_ADDR)?;
                    // Fuzzing time.
                    let exec_ret = match iterations.as_mut() {
                        Some(0) => break,
                        Some(x) => {
                            *x -= 1;
                            self.executor.vcpu_run()?
                        }
                        None => self.executor.vcpu_run()?,
                    };
                    // Runs our post-exec hook and returns the execution result.
                    loader.post_exec(&mut self.executor)?;
                    exec_ret
                } else {
                    pre_exec_ret
                }
            };
            let exec_time_end = time::Instant::now();
            // Updates the testcase execution time and coverage.
            testcase.exec_time = exec_time_end - exec_time_start;
            testcase.coverage = self.executor.cdata.clone();
            // Increases the number of testcases executed thus far.
            worker_info.nb_testcases += 1;
            // Tells the main thread that we're still alive and sends the current worker info as
            // well.
            if time::Instant::now() - latest_ping > time::Duration::new(1, 0) {
                latest_ping = time::Instant::now();
                let tmp_worker_info = worker_info;
                worker_info = WorkerInfo::new(self.executor.vcpu.get_instance());
                self.channel_tx.send(tmp_worker_info).unwrap();
            }
            // Checks if current iteration returned because of a timeout or a crash.
            match ek {
                ExitKind::Crash(title) => {
                    // Saves the current coverage data because checking the crash's stability
                    // will overwrite it.
                    let cdata = self.executor.cdata.clone();
                    let hash = self.get_crash_backtrace(&testcase)?;
                    if let Some(hash) = hash {
                        // Checks if the crash is already known.
                        let new_crash = self.executor.global_coverage.update_new_crashes(hash);
                        if new_crash && self.executor.config.save_crashes {
                            self.crash_handler.store_crash(
                                &loader,
                                &title,
                                &testcase,
                                &self.executor,
                                false,
                            )?;
                            worker_info.nb_uniq_crashes += 1;
                        }
                        worker_info.nb_crashes += 1;
                    }
                    // Performs a full memory restore with the snapshot that contains the
                    // coverage and tracing hooks.
                    self.executor
                        .restore_snapshot(SnapshotAction::SwitchToCoverage)?;
                    // Restores the executor's coverage data.
                    self.executor.cdata = cdata;
                    // Always resets after a crash.
                    reset = true;
                    keep_testcase = false;
                }
                ExitKind::Timeout => {
                    if self.executor.config.save_timeouts {
                        self.crash_handler.store_crash(
                            &loader,
                            "Timeout",
                            &testcase,
                            &self.executor,
                            true,
                        )?;
                    }
                    worker_info.nb_timeouts += 1;
                    // Always resets after a timeout.
                    reset = true;
                    keep_testcase = false;
                    // For timeouts, we skip the testcase addition to the corpus.
                    continue;
                }
                _ => {}
            }
            // Updates the global coverage map if our testcase is not empty and if we will request
            // a new testcase after this iteration.
            if !testcase.is_empty() && !keep_testcase {
                if let Some(new_paths) = self
                    .executor
                    .global_coverage
                    .update_new_coverage(&self.executor.cdata)
                {
                    // Sets the testcase seed.
                    let mut testcase = testcase.clone();
                    testcase.set_seed(seed);
                    // Adds the testcase to the corpus if it generated new paths.
                    self.corpus.add_testcase(testcase)?;
                    worker_info.nb_paths += new_paths;
                }
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------------------------
// Hyperpom - Executor
// -----------------------------------------------------------------------------------------------

/// Virtual address space snapshot types.
pub enum SnapshotAction {
    /// Restores the address space using the corresponding the snapshot.
    Restore,
    /// Switches the current address space to the one with coverage hooks.
    SwitchToCoverage,
    /// Switches the current address space to the one with backtrace hooks.
    SwitchToBacktrace,
}

/// The address space type currently in use.
pub enum VirtMemMode {
    /// Address space where coverage hooks are applied.
    Coverage,
    /// Address space where backtrace hooks are applied.
    Backtrace,
}

/// A wrapper structure for the *coverage* and *backtrace* address spaces. The current mode is
/// defined by the value stored in `mode` which is either [`VirtMemMode::Coverage`] or
/// [`VirtMemMode::Backtrace`].
pub struct VirtMem {
    /// The address space type currently in use by the fuzzer.
    pub mode: VirtMemMode,
    /// The address space where coverage hooks are applied.
    pub covtrace: RefCell<VirtMemAllocator>,
    /// Snapshot of the address space where coverage hooks are applied.
    pub covtrace_snapshot: RefCell<VirtMemAllocator>,
    /// The address space where backtrace hooks are applied.
    pub backtrace: RefCell<VirtMemAllocator>,
    /// Snapshot of the address space where backtrace hooks are applied.
    pub backtrace_snapshot: RefCell<VirtMemAllocator>,
}

impl VirtMem {
    /// Creates a new virtual memory wrapper structure.
    pub fn new(pma: PhysMemAllocator) -> Result<Self> {
        Ok(Self {
            mode: VirtMemMode::Coverage,
            covtrace: RefCell::new(VirtMemAllocator::new(pma.clone())?),
            covtrace_snapshot: RefCell::new(VirtMemAllocator::new(pma.clone())?),
            backtrace: RefCell::new(VirtMemAllocator::new(pma.clone())?),
            backtrace_snapshot: RefCell::new(VirtMemAllocator::new(pma)?),
        })
    }

    /// Borrows the address space in the current mode.
    pub fn borrow(&self) -> Ref<'_, VirtMemAllocator> {
        match self.mode {
            VirtMemMode::Coverage => self.covtrace.borrow(),
            VirtMemMode::Backtrace => self.backtrace.borrow(),
        }
    }

    /// Mutably borrows the address space in the current mode.
    pub fn borrow_mut(&self) -> RefMut<'_, VirtMemAllocator> {
        match self.mode {
            VirtMemMode::Coverage => self.covtrace.borrow_mut(),
            VirtMemMode::Backtrace => self.backtrace.borrow_mut(),
        }
    }

    /// Borrows the snapshot of the address space in the current mode.
    pub fn borrow_snapshot(&self) -> Ref<'_, VirtMemAllocator> {
        match self.mode {
            VirtMemMode::Coverage => self.covtrace_snapshot.borrow(),
            VirtMemMode::Backtrace => self.backtrace_snapshot.borrow(),
        }
    }

    /// Mutably borrows the snapshot of the address space in the current mode.
    pub fn borrow_snapshot_mut(&self) -> RefMut<'_, VirtMemAllocator> {
        match self.mode {
            VirtMemMode::Coverage => self.covtrace_snapshot.borrow_mut(),
            VirtMemMode::Backtrace => self.backtrace_snapshot.borrow_mut(),
        }
    }

    /// Wrapper for [`VirtMemAllocator::map`](crate::memory::VirtMemAllocator::map) borrowing the
    /// address space currently in use.
    pub fn map(&mut self, addr: u64, size: usize, perms: av::MemPerms) -> Result<()> {
        self.borrow_mut().map(addr, size, perms)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::map_privileged`](crate::memory::VirtMemAllocator::map_privileged)
    /// borrowing the address space currently in use.
    pub fn map_privileged(&mut self, addr: u64, size: usize, perms: av::MemPerms) -> Result<()> {
        self.borrow_mut().map_privileged(addr, size, perms)
    }

    /// Wrapper for [`VirtMemAllocator::unmap`](crate::memory::VirtMemAllocator::unmap) borrowing
    /// the address space currently in use.
    pub fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        self.borrow_mut().unmap(addr, size)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::restore_from_snapshot`](crate::memory::VirtMemAllocator::restore_from_snapshot)
    /// borrowing the address space currently in use.
    pub fn restore_from_snapshot(&mut self, snapshot: &VirtMemAllocator) -> Result<()> {
        self.borrow_mut().restore_from_snapshot(snapshot)
    }

    /// Wrapper for [`VirtMemAllocator::read`](crate::memory::VirtMemAllocator::read) borrowing
    /// the address space currently in use.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        self.borrow().read(addr, buf)
    }

    /// Wrapper for [`VirtMemAllocator::read_byte`](crate::memory::VirtMemAllocator::read_byte)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn read_byte(&self, addr: u64) -> Result<u8> {
        self.borrow().read_byte(addr)
    }

    /// Wrapper for [`VirtMemAllocator::read_word`](crate::memory::VirtMemAllocator::read_word)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn read_word(&self, addr: u64) -> Result<u16> {
        self.borrow().read_word(addr)
    }

    /// Wrapper for [`VirtMemAllocator::read_dword`](crate::memory::VirtMemAllocator::read_dword)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn read_dword(&self, addr: u64) -> Result<u32> {
        self.borrow().read_dword(addr)
    }

    /// Wrapper for [`VirtMemAllocator::read_qword`](crate::memory::VirtMemAllocator::read_qword)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn read_qword(&self, addr: u64) -> Result<u64> {
        self.borrow().read_qword(addr)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::read_cstring`](crate::memory::VirtMemAllocator::read_cstring) borrowing
    /// the address space currently in use.
    #[inline]
    pub fn read_cstring(&self, addr: u64) -> Result<String> {
        self.borrow().read_cstring(addr)
    }

    /// Wrapper for [`VirtMemAllocator::write`](crate::memory::VirtMemAllocator::write) borrowing
    /// the address space currently in use.
    #[inline]
    pub fn write(&mut self, addr: u64, buf: &[u8]) -> Result<usize> {
        self.borrow_mut().write(addr, buf)
    }

    /// Wrapper for [`VirtMemAllocator::write_byte`](crate::memory::VirtMemAllocator::write_byte)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_byte(&mut self, addr: u64, data: u8) -> Result<usize> {
        self.borrow_mut().write_byte(addr, data)
    }

    /// Wrapper for [`VirtMemAllocator::write_word`](crate::memory::VirtMemAllocator::write_word)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_word(&mut self, addr: u64, data: u16) -> Result<usize> {
        self.borrow_mut().write_word(addr, data)
    }

    /// Wrapper for [`VirtMemAllocator::write_dword`](crate::memory::VirtMemAllocator::write_dword)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_dword(&mut self, addr: u64, data: u32) -> Result<usize> {
        self.borrow_mut().write_dword(addr, data)
    }

    /// Wrapper for [`VirtMemAllocator::write_qword`](crate::memory::VirtMemAllocator::write_qword)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_qword(&mut self, addr: u64, data: u64) -> Result<usize> {
        self.borrow_mut().write_qword(addr, data)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::write_cstring`](crate::memory::VirtMemAllocator::write_cstring)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_cstring(&mut self, addr: u64, s: &str) -> Result<usize> {
        self.borrow_mut().write_cstring(addr, s)
    }

    /// Wrapper for [`VirtMemAllocator::write_dirty`](crate::memory::VirtMemAllocator::write_dirty)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_dirty(&mut self, addr: u64, buf: &[u8]) -> Result<usize> {
        self.borrow_mut().write_dirty(addr, buf)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::write_byte_dirty`](crate::memory::VirtMemAllocator::write_byte_dirty)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_byte_dirty(&mut self, addr: u64, data: u8) -> Result<usize> {
        self.borrow_mut().write_byte_dirty(addr, data)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::write_word_dirty`](crate::memory::VirtMemAllocator::write_word_dirty)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_word_dirty(&mut self, addr: u64, data: u16) -> Result<usize> {
        self.borrow_mut().write_word_dirty(addr, data)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::write_dword_dirty`](crate::memory::VirtMemAllocator::write_dword_dirty)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_dword_dirty(&mut self, addr: u64, data: u32) -> Result<usize> {
        self.borrow_mut().write_dword_dirty(addr, data)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::write_qword_dirty`](crate::memory::VirtMemAllocator::write_qword_dirty)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_qword_dirty(&mut self, addr: u64, data: u64) -> Result<usize> {
        self.borrow_mut().write_qword_dirty(addr, data)
    }

    /// Wrapper for
    /// [`VirtMemAllocator::write_cstring_dirty`](crate::memory::VirtMemAllocator::write_cstring_dirty)
    /// borrowing the address space currently in use.
    #[inline]
    pub fn write_cstring_dirty(&mut self, addr: u64, s: &str) -> Result<usize> {
        self.borrow_mut().write_cstring_dirty(addr, s)
    }
}

/// Component handling everything related to executing code by the hypervisor.
///
/// # Role of the Executor in the Fuzzer
///
/// The [`Executor`] is the component that interacts directly with the hypervisor to make it
/// execute our code. It can allocate memory, place hooks, gather coverage or backtrace
/// information, etc.
///
/// While this component is used primarily by the fuzzer, it can be instanciated independently.
/// This is especially useful when harnessing or tracing the target, because it gives us complete
/// control over the program during its lifetime.
///
/// Different types of hooks can be placed by the executor using the following methods:
///
///  * [`Executor::add_function_hook`]
///  * [`Executor::add_instruction_hook`]
///  * [`Executor::add_custom_hook`]
///  * [`Executor::add_exit_hook`]
///
/// **Note:** for more information about hooking mechanisms in general, you can refer to
///           [`crate::hooks::Hooks`].
///
/// **Warning:** when using an executor you must first instanciate one (and only one per process)
///              [`VirtualMachine`](crate::applevisor::VirtualMachine) object, otherwise it will
///              return an error.
///
/// # Example
///
/// ```
/// use hyperpom::applevisor as av;
/// use hyperpom::config::Config;
/// use hyperpom::core::HyperPom;
/// use hyperpom::loader::Loader;
///
/// #[derive(Clone)]
/// pub struct GlobalData(u32);
///
/// #[derive(Clone)]
/// pub struct LocalData(u32);
///
/// #[derive(Clone)]
/// pub struct DummyLoader;
///
/// impl Loader for DummyLoader {
///     // [...]
/// }
///
/// // The first step is to instanciate the virtual machine object.
/// let _vm = av::VirtualMachine::new();
///
/// // We instanciate a global data object.
/// let gdata = GlobalData(0);
/// // We instanciate a local data object.
/// let ldata = LocalData(0);
///
/// // `loader` contains the methods that will load and map the program from the file `binary`.
/// let loader = DummyLoader::new("./binary");
///
/// // We create a configuration for the fuzzer.
/// let config = Config::builder(0x10000000, "/tmp/hyperpom/", "/tmp/corpus/")
///     .seed(0xdeadbeef)
///     .timeout(std::time::Duration::new(60, 0))
///     .iterations(Some(1))
///     .build();
///
/// // Creates an instance of the fuzzer.
/// let mut executor =
///     hp::core::Executor::<DummyLoader, LocalData, GlobalData>::new(config, loader, ldata, gdata)
///         .expect("could not create the executor");
///
/// // Initializes the executor.
/// executor.init()?;
///
/// // Runs the target without a testcase.
/// executor.run(None).expect("execution failed");
///
/// // Prints the number of paths covered
/// println!("{} paths covered", executor.cdata.set.len());
/// ```
pub struct Executor<L: Loader, LD, GD> {
    /// The underlying [`applevisor::Vcpu`] instance.
    pub vcpu: av::Vcpu,
    /// A shared reference to the global physical memory allocator.
    pub pma: Option<PhysMemAllocator>,
    /// The virtual address spaces and their snapshots.
    pub vma: VirtMem,
    /// The loader instance passed by the user.
    pub loader: L,
    /// HACK: a copy of the loader to call trait methods while passing the Executor object's to
    /// them without triggering any borrowing error.
    pub loader_copy: Option<L>,
    /// The hooks applied to the target.
    pub hooks: Hooks<LD, GD>,
    /// Data local to the fuzzer.
    pub ldata: LD,
    /// A shared reference to the global data.
    pub gdata: Arc<RwLock<GD>>,
    /// Coverage data for the current iteration.
    pub cdata: Coverage,
    /// Backtrace data for the current iteration.
    pub bdata: Backtrace,
    /// A shared reference to the global coverage data.
    pub global_coverage: GlobalCoverage,
    /// A copy of the configuration passed by the user.
    pub config: Config<LD, GD>,
    /// The list of symbols for the target.
    pub symbols: Symbols,
    /// General purpose registers snapshot.
    pub registers_snapshot: Vec<u64>,
    /// System registers snapshot.
    pub sys_registers_snapshot: Vec<u64>,
    /// Floating point registers snapshot.
    pub fp_registers_snapshot: Vec<simd::i8x16>,
}

impl<L: Loader + Loader<LD = LD> + Loader<GD = GD>, LD: Clone, GD: Clone> Executor<L, LD, GD> {
    /// Creates a new executor instance that can be run outside of Hyperpom.
    pub fn new(config: ConfigData<LD, GD>, loader: L, ldata: LD, gdata: GD) -> Result<Self> {
        let config = if let ConfigData::Executor(inner_config) = config {
            inner_config
        } else {
            return Err(CoreError::InvalidConfiguration)?;
        };
        let pma = PhysMemAllocator::new(config.as_size)?;
        let symbols = loader.symbols()?;
        let coverage_ranges = loader.coverage_ranges()?;
        Ok(Self {
            vcpu: av::Vcpu::new()?,
            pma: Some(pma.clone()),
            vma: VirtMem::new(pma)?,
            loader,
            loader_copy: None,
            hooks: Hooks::<LD, GD>::new(),
            ldata,
            gdata: Arc::new(RwLock::new(gdata)),
            cdata: Coverage::new(),
            bdata: Backtrace::new(),
            global_coverage: GlobalCoverage::new(coverage_ranges),
            config,
            symbols,
            registers_snapshot: vec![],
            sys_registers_snapshot: vec![],
            fp_registers_snapshot: vec![],
        })
    }

    /// Creates a new executor instance to be specifically part of an Hyperpom instance.
    #[allow(clippy::too_many_arguments)]
    fn new_hyperpom(
        vcpu: av::Vcpu,
        pma: PhysMemAllocator,
        loader: L,
        hooks: Hooks<LD, GD>,
        ldata: LD,
        gdata: Arc<RwLock<GD>>,
        global_coverage: GlobalCoverage,
        config: Config<LD, GD>,
    ) -> Result<Self> {
        let symbols = loader.symbols()?;
        Ok(Self {
            vcpu,
            pma: None,
            vma: VirtMem::new(pma)?,
            loader,
            loader_copy: None,
            hooks,
            ldata,
            gdata,
            cdata: Coverage::new(),
            bdata: Backtrace::new(),
            global_coverage,
            config,
            symbols,
            registers_snapshot: vec![],
            sys_registers_snapshot: vec![],
            fp_registers_snapshot: vec![],
        })
    }

    /// The executor initialization function. This function must be called before running the
    /// executor since it is responsible for:
    ///
    ///  * calling [`Loader::map`](crate::loader::Loader::map);
    ///  * applying hooks;
    ///  * initializing the cache maintenance handlers;
    ///  * taking snapshots.
    pub fn init(&mut self) -> Result<()> {
        // HACK: Clones the loader because we need a mutable reference to the loader as well as the
        // Worker. There might be a cleaner way to do this, but this will do for now.
        let mut loader = self.loader.clone();
        // Loads the binary in the Vcpu address space using the user-defined `load` function.
        loader.map(self)?;
        // Initializes the virtual address space (sets the page table registers, the exception
        // vector, etc.)
        self.vma.covtrace.borrow_mut().init(&mut self.vcpu, true)?;
        // Adds the user-defined hooks from the loader.
        loader.hooks(self)?;
        // Writes hooks in the virtual address space.
        self.hooks.apply(&mut self.vma.covtrace.borrow_mut())?;
        // Intializes the cache maintenance handler.
        Caches::init(&mut self.vcpu, &mut self.vma.covtrace.borrow_mut())?;
        // Sets registers and calls arbitrary function in the target program to initialize
        // the memory and execution states of the worker. It peforms the final modifications
        // and initializations before snapshotting occurs and the state is used as a model for
        // all fuzzing iterations.
        loader.pre_snapshot(self)?;
        self.loader = loader.clone();
        self.loader_copy = Some(loader);
        // Sets the return address to an unmapped address in order to detect when the program
        // returns.
        self.vcpu.set_reg(av::Reg::LR, END_ADDR)?;
        // Once everything is initialized, takes two snapshots of the virtual address space:
        //  - `vma_snapshot` is used after each testcase execution to reset the virtual address
        //    space to the initial state (coverage/trace hooks are applied on this address space);
        //  - `vma_backtrace` other is used when checking if a crash is new and deterministic
        //    (backtrace hooks are applied on this address space).
        // The snapshots are separated because of the hooks applied on them: we don't need
        // backtrace information when fuzzing and we don't need coverage/tracing information when
        // verifying a crash.
        // TODO: this implementation takes up a lot of memory, and it might be better to just
        // remove and reapply coverage/backtrace hooks when necessary.
        // Should be investigated later.
        *self.vma.backtrace.borrow_mut() = self.vma.covtrace.borrow().clone();
        // Clones the current hooks into another object to separate hooks applied to `vma_snapshot`
        // and `vma_backtrace`.
        let mut hooks_backtrace = self.hooks.clone();
        // Adds tracing hooks if tracing is enabled.
        if self.config.tracer {
            Tracer::add_hooks(
                self.loader.trace_ranges()?,
                self.config.tracer_hook,
                &mut self.hooks,
            )?;
        }
        // Adds coverage hooks if coverage is enabled.
        if self.config.coverage {
            self.global_coverage.add_hooks(
                &self.vma.covtrace.borrow_mut(),
                &mut self.hooks,
                self.config.comparison_unrolling,
            )?;
        }
        // Writes coverage and tracing hooks in the regular virtual address space and its snapshot.
        self.hooks.apply(&mut self.vma.covtrace.borrow_mut())?;
        *self.vma.covtrace_snapshot.borrow_mut() = self.vma.covtrace.borrow().clone();
        // Adds backtrace hooks to both hooks objects, because `hooks_backtrace` will be discarded
        // at the end of the function and we need to have the hooks registered in the main object
        // so they can be known by the fuzzer and handled properly.
        Backtrace::add_hooks(
            self.loader.coverage_ranges()?,
            &self.vma.backtrace.borrow(),
            &mut hooks_backtrace,
        )?;
        Backtrace::add_hooks(
            self.loader.coverage_ranges()?,
            &self.vma.backtrace.borrow(),
            &mut self.hooks,
        )?;
        // However we only apply the hooks in `hooks_backtrace` to the virtual address space
        // dedicated to crash dedups and backtrace recording.
        hooks_backtrace.apply(&mut self.vma.backtrace.borrow_mut())?;
        *self.vma.backtrace_snapshot.borrow_mut() = self.vma.backtrace.borrow().clone();
        self.hooks
            .fill_instructions(&mut self.vma.covtrace.borrow_mut())?;
        // Once everything is initialized, takes a snapshot of the registers.
        // It will be used after each testcase execution to reset the virtual address space to
        // the initial state.
        self.save_registers()?;
        self.save_sys_registers()?;
        self.save_fp_registers()?;
        Ok(())
    }

    /// Adds a user-defined hook at `addr`.
    ///
    /// See [`Hooks`] for more information about hooking in general.
    pub fn add_custom_hook(&mut self, addr: u64, hook: HookFn<LD, GD>) {
        self.hooks.add_custom_hook(addr, hook);
    }

    /// Adds a user-defined hook on the function named `name`.
    ///
    /// See [`Hooks`] for more information about hooking in general.
    pub fn add_function_hook(&mut self, name: &str, hook: HookFn<LD, GD>) -> Result<()> {
        let symbol = self
            .symbols
            .symbols
            .iter()
            .find(|(_, s)| s.name == name)
            .map(|(_, s)| s)
            .ok_or_else(|| Error::Loader(LoaderError::UnknownSymbol(name.to_string())))?;
        self.hooks.add_custom_hook(symbol.addr, hook);
        Ok(())
    }

    /// Adds a user-defined hook on all the instructions that match `pattern`.
    ///
    /// See [`Hooks`] for more information about hooking in general.
    pub fn add_instruction_hook(&mut self, pattern: &str, hook: HookFn<LD, GD>) -> Result<()> {
        let re = re::Regex::new(pattern).unwrap();
        // Iterates over the code ranges.
        for CodeRange(range) in self.loader.code_ranges()? {
            // In a given range, iterates over each instruction address.
            for addr in range.clone().step_by(4) {
                // Reads the instruction at the current address.
                let mut code = [0; 4];
                self.vma.borrow().read(addr, &mut code)?;
                CSE.with(|cs| {
                    let insns = cs
                        .disasm_count(&code, addr, 1)
                        .expect("could not disassemble while adding coverage hooks");
                    if let Some(insn) = insns.as_ref().first() {
                        if re.is_match(&format!(
                            "{} {}",
                            insn.mnemonic().unwrap(),
                            insn.op_str().unwrap()
                        )) {
                            self.hooks.add_custom_hook(addr, hook);
                        }
                    }
                });
            }
        }
        Ok(())
    }

    /// Removes a user-defined hook at `addr`.
    ///
    /// See [`Hooks`] for more information about hooking in general.
    pub fn remove_custom_hook(&mut self, addr: u64) {
        self.hooks.remove_custom_hook(addr);
    }

    /// Adds an exit hook at `addr`.
    ///
    /// See [`Hooks`] for more information about hooking in general.
    pub fn add_exit_hook(&mut self, addr: u64) {
        self.hooks.add_exit_hook(addr);
    }

    /// Removes an exit hook at `addr`.
    ///
    /// See [`Hooks`] for more information about hooking in general.
    pub fn remove_exit_hook(&mut self, addr: u64) {
        self.hooks.remove_exit_hook(addr);
    }

    /// Function that starts the Vcpu and handles any exception that occurs.
    #[inline]
    pub fn vcpu_run(&mut self) -> Result<ExitKind> {
        loop {
            self.vcpu.run()?;
            let exit_info = self.vcpu.get_exit_info();
            let exit = match exit_info.reason {
                av::ExitReason::CANCELED => ExitKind::Timeout,
                av::ExitReason::EXCEPTION => Exceptions::handle::<L, LD, GD>(self)?,
                av::ExitReason::VTIMER_ACTIVATED => unimplemented!(),
                av::ExitReason::UNKNOWN => panic!(
                    "Vcpu exited unexpectedly at address {:#x}",
                    self.vcpu.get_reg(av::Reg::PC)?
                ),
            };
            match exit {
                ExitKind::Continue => continue,
                _ => break Ok(exit),
            }
        }
    }

    /// Loads a testcase in memory before running it.
    #[inline]
    pub fn run(&mut self, testcase: Option<&Testcase>) -> Result<ExitKind> {
        let mut reset = false;
        let mut keep_testcase = false;
        // We can unwrap here because init should have been called prior to calling this function
        // and a copy of the loader should have been made.
        let mut loader = self.loader_copy.take().unwrap();
        // Resets the executor's state.
        loader.reset_state(self)?;
        loop {
            if let Some(testcase) = testcase {
                match loader.load_testcase(self, testcase.get_data())? {
                    // If the testcase provided is invalid, we return an error because there's
                    // not much that we can do.
                    LoadTestcaseAction::Invalid | LoadTestcaseAction::InvalidAndReset => {
                        self.loader_copy = Some(loader);
                        return Err(CoreError::InvalidTestcase)?;
                    }
                    // If we want to keep the testcase.
                    LoadTestcaseAction::Keep => {
                        keep_testcase = true;
                        reset = false;
                    }
                    // If we want to keep the testcase and reset the fuzzer's state.
                    LoadTestcaseAction::KeepAndReset => {
                        keep_testcase = true;
                        reset = true;
                    }
                    _ => {}
                }
            }
            let ek = self.run_inner(&mut loader)?;
            match ek {
                // If a crash or a timeout occured, we propagate the info.
                ExitKind::Crash(_) | ExitKind::Timeout => {
                    self.loader_copy = Some(loader);
                    return Ok(ek);
                }
                // Otherwise, we check if we want to do another iteration with the same testcase,
                // and if we need to reset its state.
                _ => {
                    if keep_testcase {
                        if reset {
                            self.restore_snapshot(SnapshotAction::Restore)?;
                        }
                        continue;
                    }
                    self.loader_copy = Some(loader);
                    return Ok(ek);
                }
            }
        }
    }

    /// Inner execution method that runs the pre-execution hook, the actual execution and then the
    /// post-execution hook.
    #[inline]
    fn run_inner(&mut self, loader: &mut L) -> Result<ExitKind> {
        // Executes our pre execution hook before we start fuzzing.
        let pre_exec_ret = loader.pre_exec(self)?;
        // Checks if the pre execution hook worked.
        if let ExitKind::Continue = pre_exec_ret {
            // Sets the return address to an unmapped address in order to detect when the
            // program returns. Not sure if it's a good idea to have the fuzzer do it
            // instead of the user, but we'll see.
            self.vcpu.set_reg(av::Reg::LR, END_ADDR)?;
            // Executes the testcase.
            let exec_ret = self.vcpu_run()?;
            // Runs our post-exec hook and returns the execution result.
            loader.post_exec(self)?;
            Ok(exec_ret)
        } else {
            Ok(pre_exec_ret)
        }
    }

    /// Restores the current address space from a snapshot or switch to another address space
    /// depending on the action specified by `snapshot_action`. Also restores the registers and
    /// flush the TLB as well as the instruction caches.
    #[inline]
    pub fn restore_snapshot(&mut self, snapshot_action: SnapshotAction) -> Result<()> {
        // Switches or restores the virtual address space and invalidates the TLB.
        // TODO: For the moment `tlbi_vmalle1_ic_ialluis` needs to be called before restoring the
        //       registers, because it crashes once it hits the eret and tries to return to
        //       END_ADDR. The state is then stuck in EL1, which is not ideal. Restoring the
        //       registers after takes care of going back to EL1, but maybe it should be a bit
        //       cleaner.
        self.vcpu.set_reg(av::Reg::LR, END_ADDR)?;
        self.vcpu.set_reg(av::Reg::PC, END_ADDR)?;
        match snapshot_action {
            SnapshotAction::Restore => {
                let mut vma = self.vma.borrow_mut();
                let vma_snapshot = self.vma.borrow_snapshot();
                vma.restore_from_snapshot(&vma_snapshot)?;
                vma.set_trans_table_base_registers(&self.vcpu)?;
                Caches::tlbi_vmalle1_ic_ialluis(&mut self.vcpu, &mut vma)?;
            }
            SnapshotAction::SwitchToCoverage => {
                self.vma.mode = VirtMemMode::Coverage;
                let mut vma = self.vma.borrow_mut();
                vma.set_trans_table_base_registers(&self.vcpu)?;
                Caches::tlbi_vmalle1_ic_ialluis(&mut self.vcpu, &mut vma)?;
            }
            SnapshotAction::SwitchToBacktrace => {
                self.vma.mode = VirtMemMode::Backtrace;
                let mut vma = self.vma.borrow_mut();
                vma.set_trans_table_base_registers(&self.vcpu)?;
                Caches::tlbi_vmalle1_ic_ialluis(&mut self.vcpu, &mut vma)?;
            }
        }
        // Cleans the TLB and the instruction caches.
        self.vcpu_run()?;
        // Restores registers
        self.restore_registers()?;
        self.restore_sys_registers()?;
        self.restore_fp_registers()?;
        // Restores the TTBR*_EL1 system registers if we are switching to or restoring from the
        // backtrace virtual address space, because they were overwritten while restoring sys
        // registers.
        let vma = self.vma.borrow();
        vma.set_trans_table_base_registers(&self.vcpu)?;
        Ok(())
    }

    /// Takes a snapshot of the general purpose registers.
    pub fn save_registers(&mut self) -> Result<()> {
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X0)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X1)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X2)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X3)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X4)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X5)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X6)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X7)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X8)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X9)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X10)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X11)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X12)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X13)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X14)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X15)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X16)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X17)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X18)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X19)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X20)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X21)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X22)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X23)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X24)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X25)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X26)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X27)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X28)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::X29)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::PC)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::FPCR)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::FPSR)?);
        self.registers_snapshot
            .push(self.vcpu.get_reg(av::Reg::CPSR)?);
        Ok(())
    }

    /// Restores the Vcpu general purpose registers from a snapshot.
    pub fn restore_registers(&self) -> Result<()> {
        let mut iter = self.registers_snapshot.iter();
        self.vcpu.set_reg(av::Reg::X0, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X1, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X2, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X3, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X4, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X5, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X6, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X7, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X8, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X9, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X10, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X11, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X12, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X13, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X14, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X15, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X16, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X17, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X18, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X19, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X20, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X21, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X22, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X23, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X24, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X25, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X26, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X27, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X28, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::X29, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::PC, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::FPCR, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::FPSR, *iter.next().unwrap())?;
        self.vcpu.set_reg(av::Reg::CPSR, *iter.next().unwrap())?;
        Ok(())
    }

    /// Takes a snapshot of the system registers.
    pub fn save_sys_registers(&mut self) -> Result<()> {
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR0_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR0_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR0_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR0_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR1_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR1_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR1_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR1_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR2_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR2_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR2_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR2_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR3_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR3_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR3_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR3_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR4_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR4_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR4_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR4_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR5_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR5_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR5_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR5_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR6_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR6_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR6_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR6_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR7_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR7_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR7_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR7_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR8_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR8_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR8_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR8_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR9_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR9_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR9_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR9_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR10_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR10_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR10_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR10_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR11_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR11_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR11_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR11_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR12_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR12_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR12_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR12_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR13_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR13_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR13_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR13_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR14_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR14_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR14_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR14_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBVR15_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGBCR15_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWVR15_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::DBGWCR15_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::MDCCINT_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::MDSCR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::MIDR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::MPIDR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::SCTLR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::CPACR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::TTBR0_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::TTBR1_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::TCR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APIAKEYLO_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APIAKEYHI_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APIBKEYLO_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APIBKEYHI_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APDAKEYLO_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APDAKEYHI_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APDBKEYLO_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APDBKEYHI_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APGAKEYLO_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::APGAKEYHI_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::SPSR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::SP_EL0)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::AFSR0_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::AFSR1_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::ESR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::FAR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::PAR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::MAIR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::AMAIR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::VBAR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::CONTEXTIDR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::TPIDR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::CNTKCTL_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::CSSELR_EL1)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::TPIDR_EL0)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::TPIDRRO_EL0)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::CNTV_CTL_EL0)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::CNTV_CVAL_EL0)?);
        self.sys_registers_snapshot
            .push(self.vcpu.get_sys_reg(av::SysReg::SP_EL1)?);
        Ok(())
    }

    /// Restores the Vcpu system registers from a snapshot.
    pub fn restore_sys_registers(&self) -> Result<()> {
        let mut iter = self.sys_registers_snapshot.iter();
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR0_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR0_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR0_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR0_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR1_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR1_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR1_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR1_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR2_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR2_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR2_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR2_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR3_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR3_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR3_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR3_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR4_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR4_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR4_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR4_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR5_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR5_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR5_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR5_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR6_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR6_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR6_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR6_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR7_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR7_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR7_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR7_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR8_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR8_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR8_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR8_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR9_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR9_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR9_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR9_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR10_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR10_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR10_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR10_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR11_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR11_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR11_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR11_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR12_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR12_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR12_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR12_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR13_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR13_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR13_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR13_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR14_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR14_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR14_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR14_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBVR15_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGBCR15_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWVR15_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::DBGWCR15_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::MDCCINT_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::MDSCR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::MIDR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::MPIDR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::SCTLR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::CPACR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::TTBR0_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::TTBR1_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::TCR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APIAKEYLO_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APIAKEYHI_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APIBKEYLO_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APIBKEYHI_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APDAKEYLO_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APDAKEYHI_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APDBKEYLO_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APDBKEYHI_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APGAKEYLO_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::APGAKEYHI_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::SPSR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::ELR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::SP_EL0, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::AFSR0_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::AFSR1_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::ESR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::FAR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::PAR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::MAIR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::AMAIR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::VBAR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::CONTEXTIDR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::TPIDR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::CNTKCTL_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::CSSELR_EL1, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::TPIDR_EL0, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::TPIDRRO_EL0, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::CNTV_CTL_EL0, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::CNTV_CVAL_EL0, *iter.next().unwrap())?;
        self.vcpu
            .set_sys_reg(av::SysReg::SP_EL1, *iter.next().unwrap())?;
        Ok(())
    }

    /// Takes a snapshot of the floating point registers.
    pub fn save_fp_registers(&mut self) -> Result<()> {
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q0)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q1)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q2)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q3)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q4)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q5)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q6)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q7)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q8)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q9)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q10)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q11)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q12)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q13)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q14)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q15)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q16)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q17)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q18)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q19)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q20)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q21)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q22)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q23)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q24)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q25)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q26)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q27)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q28)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q29)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q30)?);
        self.fp_registers_snapshot
            .push(self.vcpu.get_simd_fp_reg(av::SimdFpReg::Q31)?);
        Ok(())
    }

    /// Restores the Vcpu floating point registers from a snapshot.
    pub fn restore_fp_registers(&self) -> Result<()> {
        let mut iter = self.fp_registers_snapshot.iter();
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q0, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q1, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q2, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q3, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q4, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q5, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q6, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q7, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q8, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q9, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q10, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q11, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q12, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q13, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q14, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q15, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q16, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q17, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q18, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q19, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q20, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q21, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q22, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q23, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q24, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q25, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q26, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q27, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q28, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q29, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q30, *iter.next().unwrap())?;
        self.vcpu
            .set_simd_fp_reg(av::SimdFpReg::Q31, *iter.next().unwrap())?;
        Ok(())
    }
}

/// Counts the number of arguments passed to a macro.
#[macro_export]
macro_rules! args_count {
    () => {0};
    ($head:expr, $($tail:expr,)*) => {1 + args_count!($($tail,)*)};
}

/// Calls an arbitrary function using its symbol name.
#[macro_export]
macro_rules! call_func {
    ($exec:expr, $name:tt) => {{
        let symbol = $exec
        .symbols
        .symbols
        .iter()
        .find(|(_, s)| &s.name == $name)
        .map(|(_, s)| s)
        .ok_or(Error::Loader(LoaderError::UnknownSymbol($name.to_string())))?;
        call_func_by_addr! { $exec, symbol.addr }
    }};
    ($exec:expr, $name:tt, $($x:expr),*) => {{
        let saved_sp = $exec.vcpu.get_sys_reg($crate::applevisor::SysReg::SP_EL0)?;
        let mut index = 0;
        let count = args_count!($($x,)*);
        let mut sp = if count > 8 {
            let sp_size = (count - 8) * 8;
            $exec.vcpu.set_sys_reg($crate::applevisor::SysReg::SP_EL0, saved_sp + sp_size)?;
            saved_sp + sp_size
        } else {
            0
        };
        $(
            match index {
                0 => $exec.vcpu.set_reg($crate::applevisor::Reg::X0, $x)?,
                1 => $exec.vcpu.set_reg($crate::applevisor::Reg::X1, $x)?,
                2 => $exec.vcpu.set_reg($crate::applevisor::Reg::X2, $x)?,
                3 => $exec.vcpu.set_reg($crate::applevisor::Reg::X3, $x)?,
                4 => $exec.vcpu.set_reg($crate::applevisor::Reg::X4, $x)?,
                5 => $exec.vcpu.set_reg($crate::applevisor::Reg::X5, $x)?,
                6 => $exec.vcpu.set_reg($crate::applevisor::Reg::X6, $x)?,
                7 => $exec.vcpu.set_reg($crate::applevisor::Reg::X7, $x)?,
                _ => {
                    $exec.vcpu.set_sys_reg($crate::applevisor::SysReg::SP_EL0, sp)?;
                    $exec.vma.borrow_mut().write_qword(sp, $x)?;
                    sp += 8;
                },
            }
            index += 1;
        )*
        call_func! { $exec, $name }
    }};
}

/// Calls an arbitrary function using its address.
#[macro_export]
macro_rules! call_func_by_addr {
    ($exec:expr, $addr:expr) => {{
        let saved_psr = $exec.vcpu.get_reg($crate::applevisor::Reg::CPSR)?;
        let saved_pc = $exec.vcpu.get_reg($crate::applevisor::Reg::PC)?;
        let saved_lr = $exec.vcpu.get_reg($crate::applevisor::Reg::LR)?;
        $exec.vcpu.set_reg($crate::applevisor::Reg::LR, $crate::exceptions::END_ADDR)?;
        $exec.vcpu.set_reg($crate::applevisor::Reg::PC, $addr)?;
        let ret = $exec.vcpu_run()?;
        $exec.vcpu.set_reg($crate::applevisor::Reg::LR, saved_lr)?;
        $exec.vcpu.set_reg($crate::applevisor::Reg::PC, saved_pc)?;
        $exec.vcpu.set_reg($crate::applevisor::Reg::CPSR, saved_psr)?;
        Ok::<(u64, $crate::crash::ExitKind), Error>(($exec.vcpu.get_reg($crate::applevisor::Reg::X0)?, ret))
    }};
    ($exec:expr, $addr:expr, $($x:expr),*) => {{
        let saved_sp = $exec.vcpu.get_sys_reg($crate::applevisor::SysReg::SP_EL0)?;
        let mut index = 0;
        let count = args_count!($($x,)*);
        let mut sp = if count > 8 {
            let sp_size = (count - 8) * 8;
            $exec.vcpu.set_sys_reg($crate::applevisor::SysReg::SP_EL0, saved_sp + sp_size)?;
            saved_sp + sp_size
        } else {
            0
        };
        $(
            match index {
                0 => $exec.vcpu.set_reg($crate::applevisor::Reg::X0, $x)?,
                1 => $exec.vcpu.set_reg($crate::applevisor::Reg::X1, $x)?,
                2 => $exec.vcpu.set_reg($crate::applevisor::Reg::X2, $x)?,
                3 => $exec.vcpu.set_reg($crate::applevisor::Reg::X3, $x)?,
                4 => $exec.vcpu.set_reg($crate::applevisor::Reg::X4, $x)?,
                5 => $exec.vcpu.set_reg($crate::applevisor::Reg::X5, $x)?,
                6 => $exec.vcpu.set_reg($crate::applevisor::Reg::X6, $x)?,
                7 => $exec.vcpu.set_reg($crate::applevisor::Reg::X7, $x)?,
                _ => {
                    $exec.vcpu.set_sys_reg($crate::applevisor::SysReg::SP_EL0, sp)?;
                    $exec.vma.borrow_mut().write_qword(sp, $x)?;
                    sp += 8;
                },
            }
            index += 1;
        )*
        call_func_by_addr! { $exec, $addr }
    }};
}
