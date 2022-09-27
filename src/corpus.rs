//! Handles the corpus and testcases sent to the fuzzed targets.

use std::fs::{read_dir, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rhexdump as rh;

use crate::coverage::*;
use crate::error::*;
use crate::utils::*;

/// Determines which action should be taken after a testcase has been loaded by the fuzzer.
/// Because a given testcase can be reused across multiple iterations, it's possible to tell the
/// fuzzer whether we want to keep it and use the remaining data for the next iteration or discard
/// it and get a new one.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum LoadTestcaseAction {
    /// Once the current testcase is loaded, we discard it and get a new one for the next
    /// iteration. Doesn't reset the fuzzer from the snapshots.
    New,
    /// Once the current testcase is loaded, we discard it and get a new one for the next
    /// iteration. Resets the fuzzer using the snapshots.
    NewAndReset,
    /// If there is still data in the current testcase that can be used for the next iteration,
    /// we keep it. Doesn't reset the fuzzer from the snapshots.
    Keep,
    /// If there is still data in the current testcase that can be used for the next iteration,
    /// we keep it. Resets the fuzzer using the snapshots.
    KeepAndReset,
    /// The testcase is invalid, a new one will be fetched and loaded right away. Doesn't reset
    /// the fuzzer from the snapshots.
    Invalid,
    /// The testcase is invalid, a new one will be fetched and loaded right away. Resets the
    /// fuzzer using the snapshots.
    InvalidAndReset,
}

/// Represents the input executed during one iteration of the fuzzer.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Testcase {
    /// The path to the testcase on disk.
    pub(crate) path: Option<PathBuf>,
    /// The seed that helped generate the testcase (used for name generation).
    pub(crate) seed: Option<u64>,
    /// The time it took for the testcase to run.
    pub(crate) exec_time: Duration,
    /// The coverage associated to this testcase.
    pub(crate) coverage: Coverage,
    /// The testcase's content.
    pub(crate) data: Vec<u8>,
}

impl Testcase {
    /// Creates a new testcase from a slice.
    pub fn new(seed: u64, data: &[u8]) -> Self {
        Self {
            path: None,
            seed: Some(seed),
            exec_time: Duration::new(0, 0),
            coverage: Coverage::new(),
            data: data.to_vec(),
        }
    }

    /// Loads a testcase from the file located at `filepath`.
    pub fn from_file(filepath: impl AsRef<Path>) -> Result<Self> {
        let mut testcase = OpenOptions::new().read(true).open(&filepath)?;
        let mut data = vec![];
        testcase.read_to_end(&mut data)?;
        Ok(Self {
            path: Some(filepath.as_ref().to_owned()),
            seed: None,
            exec_time: Duration::new(0, 0),
            coverage: Coverage::new(),
            data,
        })
    }

    /// Writes a testcase into the `dir` directory.
    pub fn to_file(&self, dir: impl AsRef<Path>) -> Result<()> {
        let filepath = self.filepath(dir);
        let mut testcase = OpenOptions::new().create(true).write(true).open(filepath)?;
        testcase.write_all(&self.data)?;
        Ok(())
    }

    /// Returns the testcase's size.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns if the testcase is empty.
    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    /// Returns an immutable reference to the testcase data.
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable reference to the testcase data.
    pub fn get_data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Sets the seed used to generate the testcase.
    pub fn set_seed(&mut self, seed: u64) {
        self.seed = Some(seed);
    }

    /// Generates a random testcase filepath in the corpus directory.
    fn filepath(&self, dir: impl AsRef<Path>) -> PathBuf {
        let fmt =
            time::format_description::parse("[year][month][day]-[hour][minute][second]").unwrap();
        // We can unwrap safely here, because testcases without a seed are those that were loaded
        // from the corpus, so they shouldn't be written back without having their seed set after
        // having been mutated.
        let seed = self.seed.unwrap();
        dir.as_ref().join(PathBuf::from(format!(
            "testcase_{}_{:x}",
            time::OffsetDateTime::now_utc().format(&fmt).unwrap(),
            seed,
        )))
    }
}

impl std::default::Default for Testcase {
    fn default() -> Self {
        Testcase::new(0, &[])
    }
}

impl std::fmt::Display for Testcase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", rh::hexdump(&self.data))
    }
}

/// The non-shareable inner structure of [`Corpus`] that contains the testcases.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CorpusInner {
    /// Path to the inputs directory.
    pub(crate) path: PathBuf,
    /// Vector containing tuples of [`Testcase`]s and the number of use of each testcase.
    /// This vector is sorted by number of uses, from the most used testcase to the least used one.
    pub(crate) testcases: Vec<(usize, Testcase)>,
    /// The corpus random generator used to choose the next testcase.
    pub(crate) rand: Random,
}

impl CorpusInner {
    /// Creates a new inner corpus structure.
    fn new(rand: Random, path: PathBuf) -> Result<Self> {
        Ok(Self {
            path,
            testcases: vec![],
            rand,
        })
    }
}

/// The corpus containing testcases shared between all fuzzing workers.
///
/// # Role of the Corpus in the Fuzzer.
///
/// Our mutation-based fuzzer needs an initial set of testcases to start running. These testcases
/// are stored in the corpus and can be loaded from a directory using [`Corpus::load_from_dir`].
///
/// The fuzzer currently does not implement corpus minimization, a process that removes as many
/// testcases as possible without reducing coverage. While implementing such a system would
/// distill the current corpus to its essence, we would effectively lose out on information that
/// might have been useful for later iterations (e.g. a testcase that sets up an internal state
/// that would trigger a bug after being mutated for a few times). Instead, this fuzzer keeps all
/// testcases, but favors the least used ones when picking the next testcase using
/// [`Corpus::get_testcase`].
#[derive(Clone, Debug)]
pub struct Corpus {
    pub(crate) inner: Arc<RwLock<CorpusInner>>,
}

impl Corpus {
    /// Creates a new shared corpus.
    pub fn new(
        rand: Random,
        corpus_path: impl AsRef<Path>,
        work_dir: impl AsRef<Path>,
        load_corpus: bool,
    ) -> Result<Self> {
        let mut inputs_path = work_dir.as_ref().to_owned();
        inputs_path.push("inputs");
        // Creates the directory containing the inputs queued for mutation.
        std::fs::create_dir_all(&inputs_path)?;
        // Copies the file from the corpus directory into the inputs directory if corpus loading is
        // enabled.
        if load_corpus && corpus_path.as_ref().exists() {
            for corpus_entry in read_dir(&corpus_path)? {
                let corpus_entry = corpus_entry?;
                let corpus_entry_path = corpus_entry.path();
                // Ignores subdirectories.
                if !corpus_entry_path.is_dir() {
                    let mut inputs_entry_path = inputs_path.clone();
                    inputs_entry_path.push(corpus_entry.file_name());
                    std::fs::copy(corpus_entry_path, inputs_entry_path)?;
                }
            }
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(CorpusInner::new(rand, inputs_path)?)),
        })
    }

    /// Loads all testcases stored in the `path` directory.
    pub fn load_from_dir(&mut self, max_size: usize) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        // Iterates over each entry in `path`.
        for entry in read_dir(&inner.path)? {
            let entry = entry?;
            let path = entry.path();
            // Ignores subdirectories.
            if !path.is_dir() {
                let testcase = Testcase::from_file(path)?;
                // Testcases that are too big are ignored.
                // TODO: maybe add a config option to decide between ignoring the testcase,
                //       truncating it, or raising an error.
                if testcase.len() > max_size {
                    continue;
                }
                inner.testcases.push((0, testcase));
            }
        }
        Ok(())
    }

    /// Adds a testcase to the shared corpus.
    pub fn add_testcase(&mut self, testcase: Testcase) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        // We write the testcase into the corpus directory.
        testcase.to_file(&inner.path)?;
        // When we push this testcase at the end we don't need to sort the array, because a
        // new testcase is guarenteed to be the least used one.
        inner.testcases.push((0, testcase));
        Ok(())
    }

    /// Gets one testcase from the shared corpus (the least used are more likely to be selected
    /// next).
    pub fn get_testcase(&mut self) -> Testcase {
        let mut inner = self.inner.write().unwrap();
        let corpus_len = inner.testcases.len() as u64;
        if corpus_len == 0 {
            return Testcase::default();
        }
        // Generates a random index in the corpus using an exponential distribution.
        // to select, on average, less used testcases that are the least used (those towards the
        // end of the vector)
        let idx = corpus_len - 1 - inner.rand.exp_range(0, corpus_len).unwrap();
        let testcase = if let Some((count, testcase)) = inner.testcases.get_mut(idx as usize) {
            *count += 1;
            testcase.clone()
        } else {
            // We've checked earlier that the corpus has at least one testcase.
            unreachable!();
        };
        // Sorts the vector by number of testcases, from the most used one to the least used one.
        inner.testcases.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        // Returns the testcase was extracted.
        testcase
    }

    /// Returns the numbers of testcases in the corpus.
    pub fn nb_entries(&self) -> usize {
        self.inner.read().unwrap().testcases.len()
    }
}
