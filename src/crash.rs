//! Methods to create crash files after a crash or a timeout occured.

use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};

use time;

use crate::core::Executor;
use crate::corpus::*;
use crate::error::*;
use crate::loader::*;
use crate::utils::*;

/// Represents the type of exit can be returned after the execution of a testcase.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ExitKind {
    /// Resumes the execution after an exception occured and was handled.
    Continue,
    /// The execution continues, but we signaled that we returned early from the function
    /// (kind of a hack to update the backtrace even if we didn't execute the return instruction).
    EarlyFunctionReturn,
    /// An exception occured and resulted in a crash. Stores the title of the crash report.
    Crash(String),
    /// The execution timed out.
    Timeout,
    /// The program exited normally.
    Exit,
}

/// Structure handling crashes
///
/// # Role of the Crash Handler in the Fuzzer
///
/// The crash handler does not do much apart from creating a crash files after the targeted program
/// crashed or timed out. It retrieves the corresponding testcase as well as information from the
/// fuzzing worker and creates a file that contains:
///
///  * the crash reason (which is currently just the exception type);
///  * the state of the virtual CPU when the crash happened;
///  * the backtrace;
///  * an hexadecimal dump of the testcase.
///
/// An additional file that only contains the testcase is also created.
///
/// Crashes and timeouts are stored using [`CrashHandler::store_crash`].
pub struct CrashHandler {
    /// The path to the crash directory.
    path: PathBuf,
    /// Random generator used to generate filenames.
    rand: Random,
}

impl CrashHandler {
    /// Creates a new crash handler.
    pub fn new(path: impl AsRef<Path>, rand: Random) -> Result<Self> {
        fs::create_dir_all(&path)?;
        Ok(Self {
            path: path.as_ref().to_owned(),
            rand,
        })
    }

    /// Generates random filepaths in the crash directory for the crash information file and the
    /// testcase that resulted in a crash.
    fn crash_filepath(&mut self) -> (PathBuf, PathBuf) {
        let fmt =
            time::format_description::parse("[year][month][day]-[hour][minute][second]").unwrap();
        let path = self.path.join(PathBuf::from(format!(
            "crash_{}_{}",
            time::OffsetDateTime::now_utc().format(&fmt).unwrap(),
            self.rand.str(10),
        )));
        let mut path_info = path.clone();
        path_info.set_extension("info");
        (path, path_info)
    }

    /// Generates random filepaths in the crash directory for the timeout information file and the
    /// testcase that resulted in a timeout.
    fn timeout_filepath(&mut self) -> (PathBuf, PathBuf) {
        let fmt =
            time::format_description::parse("[year][month][day]-[hour][minute][second]").unwrap();
        let path = self.path.join(PathBuf::from(format!(
            "timeout_{}_{}",
            time::OffsetDateTime::now_utc().format(&fmt).unwrap(),
            self.rand.str(10),
        )));
        let mut path_info = path.clone();
        path_info.set_extension("info");
        (path, path_info)
    }

    /// Stores in the crash directory a crash information file and the testcase that resulted in
    /// a crash.
    pub fn store_crash<L: Loader + Loader<LD = LD> + Loader<GD = GD>, LD: Clone, GD: Clone>(
        &mut self,
        loader: &L,
        title: &str,
        tc: &Testcase,
        executor: &Executor<L, LD, GD>,
        is_timeout: bool,
    ) -> Result<()> {
        // Generates filepaths for the resulting files.
        let (filepath, filepath_info) = if is_timeout {
            self.crash_filepath()
        } else {
            self.timeout_filepath()
        };
        // Opens the crash information file.
        let mut crash_info = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(filepath_info)?;
        let crash_str = loader.format_crash(title, tc, executor, is_timeout)?;
        crash_info.write_all(crash_str.as_bytes())?;
        // Opens the testcase crash file.
        let mut crash = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(filepath)?;
        // Writes the testcase into it.
        crash.write_all(tc.get_data())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_filepath() {
        let mut rand = Random::new(1);
        let mut handler = CrashHandler::new("/tmp/crashes/", rand.split()).unwrap();
        println!("{:?}", handler.crash_filepath());
        println!("{:?}", handler.timeout_filepath());
    }
}
