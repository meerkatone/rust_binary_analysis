//! Publish a complete report with a same-directory atomic rename.
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

pub(crate) struct AtomicOutput {
    pub(crate) file: File,
    temporary: PathBuf,
    destination: PathBuf,
}

impl AtomicOutput {
    pub(crate) fn new(destination: &Path) -> io::Result<Self> {
        let directory = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        loop {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let temporary =
                directory.join(format!(".bn-report-{}-{sequence}.tmp", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        temporary,
                        destination: destination.into(),
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn commit(self) -> io::Result<()> {
        self.file.sync_all()?;
        fs::rename(&self.temporary, &self.destination)
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn incomplete_report_preserves_previous_file_and_cleans_up() {
        let directory = std::env::temp_dir().join(format!(
            "bn-atomic-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let destination = directory.join("report.parquet");
        fs::write(&destination, b"previous").unwrap();
        {
            let mut pending = AtomicOutput::new(&destination).unwrap();
            pending.file.write_all(b"incomplete").unwrap();
            assert_eq!(fs::read(&destination).unwrap(), b"previous");
        }
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        let mut pending = AtomicOutput::new(&destination).unwrap();
        pending.file.write_all(b"complete").unwrap();
        pending.commit().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"complete");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }
}
