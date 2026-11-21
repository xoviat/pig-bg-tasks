//! AF_UNIX transport on Unix: std's `UnixListener`/`UnixStream`, the same
//! filesystem-socket convention the Windows build implements over winsock.

use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One listening endpoint (a filesystem socket).
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
}

impl Listener {
    /// Bind + listen at `path`, removing a stale socket file of a crashed
    /// session first. The parent directory is created if missing and the
    /// socket is user-only (0600), like the Go link.
    pub fn bind(path: &Path) -> io::Result<Listener> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let _ = std::fs::remove_file(path); // stale socket of a dead session
        let inner = UnixListener::bind(path)?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        Ok(Listener { inner, path: path.to_path_buf() })
    }

    /// Accept one child connection (blocking).
    pub fn accept(&self) -> io::Result<Stream> {
        let (s, _) = self.inner.accept()?;
        Ok(Stream(s))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One connected peer.
pub struct Stream(UnixStream);

impl Stream {
    /// Dial an endpoint. A missing/stale endpoint fails fast (the caller
    /// retries across endpoints and attempts).
    pub fn connect(path: &Path) -> io::Result<Stream> {
        UnixStream::connect(path).map(Stream)
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(d)
    }

    pub fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(d)
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
