//! AF_UNIX transport on Windows: winsock `AF_UNIX` sockets (Windows 10+
//! 17063), with the endpoint as a filesystem socket path — the same
//! convention the Unix build uses (maintainer directive: AF_UNIX, not named
//! pipes).
//!
//! The listener calls winsock `accept` directly and wraps the result in
//! std's `TcpStream`: std's own `TcpListener::accept` parses the returned
//! `sockaddr_storage` and rejects the AF_UNIX address family with
//! `EINVAL` (probed on this host), while `TcpStream` reads/writes/timeouts
//! work unchanged on the raw handle.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::windows::io::{FromRawSocket, RawSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows::Win32::Networking::WinSock::{
    self, ADDRESS_FAMILY, AF_UNIX, SOCKADDR, SOCKADDR_UN, SOCK_STREAM, SOCKET, WSAStartup, WSADATA,
};

/// `sun_path` is 108 bytes including the terminator; keep room for both.
const MAX_PATH_BYTES: usize = 107;

/// Winsock must be up before the first `socket()`; std initializes it for its
/// own sockets, but this code creates sockets directly. Idempotent.
fn winsock() -> io::Result<()> {
    static RC: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    let rc = *RC.get_or_init(|| unsafe {
        let mut data = WSADATA::default();
        WSAStartup(0x0202, &mut data)
    });
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

/// Build the `sockaddr_un` for a filesystem path (UTF-8, NUL-terminated).
/// Windows wants `sizeof(SOCKADDR_UN)` in `addrlen` (the Microsoft
/// `afunix.c` sample); the exact Linux-style path length also probes fine.
fn addr(path: &Path) -> io::Result<(SOCKADDR_UN, i32)> {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("AF_UNIX path out of range ({} bytes): {text}", bytes.len()),
        ));
    }
    let mut sa = SOCKADDR_UN::default(); // zeroed: the terminator is the trailing NUL
    sa.sun_family = ADDRESS_FAMILY(AF_UNIX);
    for (i, b) in bytes.iter().enumerate() {
        sa.sun_path[i] = *b as i8;
    }
    Ok((sa, std::mem::size_of::<SOCKADDR_UN>() as i32))
}

fn new_socket() -> io::Result<SOCKET> {
    winsock()?;
    unsafe { WinSock::socket(AF_UNIX as i32, SOCK_STREAM, 0) }.map_err(io::Error::other)
}

/// One listening endpoint (a filesystem socket).
pub struct Listener {
    sock: SOCKET,
    path: PathBuf,
}

impl Listener {
    /// Bind + listen at `path`, removing a stale socket file of a crashed
    /// session first. The parent directory is created if missing.
    pub fn bind(path: &Path) -> io::Result<Listener> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Stale socket of a dead session. A failure here (other than
        // "never existed") is exactly the state where a dead process left
        // a file behind — record it instead of dropping it on the floor.
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != io::ErrorKind::NotFound {
                crate::bg::dbg::trace(serde_json::json!({
                    "phase": "link_stale_socket_remove_failed",
                    "path": path.to_string_lossy(), "err": e.to_string()
                }));
            }
        }
        let s = new_socket()?;
        let fail = |e: io::Error, s: SOCKET| -> io::Error {
            unsafe {
                let _ = WinSock::closesocket(s);
            }
            e
        };
        let (sa, len) = match addr(path) {
            Ok(v) => v,
            Err(e) => return Err(fail(e, s)),
        };
        unsafe {
            if WinSock::bind(s, &sa as *const _ as *const SOCKADDR, len) != 0 {
                return Err(fail(io::Error::last_os_error(), s));
            }
            if WinSock::listen(s, 16) != 0 {
                return Err(fail(io::Error::last_os_error(), s));
            }
        }
        Ok(Listener { sock: s, path: path.to_path_buf() })
    }

    /// Accept one child connection (blocking).
    pub fn accept(&self) -> io::Result<Stream> {
        let client = unsafe { WinSock::accept(self.sock, None, None) }.map_err(io::Error::other)?;
        let stream = unsafe { TcpStream::from_raw_socket(client.0 as RawSocket) };
        Ok(Stream(stream))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        unsafe {
            let _ = WinSock::closesocket(self.sock);
        }
        // A socket file that outlives its listener is precisely the
        // "file present, connect refused" state children dial into —
        // never swallow a removal failure.
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != io::ErrorKind::NotFound {
                crate::bg::dbg::trace(serde_json::json!({
                    "phase": "link_socket_remove_failed",
                    "path": self.path.to_string_lossy(), "err": e.to_string()
                }));
            }
        }
    }
}

/// One connected peer.
pub struct Stream(TcpStream);

impl Stream {
    /// Dial an endpoint. A missing/stale endpoint fails fast (the caller
    /// retries across endpoints and attempts).
    pub fn connect(path: &Path) -> io::Result<Stream> {
        winsock()?;
        let s = new_socket()?;
        let (sa, len) = addr(path)?;
        unsafe {
            if WinSock::connect(s, &sa as *const _ as *const SOCKADDR, len) != 0 {
                let e = io::Error::last_os_error();
                let _ = WinSock::closesocket(s);
                return Err(e);
            }
        }
        Ok(Stream(unsafe { TcpStream::from_raw_socket(s.0 as RawSocket) }))
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
