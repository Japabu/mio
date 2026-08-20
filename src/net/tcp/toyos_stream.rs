use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr};

use crate::{event, Interest, Registry, Token};
use toyos_abi::RawHandle;
use toyos_abi::syscall::{self, SyscallError};
use toyos::net::{NetError, TcpSocketId};

/// A non-blocking TCP stream backed by kernel pipes via netd.
pub struct TcpStream {
    rx_handle: RawHandle,
    tx_handle: RawHandle,
    peer_addr: SocketAddr,
    local_port: u16,
    socket_id: TcpSocketId,
}

pub(crate) fn net_err_to_io(e: NetError) -> io::Error {
    let kind = match e {
        NetError::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        NetError::ConnectionReset => io::ErrorKind::ConnectionReset,
        NetError::TimedOut => io::ErrorKind::TimedOut,
        NetError::AddrInUse => io::ErrorKind::AddrInUse,
        NetError::NotConnected => io::ErrorKind::NotConnected,
        NetError::InvalidInput => io::ErrorKind::InvalidInput,
        NetError::NetdNotFound => io::ErrorKind::NotConnected,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, "netd error")
}

impl TcpStream {
    /// Issue a non-blocking connect to the specified address via netd.
    pub fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
        let ip = match addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(_) => {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "IPv6 not supported"));
            }
        };

        let conn = toyos::net::tcp_connect(ip, addr.port(), 30000).map_err(net_err_to_io)?;

        Ok(TcpStream {
            rx_handle: conn.rx.into_raw(),
            tx_handle: conn.tx.into_raw(),
            peer_addr: addr,
            local_port: conn.local_port,
            socket_id: conn.socket_id,
        })
    }

    /// Create a TcpStream from pipe ends netd already handed over (used by
    /// TcpListener::accept).
    pub(crate) fn from_accepted(accepted: toyos::net::TcpAccepted) -> TcpStream {
        let peer_addr = SocketAddr::from((accepted.remote_addr, accepted.remote_port));
        TcpStream {
            rx_handle: accepted.rx.into_raw(),
            tx_handle: accepted.tx.into_raw(),
            peer_addr,
            local_port: accepted.local_port,
            socket_id: accepted.socket_id,
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([0, 0, 0, 0], self.local_port)))
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how_val: u32 = match how {
            Shutdown::Read => 0,
            Shutdown::Write => 1,
            Shutdown::Both => 2,
        };
        toyos::net::tcp_shutdown(self.socket_id, how_val).map_err(net_err_to_io)
    }

    pub fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        Ok(()) // No-op: smoltcp doesn't implement Nagle
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(true)
    }

    pub fn set_ttl(&self, _ttl: u32) -> io::Result<()> {
        Ok(())
    }

    pub fn ttl(&self) -> io::Result<u32> {
        Ok(64)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(None)
    }

    pub fn peek(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "peek not supported"))
    }

    pub fn try_io<F, T>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> io::Result<T>,
    {
        f()
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match syscall::read_nonblock(self.rx_handle, buf) {
            Ok(0) => Ok(0),
            Ok(n) => Ok(n),
            Err(SyscallError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }
}

impl Read for &'_ TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match syscall::read_nonblock(self.rx_handle, buf) {
            Ok(0) => Ok(0),
            Ok(n) => Ok(n),
            Err(SyscallError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match syscall::write_nonblock(self.tx_handle, buf) {
            Ok(n) => Ok(n),
            Err(SyscallError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &'_ TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match syscall::write_nonblock(self.tx_handle, buf) {
            Ok(n) => Ok(n),
            Err(SyscallError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl event::Source for TcpStream {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        let sel = registry.selector();
        if interests.is_readable() {
            sel.register_handle(self.rx_handle, token, Interest::READABLE)?;
        }
        if interests.is_writable() {
            sel.register_handle(self.tx_handle, token, Interest::WRITABLE)?;
        }
        Ok(())
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        let sel = registry.selector();
        sel.deregister_handle(self.rx_handle)?;
        sel.deregister_handle(self.tx_handle)?;
        if interests.is_readable() {
            sel.register_handle(self.rx_handle, token, Interest::READABLE)?;
        }
        if interests.is_writable() {
            sel.register_handle(self.tx_handle, token, Interest::WRITABLE)?;
        }
        Ok(())
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        let sel = registry.selector();
        sel.deregister_handle(self.rx_handle)?;
        sel.deregister_handle(self.tx_handle)?;
        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _ = toyos::net::tcp_close(self.socket_id);
        syscall::close(self.rx_handle);
        syscall::close(self.tx_handle);
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpStream")
            .field("rx_handle", &self.rx_handle)
            .field("tx_handle", &self.tx_handle)
            .field("peer_addr", &self.peer_addr)
            .finish()
    }
}
