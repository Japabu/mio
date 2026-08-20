use crate::sys::Selector;
use crate::Token;
use std::io;
use toyos_abi::RawHandle;

#[derive(Debug)]
pub struct Waker {
    write_handle: RawHandle,
}

impl Waker {
    pub fn new(selector: &Selector, token: Token) -> io::Result<Waker> {
        let pipe = toyos_abi::syscall::pipe()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
        selector.register_handle(pipe.read, token, crate::Interest::READABLE)?;
        Ok(Waker {
            write_handle: pipe.write,
        })
    }

    pub fn wake(&self) -> io::Result<()> {
        let _ = toyos_abi::syscall::write_nonblock(self.write_handle, &[1]);
        Ok(())
    }
}
