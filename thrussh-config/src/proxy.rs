use std;
use tokio;
use futures::{Poll, Async, Future};
use tokio::net::tcp::TcpStream;
use std::net::SocketAddr;
use std::process::{Stdio, Command};
use thrussh;
use std::io::Write;

/// A type to implement either a TCP socket, or proxying through an external command.
pub enum Stream {
    #[allow(missing_docs)]
    Child(std::process::Child),
    #[allow(missing_docs)]
    Tcp(TcpStream)
}

pub struct ConnectFuture(Option<ConnectFuture_>);
enum ConnectFuture_ {
    Tcp(tokio::net::tcp::ConnectFuture),
    Child(std::process::Child),
}

impl Future for ConnectFuture {
    type Item = Stream;
    type Error = tokio::io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.take().unwrap() {
            ConnectFuture_::Tcp(mut tcp) => {
                match tcp.poll()? {
                    Async::Ready(tcp) => Ok(Async::Ready(Stream::Tcp(tcp))),
                    Async::NotReady => {
                        self.0 = Some(ConnectFuture_::Tcp(tcp));
                        Ok(Async::NotReady)
                    }
                }
            },
            ConnectFuture_::Child(child) => Ok(Async::Ready(Stream::Child(child)))
        }
    }
}

impl Stream {
    /// Connect a direct TCP stream (as opposed to a proxied one).
    pub fn tcp_connect(addr: &SocketAddr) -> ConnectFuture {
        ConnectFuture(Some(ConnectFuture_::Tcp(tokio::net::tcp::TcpStream::connect(addr))))
    }
    /// Connect through a proxy command.
    pub fn proxy_command(cmd: &str, args: &[&str]) -> ConnectFuture {
        ConnectFuture(Some(ConnectFuture_::Child(
            Command::new(cmd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .args(args)
                .spawn().unwrap()
        )))
    }
}

impl tokio::io::Read for Stream {
    fn read(&mut self, r: &mut [u8]) -> std::io::Result<usize> {
        match *self {
            Stream::Child(ref mut c) => c.stdout.as_mut().unwrap().read(r),
            Stream::Tcp(ref mut t) => t.read(r)
        }
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match *self {
            Stream::Child(ref mut c) => {
                c.stdin.take();
                Ok(Async::Ready(()))
            },
            Stream::Tcp(ref mut t) => t.shutdown()
        }
    }
    fn poll_write(&mut self, r: &[u8]) -> Result<Async<usize>, std::io::Error> {
        match *self {
            Stream::Child(ref mut c) => {
                match c.stdin.as_mut().unwrap().write(r) {
                    Ok(n) => Ok(Async::Ready(n)),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Async::NotReady),
                    Err(e) => Err(e)
                }
            },
            Stream::Tcp(ref mut t) => t.poll_write(r)
        }
    }
    fn poll_flush(&mut self) -> Result<Async<()>, std::io::Error> {
        match *self {
            Stream::Child(ref mut c) => {
                match c.stdin.as_mut().unwrap().flush() {
                    Ok(n) => Ok(Async::Ready(n)),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Async::NotReady),
                    Err(e) => Err(e)
                }
            },
            Stream::Tcp(ref mut t) => t.poll_flush()
        }
    }
}

impl std::io::Write for Stream {
    fn write(&mut self, r: &[u8]) -> std::io::Result<usize> {
        match *self {
            Stream::Child(ref mut c) => c.stdin.as_mut().unwrap().write(r),
            Stream::Tcp(ref mut t) => t.write(r)
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match *self {
            Stream::Child(ref mut c) => c.stdin.as_mut().unwrap().flush(),
            Stream::Tcp(ref mut t) => t.flush()
        }
    }
}

impl tokio::io::AsyncRead for Stream{}
impl thrussh::Tcp for Stream {

}
