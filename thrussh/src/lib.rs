// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#![deny(missing_docs,
        trivial_casts,
        unstable_features,
        unused_import_braces)]

//! Server and client SSH asynchronous library, based on tokio/futures.
//!
//! The normal way to use this library, both for clients and for
//! servers, is by creating *handlers*, i.e. types that implement
//! `client::Handler` for clients and `server::Handler` for
//! servers.
//!
//! # Writing servers
//!
//! In the specific case of servers, a server must implement
//! `server::Server`, a trait for creating new `server::Handler`.  The
//! main type to look at in the `server` module is `Session` (and
//! `Config`, of course).
//!
//! Here is an example server, which forwards input from each client
//! to all other clients:
//!
//! ```
//! extern crate thrussh;
//! extern crate thrussh_keys;
//! extern crate futures;
//! extern crate tokio;
//! use std::sync::{Mutex, Arc};
//! use thrussh::*;
//! use thrussh::server::{Auth, Session};
//! use thrussh_keys::*;
//! use std::collections::HashMap;
//! use futures::Future;
//!
//! #[derive(Clone)]
//! struct Server {
//!     client_pubkey: Arc<thrussh_keys::key::PublicKey>,
//!     clients: Arc<Mutex<HashMap<(usize, ChannelId), thrussh::server::Handle>>>,
//!     id: usize,
//! }
//!
//! impl server::Server for Server {
//!     type Handler = Self;
//!     fn new(&mut self) -> Self {
//!         let s = self.clone();
//!         self.id += 1;
//!         s
//!     }
//! }
//!
//! impl server::Handler for Server {
//!     type Error = std::io::Error;
//!     type FutureAuth = futures::Finished<(Self, server::Auth), Self::Error>;
//!     type FutureUnit = futures::Finished<(Self, server::Session), Self::Error>;
//!     type FutureBool = futures::Finished<(Self, server::Session, bool), Self::Error>;
//!
//!     fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
//!         futures::finished((self, auth))
//!     }
//!     fn finished_bool(self, session: Session, b: bool) -> Self::FutureBool {
//!         futures::finished((self, session, b))
//!     }
//!     fn finished(self, session: Session) -> Self::FutureUnit {
//!         futures::finished((self, session))
//!     }
//!     fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
//!         {
//!             let mut clients = self.clients.lock().unwrap();
//!             clients.insert((self.id, channel), session.handle());
//!         }
//!         futures::finished((self, session))
//!     }
//!     fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
//!         futures::finished((self, server::Auth::Accept))
//!     }
//!     fn data(self, channel: ChannelId, data: &[u8], mut session: server::Session) -> Self::FutureUnit {
//!         {
//!             let mut clients = self.clients.lock().unwrap();
//!             for ((id, channel), ref mut s) in clients.iter_mut() {
//!                 if *id != self.id {
//!                     s.data(*channel, None, CryptoVec::from_slice(data));
//!                 }
//!             }
//!         }
//!         session.data(channel, None, data);
//!         futures::finished((self, session))
//!     }
//! }
//!
//! fn main() {
//!     //! Starting the server thread.
//!     let client_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
//!     let client_pubkey = Arc::new(client_key.clone_public_key());
//!     let mut config = thrussh::server::Config::default();
//!     config.connection_timeout = Some(std::time::Duration::from_secs(600));
//!     config.auth_rejection_time = std::time::Duration::from_secs(3);
//!     config.keys.push(thrussh_keys::key::KeyPair::generate_ed25519().unwrap());
//!     let config = Arc::new(config);
//!     let sh = Server{
//!         client_pubkey,
//!         clients: Arc::new(Mutex::new(HashMap::new())),
//!         id: 0
//!     };
//!     tokio::run(thrussh::server::run(config, "0.0.0.0:2222", sh));
//! }
//! ```
//!
//! Note the call to `session.handle()`, which allows to keep a handle
//! to a client outside the event loop. This feature is internally
//! implemented using `futures::sync::mpsc` channels.
//!
//! Note that this is just a toy server. In particular:
//!
//! - It doesn't handle errors when `s.data` returns an error,
//!   i.e. when the client has disappeared
//!
//! - Each new connection increments the `id` field. Even though we
//! would need a lot of connections per second for a very long time to
//! saturate it, there are probably better ways to handle this to
//! avoid collisions.
//!
//!
//! # Implementing clients
//!
//! Maybe surprisingly, the data types used by Thrussh to implement
//! clients are relatively more complicated than for servers. This is
//! mostly related to the fact that clients are generally used both in
//! a synchronous way (in the case of SSH, we can think of sending a
//! shell command), and asynchronously (because the server may send
//! unsollicited messages sometimes), and hence need to handle
//! multiple interfaces.
//!
//! The important types in the `client` module are `Session` and
//! `Connection`. A `Connection` is typically used to send commands to
//! the server and wait for responses, and contains a `Session`. The
//! `Session` is passed to the `Handler` when the client receives
//! data.
//!
//! ```
//!extern crate thrussh;
//!extern crate thrussh_keys;
//!extern crate futures;
//!extern crate tokio;
//!extern crate env_logger;
//!use std::sync::Arc;
//!use thrussh::*;
//!use thrussh::server::{Auth, Session};
//!use thrussh_keys::*;
//!use futures::Future;
//!use std::io::Read;
//!
//!
//!struct Client {
//!  key: Arc<thrussh_keys::key::KeyPair>
//!}
//!
//!impl client::Handler for Client {
//!    type Error = ();
//!    type FutureBool = futures::Finished<(Self, bool), Self::Error>;
//!    type FutureUnit = futures::Finished<Self, Self::Error>;
//!    type FutureSign = futures::Finished<(Self, thrussh::CryptoVec), Self::Error>;
//!    type SessionUnit = futures::Finished<(Self, client::Session), Self::Error>;
//!    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
//!        println!("check_server_key: {:?}", server_public_key);
//!        futures::finished((self, true))
//!    }
//!    fn channel_open_confirmation(self, channel: ChannelId, session: client::Session) -> Self::SessionUnit {
//!        println!("channel_open_confirmation: {:?}", channel);
//!        futures::finished((self, session))
//!    }
//!    fn data(self, channel: ChannelId, ext: Option<u32>, data: &[u8], session: client::Session) -> Self::SessionUnit {
//!        println!("data on channel {:?} {:?}: {:?}", ext, channel, std::str::from_utf8(data));
//!        futures::finished((self, session))
//!    }
//!}
//!
//!impl Client {
//!
//!  fn run(self, config: Arc<client::Config>, _: &str) {
//!     let key = self.key.clone();
//!     tokio::run(
//!
//!       client::connect_future(
//!         "127.0.0.1:2222", config, None, self,
//!         |connection| {
//!           connection.authenticate_key("pe", key)
//!             .and_then(|session| {
//!               session.channel_open_session().and_then(|(session, channelid)| {
//!                 session.data(channelid, None, "Hello, world!").and_then(|(mut session, _)| {
//!                   session.disconnect(Disconnect::ByApplication, "Ciao", "");
//!                   session
//!                 })
//!               })
//!         })
//!       }).unwrap().map_err(|_| ())
//!     )
//!  }
//!}
//!
//!fn main() {
//!    env_logger::init();
//!    // Starting the server thread.
//!    let client_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
//!    let client_pubkey = Arc::new(client_key.clone_public_key());
//!    let mut config = thrussh::client::Config::default();
//!    config.connection_timeout = Some(std::time::Duration::from_secs(600));
//!    let config = Arc::new(config);
//!    let sh = Client { key: Arc::new(client_key) };
//!    sh.run(config, "127.0.0.1:2222");
//!}
//! ```
//! # Using non-socket IO / writing tunnels
//!
//! The easy way to implement SSH tunnels, like `ProxyCommand` for
//! OpenSSH, is to use the `thrussh-config` crate, and use the
//! `Stream::tcp_connect` or `Stream::proxy_command` methods of that
//! crate. That crate is a very lightweight layer above Thrussh, only
//! implementing for external commands the traits used for sockets.
//!
//! # The SSH protocol
//!
//! If we exclude the key exchange and authentication phases, handled
//! by Thrussh behind the scenes, the rest of the SSH protocol is
//! relatively simple: clients and servers open *channels*, which are
//! just integers used to handle multiple requests in parallel in a
//! single connection. Once a client has obtained a `ChannelId` by
//! calling one the many `channel_open_…` methods of
//! `client::Connection`, the client may send exec requests and data
//! to the server.
//!
//! A simple client just asking the server to run one command will
//! usually start by calling
//! `client::Connection::channel_open_session`, then
//! `client::Connection::exec`, then possibly
//! `client::Connection::data` a number of times to send data to the
//! command's standard input, and finally `Connection::channel_eof`
//! and `Connection::channel_close`.
//!
//! # Design principles
//!
//! The main goal of this library is conciseness, and reduced size and
//! readability of the library's code. Moreover, this library is split
//! between Thrussh, which implements the main logic of SSH clients
//! and servers, and Thrussh-keys, which implements calls to
//! cryptographic primitives.
//!
//! One non-goal is to implement all possible cryptographic algorithms
//! published since the initial release of SSH. Technical debt is
//! easily acquired, and we would need a very strong reason to go
//! against this principle. If you are designing a system from
//! scratch, we urge you to consider recent cryptographic primitives
//! such as Ed25519 for public key cryptography, and Chacha20-Poly1305
//! for symmetric cryptography and MAC.
//!
//! # Internal details of the event loop
//!
//! It might seem a little odd that the read/write methods for server
//! or client sessions often return neither `Result` nor
//! `Future`. This is because the data sent to the remote side is
//! buffered, because it needs to be encrypted first, and encryption
//! works on buffers, and for many algorithms, not in place.
//!
//! Hence, the event loop keeps waiting for incoming packets, reacts
//! to them by calling the provided `Handler`, which fills some
//! buffers. If the buffers are non-empty, the event loop then sends
//! them to the socket, flushes the socket, empties the buffers and
//! starts again. In the special case of the server, unsollicited
//! messages sent through a `server::Handle` are processed when there
//! is no incoming packet to read.
//!
#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate log;
extern crate byteorder;

extern crate cryptovec;

extern crate hmac;
extern crate sha2;

extern crate tokio;
extern crate tokio_io;
#[macro_use]
extern crate futures;
extern crate openssl;
extern crate thrussh_libsodium as sodium;
extern crate thrussh_keys;

mod read_exact_from;

pub use cryptovec::CryptoVec;
mod sshbuffer;
mod ssh_read;
mod tcp;
mod key;
mod mac;

pub use tcp::Tcp;

macro_rules! push_packet {
    ( $buffer:expr, $x:expr ) => {
        {
            use byteorder::{BigEndian, ByteOrder};
            let i0 = $buffer.len();
            $buffer.extend(b"\0\0\0\0");
            let x = $x;
            let i1 = $buffer.len();
            use std::ops::DerefMut;
            let buf = $buffer.deref_mut();
            BigEndian::write_u32(&mut buf[i0..], (i1-i0-4) as u32);
            x
        }
    };
}

mod session;



#[derive(Clone, Copy)]
enum Status {
    Ok,
    Disconnect,
}

/// Run one step of the protocol. This trait is currently not used,
/// but both the client and the server implement it. It was meant to
/// factor out code in common between client::Data and a former
/// server::Data.
///
/// The reason the server cannot have a useful `Data` future is that
/// the main interactions between the server and the library user are
/// through callbacks (whereas the client is mostly used by
/// manipulating `Connection`s directly).
trait AtomicPoll<E> {
    fn atomic_poll(&mut self) -> futures::Poll<Status, E>;
}

/// Since handlers are large, their associated future types must implement this trait to provide reasonable default implementations (basically, rejecting all requests).
pub trait FromFinished<T, E>: futures::Future<Item = T, Error = E> {
    /// Turns type `T` into `Self`, a future yielding `T`.
    fn finished(t: T) -> Self;
}

impl<T, E> FromFinished<T, E> for futures::Finished<T, E> {
    fn finished(t: T) -> Self {
        futures::finished(t)
    }
}

impl<T: 'static, E: 'static> FromFinished<T, E> for Box<dyn futures::Future<Item = T, Error = E>> {
    fn finished(t: T) -> Self {
        Box::new(futures::finished(t))
    }
}


#[derive(Debug)]
/// Errors.
pub enum Error {
    /// The key file could not be parsed.
    CouldNotReadKey,

    /// Unspecified problem with the beginning of key exchange.
    KexInit,

    /// No common key exchange algorithm.
    NoCommonKexAlgo,

    /// No common signature algorithm.
    NoCommonKeyAlgo,

    /// No common cipher.
    NoCommonCipher,

    /// No common hmac.
    NoCommonHmac,

    /// Invalid SSH version string.
    Version,

    /// Error during key exchange.
    Kex,

    /// Invalid packet authentication code.
    PacketAuth,

    /// The protocol is in an inconsistent state.
    Inconsistent,

    /// The client is not yet authenticated.
    NotAuthenticated,

    /// Index out of bounds.
    IndexOutOfBounds,

    /// UTF-8 decoding error (most probably ASCII error).
    Utf8(std::str::Utf8Error),

    /// Unknown server key.
    UnknownKey,

    /// Message received/sent on unopened channel.
    WrongChannel,

    /// I/O error.
    IO(std::io::Error),

    /// Disconnected
    Disconnect,

    /// No home directory found when trying to learn new host key.
    NoHomeDir,

    /// Remote key changed, this could mean a man-in-the-middle attack
    /// is being performed on the connection.
    KeyChanged(usize),

    /// Connection closed by the remote side.
    HUP,

    /// Error from the cryptography layer.
    OpenSSL(openssl::error::Error),

    /// Error from the cryptography layer.
    OpenSSLStack(openssl::error::ErrorStack),

    /// Unit error (sodiumoxide might return that).
    Unit,

    /// Connection timeout.
    ConnectionTimeout,

    /// Missing authentication method.
    NoAuthMethod,

    /// Keys error
    Keys(thrussh_keys::Error),

    /// Timer error
    Timer(tokio::timer::Error),
}

/// Errors including those coming from handler. These are not included
/// in this crate's "main" error type to allow for a simpler API (the
/// "handler error" type cannot be inferred by the compiler in some
/// functions).
#[derive(Debug)]
pub enum HandlerError<E> {
    /// Standard errors
    Error(Error),
    /// From handler
    Handler(E),
}

impl<E> std::convert::From<HandlerError<HandlerError<E>>> for HandlerError<E> {
    fn from(e: HandlerError<HandlerError<E>>) -> Self {
        match e {
            HandlerError::Handler(HandlerError::Error(e)) => HandlerError::Error(e),
            HandlerError::Handler(HandlerError::Handler(e)) => HandlerError::Handler(e),
            HandlerError::Error(e) => HandlerError::Error(e)
        }
    }
}

use std::error::Error as StdError;
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}
impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Utf8(ref e) => e.description(),
            Error::IO(ref e) => e.description(),
            Error::CouldNotReadKey => "Could not read key",
            Error::KexInit => "KexInit problem",
            Error::NoCommonKexAlgo => "No common key exchange algorithms were found",
            Error::NoCommonKeyAlgo => "No common signature algorithms were found",
            Error::NoCommonCipher => "No common ciphers were found",
            Error::NoCommonHmac => "No common hmac was found",
            Error::Kex => "Received invalid key exchange packet",
            Error::Version => "Invalid version string from the remote side",
            Error::PacketAuth => "Incorrect packet authentication code",
            Error::Inconsistent => "Unexpected message",
            Error::NotAuthenticated => "Not authenticated",
            Error::IndexOutOfBounds => "Index out of bounds in a packet",
            Error::UnknownKey => "Unknown host key",
            Error::WrongChannel => "Inexistent channel",
            Error::Disconnect => "Disconnected",
            Error::NoHomeDir => "Home directory not found",
            Error::KeyChanged(_) => "Server key changed",
            Error::HUP => "Connection closed by the remote side",
            Error::ConnectionTimeout => "Connection timout",
            Error::NoAuthMethod => "No more authentication methods available",
            Error::OpenSSL(ref e) => e.description(),
            Error::OpenSSLStack(ref e) => e.description(),
            Error::Unit => "Unknown (unit) error",
            Error::Keys(ref e) => e.description(),
            Error::Timer(ref e) => e.description(),
        }
    }
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            Error::Utf8(ref e) => Some(e),
            Error::IO(ref e) => Some(e),
            _ => None,
        }
    }
}

impl<E:std::error::Error> std::fmt::Display for HandlerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}
impl<E:std::error::Error> std::error::Error for HandlerError<E> {
    fn description(&self) -> &str {
        match *self {
            HandlerError::Error(ref e) => e.description(),
            HandlerError::Handler(ref e) => e.description(),
        }
    }
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            HandlerError::Error(ref e) => e.source(),
            HandlerError::Handler(ref e) => e.source(),
        }
    }
}



impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IO(e)
    }
}

impl From<thrussh_keys::Error> for Error {
    fn from(e: thrussh_keys::Error) -> Error {
        Error::Keys(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Utf8(e)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Error {
        Error::OpenSSLStack(e)
    }
}
/*
impl From<tokio_timer::TimerError> for Error {
    fn from(e: tokio_timer::TimerError) -> Error {
        Error::Timer(e)
    }
}
*/
impl From<()> for Error {
    fn from(_: ()) -> Error {
        Error::Unit
    }
}

impl<E> From<Error> for HandlerError<E> {
    fn from(e: Error) -> HandlerError<E> {
        HandlerError::Error(e)
    }
}
impl<E> From<std::io::Error> for HandlerError<E> {
    fn from(e: std::io::Error) -> HandlerError<E> {
        HandlerError::Error(Error::IO(e))
    }
}

impl<E> From<std::str::Utf8Error> for HandlerError<E> {
    fn from(e: std::str::Utf8Error) -> HandlerError<E> {
        HandlerError::Error(Error::Utf8(e))
    }
}
impl<E> From<thrussh_keys::Error> for HandlerError<E> {
    fn from(e: thrussh_keys::Error) -> HandlerError<E> {
        HandlerError::Error(Error::Keys(e))
    }
}

impl<E> From<tokio::timer::Error> for HandlerError<E> {
    fn from(e: tokio::timer::Error) -> HandlerError<E> {
        HandlerError::Error(Error::Timer(e))
    }
}


mod negotiation;
pub use negotiation::{Named, Preferred};
mod pty;
pub use pty::Pty;
mod msg;
mod kex;
mod cipher;

// mod mac;
// use mac::*;
// mod compression;

mod auth;

/// The number of bytes read/written, and the number of seconds before a key re-exchange is requested.
#[derive(Debug, Clone)]
pub struct Limits {
    rekey_write_limit: usize,
    rekey_read_limit: usize,
    rekey_time_limit: std::time::Duration,
}

impl Limits {
    /// Create a new `Limits`, checking that the given bounds cannot lead to nonce reuse.
    pub fn new(write_limit: usize, read_limit: usize, time_limit: std::time::Duration) -> Limits {
        assert!(write_limit <= 1 << 30 && read_limit <= 1 << 30);
        Limits {
            rekey_write_limit: write_limit,
            rekey_read_limit: read_limit,
            rekey_time_limit: time_limit,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        // Following the recommendations of
        // https://tools.ietf.org/html/rfc4253#section-9
        Limits {
            rekey_write_limit: 1 << 30, // 1 Gb
            rekey_read_limit: 1 << 30, // 1 Gb
            rekey_time_limit: std::time::Duration::from_secs(3600),
        }
    }
}

pub use auth::MethodSet;

/// Server side of this library.
pub mod server;

/// Client side of this library.
pub mod client;

/// A reason for disconnection.
#[allow(missing_docs)] // This should be relatively self-explanatory.
pub enum Disconnect {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    #[doc(hidden)]
    Reserved = 4,
    MACError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

/// The type of signals that can be sent to a remote process. If you
/// plan to use custom signals, read [the
/// RFC](https://tools.ietf.org/html/rfc4254#section-6.10) to
/// understand the encoding.
#[allow(missing_docs)]
// This should be relatively self-explanatory.
#[derive(Debug, Clone, Copy)]
pub enum Sig<'a> {
    ABRT,
    ALRM,
    FPE,
    HUP,
    ILL,
    INT,
    KILL,
    PIPE,
    QUIT,
    SEGV,
    TERM,
    USR1,
    Custom(&'a str),
}

impl<'a> Sig<'a> {
    fn name(&self) -> &'a str {
        match *self {
            Sig::ABRT => "ABRT",
            Sig::ALRM => "ALRM",
            Sig::FPE => "FPE",
            Sig::HUP => "HUP",
            Sig::ILL => "ILL",
            Sig::INT => "INT",
            Sig::KILL => "KILL",
            Sig::PIPE => "PIPE",
            Sig::QUIT => "QUIT",
            Sig::SEGV => "SEGV",
            Sig::TERM => "TERM",
            Sig::USR1 => "USR1",
            Sig::Custom(c) => c,
        }
    }
    fn from_name(name: &'a [u8]) -> Result<Sig, Error> {
        match name {
            b"ABRT" => Ok(Sig::ABRT),
            b"ALRM" => Ok(Sig::ALRM),
            b"FPE" => Ok(Sig::FPE),
            b"HUP" => Ok(Sig::HUP),
            b"ILL" => Ok(Sig::ILL),
            b"INT" => Ok(Sig::INT),
            b"KILL" => Ok(Sig::KILL),
            b"PIPE" => Ok(Sig::PIPE),
            b"QUIT" => Ok(Sig::QUIT),
            b"SEGV" => Ok(Sig::SEGV),
            b"TERM" => Ok(Sig::TERM),
            b"USR1" => Ok(Sig::USR1),
            x => Ok(Sig::Custom(std::str::from_utf8(x)?)),
        }
    }
}


/// Reason for not being able to open a channel.
#[derive(Debug, Copy, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum ChannelOpenFailure {
    AdministrativelyProhibited = 1,
    ConnectFailed = 2,
    UnknownChannelType = 3,
    ResourceShortage = 4,
}

impl ChannelOpenFailure {
    fn from_u32(x: u32) -> Option<ChannelOpenFailure> {
        match x {
            1 => Some(ChannelOpenFailure::AdministrativelyProhibited),
            2 => Some(ChannelOpenFailure::ConnectFailed),
            3 => Some(ChannelOpenFailure::UnknownChannelType),
            4 => Some(ChannelOpenFailure::ResourceShortage),
            _ => None,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// The identifier of a channel.
pub struct ChannelId(u32);

/// The parameters of a channel.
#[derive(Debug)]
pub(crate) struct Channel {
    recipient_channel: u32,
    sender_channel: ChannelId,
    recipient_window_size: u32,
    sender_window_size: u32,
    recipient_maximum_packet_size: u32,
    sender_maximum_packet_size: u32,
    /// Has the other side confirmed the channel?
    pub confirmed: bool,
    wants_reply: bool,
}
