#![deny(trivial_casts,
        unstable_features,
        unused_import_braces)]
//! This crate contains methods to deal with SSH keys, as defined in
//! crate Thrussh. This includes in particular various functions for
//! opening key files, deciphering encrypted keys, and dealing with
//! agents.
//!
//! The following example shows how to do all these in a single
//! example: start and SSH agent server, connect to it with a client,
//! decipher an encrypted private key (the password is `b"blabla"`),
//! send it to the agent, and ask the agent to sign a piece of data
//! (`b"Please sign this", below).
//!
//!```
//! extern crate thrussh_keys;
//! extern crate futures;
//! extern crate tempdir;
//! extern crate tokio_uds;
//! extern crate tokio;
//! use thrussh_keys::*;
//! use futures::Future;
//!
//! struct F(bool);
//! impl std::convert::From<bool> for F {
//!     fn from(e: bool) -> Self {
//!         F(e)
//!     }
//! }
//! impl futures::Future for F {
//!     type Item = bool;
//!     type Error = Error;
//!     fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
//!         Ok(futures::Async::Ready(self.0))
//!     }
//! }
//! #[derive(Clone)]
//! struct X{}
//! impl agent::server::Agent for X {
//!     type F = F;
//!     fn confirm(&self, pk: &key::KeyPair) -> Self::F {
//!         F(true)
//!     }
//! }
//!
//!
//! const PKCS8_ENCRYPTED: &'static str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITo1O0b8YrS0CAggA\nMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBtLH4T1KOfo1GGr7salhR8BIIE\n0KN9ednYwcTGSX3hg7fROhTw7JAJ1D4IdT1fsoGeNu2BFuIgF3cthGHe6S5zceI2\nMpkfwvHbsOlDFWMUIAb/VY8/iYxhNmd5J6NStMYRC9NC0fVzOmrJqE1wITqxtORx\nIkzqkgFUbaaiFFQPepsh5CvQfAgGEWV329SsTOKIgyTj97RxfZIKA+TR5J5g2dJY\nj346SvHhSxJ4Jc0asccgMb0HGh9UUDzDSql0OIdbnZW5KzYJPOx+aDqnpbz7UzY/\nP8N0w/pEiGmkdkNyvGsdttcjFpOWlLnLDhtLx8dDwi/sbEYHtpMzsYC9jPn3hnds\nTcotqjoSZ31O6rJD4z18FOQb4iZs3MohwEdDd9XKblTfYKM62aQJWH6cVQcg+1C7\njX9l2wmyK26Tkkl5Qg/qSfzrCveke5muZgZkFwL0GCcgPJ8RixSB4GOdSMa/hAMU\nkvFAtoV2GluIgmSe1pG5cNMhurxM1dPPf4WnD+9hkFFSsMkTAuxDZIdDk3FA8zof\nYhv0ZTfvT6V+vgH3Hv7Tqcxomy5Qr3tj5vvAqqDU6k7fC4FvkxDh2mG5ovWvc4Nb\nXv8sed0LGpYitIOMldu6650LoZAqJVv5N4cAA2Edqldf7S2Iz1QnA/usXkQd4tLa\nZ80+sDNv9eCVkfaJ6kOVLk/ghLdXWJYRLenfQZtVUXrPkaPpNXgD0dlaTN8KuvML\nUw/UGa+4ybnPsdVflI0YkJKbxouhp4iB4S5ACAwqHVmsH5GRnujf10qLoS7RjDAl\no/wSHxdT9BECp7TT8ID65u2mlJvH13iJbktPczGXt07nBiBse6OxsClfBtHkRLzE\nQF6UMEXsJnIIMRfrZQnduC8FUOkfPOSXc8r9SeZ3GhfbV/DmWZvFPCpjzKYPsM5+\nN8Bw/iZ7NIH4xzNOgwdp5BzjH9hRtCt4sUKVVlWfEDtTnkHNOusQGKu7HkBF87YZ\nRN/Nd3gvHob668JOcGchcOzcsqsgzhGMD8+G9T9oZkFCYtwUXQU2XjMN0R4VtQgZ\nrAxWyQau9xXMGyDC67gQ5xSn+oqMK0HmoW8jh2LG/cUowHFAkUxdzGadnjGhMOI2\nzwNJPIjF93eDF/+zW5E1l0iGdiYyHkJbWSvcCuvTwma9FIDB45vOh5mSR+YjjSM5\nnq3THSWNi7Cxqz12Q1+i9pz92T2myYKBBtu1WDh+2KOn5DUkfEadY5SsIu/Rb7ub\n5FBihk2RN3y/iZk+36I69HgGg1OElYjps3D+A9AjVby10zxxLAz8U28YqJZm4wA/\nT0HLxBiVw+rsHmLP79KvsT2+b4Diqih+VTXouPWC/W+lELYKSlqnJCat77IxgM9e\nYIhzD47OgWl33GJ/R10+RDoDvY4koYE+V5NLglEhbwjloo9Ryv5ywBJNS7mfXMsK\n/uf+l2AscZTZ1mhtL38efTQCIRjyFHc3V31DI0UdETADi+/Omz+bXu0D5VvX+7c6\nb1iVZKpJw8KUjzeUV8yOZhvGu3LrQbhkTPVYL555iP1KN0Eya88ra+FUKMwLgjYr\nJkUx4iad4dTsGPodwEP/Y9oX/Qk3ZQr+REZ8lg6IBoKKqqrQeBJ9gkm1jfKE6Xkc\nCog3JMeTrb3LiPHgN6gU2P30MRp6L1j1J/MtlOAr5rux\n-----END ENCRYPTED PRIVATE KEY-----\n";
//!
//! fn main() {
//!     let dir = tempdir::TempDir::new("thrussh").unwrap();
//!     let agent_path = dir.path().join("agent");
//!
//!     let mut core = tokio::runtime::Runtime::new().unwrap();
//!     let listener = tokio_uds::UnixListener::bind(&agent_path).unwrap().incoming();
//!
//!     core.spawn(
//!         agent::server::AgentServer::new(listener, X{})
//!             .map_err(|e| println!("{:?}", e))
//!     );
//!
//!     let key = decode_secret_key(PKCS8_ENCRYPTED, Some(b"blabla")).unwrap();
//!     let public = key.clone_public_key();
//!     core.block_on(
//!         tokio_uds::UnixStream::connect(&agent_path).from_err().and_then(move |stream| {
//!             agent::client::AgentClient::connect(stream)
//!                 .add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }]).and_then(move |(client, _)| {
//!                     client.request_identities().and_then(move |(client, id)| {
//!                         client.sign_request(&public, b"Please sign this").and_then(|(_, sig)| {
//!                             let sig = sig.unwrap();
//!                             futures::finished(())
//!                         })
//!                     })
//!                 })
//!         })
//!     ).unwrap();
//! }
//!```



#![recursion_limit="128"]
extern crate base64;
extern crate hex;
extern crate byteorder;
extern crate yasna;
extern crate tokio;
extern crate futures;
extern crate cryptovec;
extern crate num_bigint;
extern crate num_integer;
extern crate bit_vec;
extern crate openssl;
extern crate thrussh_libsodium as sodium;
#[cfg(test)]
extern crate tokio_uds;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate log;
extern crate serde;
extern crate dirs;
#[cfg(test)]
extern crate env_logger;

use base64::{decode_config, encode_config, MIME};
use std::path::Path;
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufRead, Read, Write, Seek, SeekFrom};
use byteorder::{BigEndian, WriteBytesExt};

pub mod key;
pub mod signature;
pub mod encoding;

mod blowfish;
mod bcrypt_pbkdf;
mod format;
pub use format::*;

/// A module to write SSH agent.
pub mod agent;

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    Utf8(std::str::Utf8Error),
    OpenSSL(openssl::error::Error),
    OpenSSLStack(openssl::error::ErrorStack),
    Base64(base64::DecodeError),
    Hex(hex::FromHexError),
    Yasna(yasna::ASN1Error),
    TokioSpawn(tokio::executor::SpawnError),
    /// Unknown error
    Unit,
    /// The key could not be read, for an unknown reason
    CouldNotReadKey,
    /// The type of the key is unsupported
    UnsupportedKeyType(Vec<u8>),
    /// The key is encrypted (should supply a password?)
    KeyIsEncrypted,
    /// Home directory could not be found
    NoHomeDir,
    /// The server key has changed
    KeyChanged(usize),
    /// The key uses an unsupported algorithm
    UnknownAlgorithm(yasna::models::ObjectIdentifier),
    /// Lock poisoning error
    Poison,
    /// Index out of bounds
    IndexOutOfBounds,
}

type Result<A> = std::result::Result<A, Error>;

impl std::error::Error for Error {}

impl std::convert::From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IO(e)
    }
}

impl std::convert::From<openssl::error::Error> for Error {
    fn from(e: openssl::error::Error) -> Self {
        Error::OpenSSL(e)
    }
}

impl std::convert::From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSSLStack(e)
    }
}

impl std::convert::From<yasna::ASN1Error> for Error {
    fn from(e: yasna::ASN1Error) -> Self {
        Error::Yasna(e)
    }
}

impl std::convert::From<tokio::executor::SpawnError> for Error {
    fn from(e: tokio::executor::SpawnError) -> Self {
        Error::TokioSpawn(e)
    }
}

impl std::convert::From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e)
    }
}

impl std::convert::From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::Hex(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

const KEYTYPE_ED25519: &'static [u8] = b"ssh-ed25519";

/// Load a public key from a file. Ed25519 and RSA keys are supported.
///
/// ```
/// thrussh_keys::load_public_key("/home/pe/.ssh/id_ed25519.pub").unwrap();
/// ```
pub fn load_public_key<P:AsRef<Path>>(path: P) -> Result<key::PublicKey> {
    let mut pubkey = String::new();
    let mut file = try!(File::open(path.as_ref()));
    try!(file.read_to_string(&mut pubkey));

    let mut split = pubkey.split_whitespace();
    match (split.next(), split.next()) {
        (Some(_), Some(key)) => parse_public_key_base64(key),
        (Some(key), None) => parse_public_key_base64(key),
        _ => Err(Error::CouldNotReadKey),
    }
}

/// Reads a public key from the standard encoding. In some cases, the
/// encoding is prefixed with a key type identifier and a space (such
/// as `ssh-ed25519 AAAAC3N...`).
///
/// ```
/// thrussh_keys::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").is_ok();
/// ```
pub fn parse_public_key_base64(key: &str) -> Result<key::PublicKey> {
    let base = decode_config(key, MIME)?;
    Ok(key::parse_public_key(&base)?)
}

pub trait PublicKeyBase64 {
    /// Create the base64 part of the public key blob.
    fn public_key_base64(&self) -> String;
}

impl PublicKeyBase64 for key::PublicKey {
    fn public_key_base64(&self) -> String {
        let name = self.name().as_bytes();
        let mut s = cryptovec::CryptoVec::new();
        s.write_u32::<BigEndian>(name.len() as u32).unwrap();
        s.extend(name);
        match *self {
            key::PublicKey::Ed25519(ref publickey) => {
                s.write_u32::<BigEndian>(publickey.key.len() as u32).unwrap();
                s.extend(&publickey.key);
            }
            key::PublicKey::RSA { ref key, .. } => {
                use encoding::Encoding;
                s.extend_ssh_mpint(&key.0.rsa().unwrap().e().to_vec());
                s.extend_ssh_mpint(&key.0.rsa().unwrap().n().to_vec());
            }
        }
        encode_config(&s, MIME)
    }
}

impl PublicKeyBase64 for key::KeyPair {
    fn public_key_base64(&self) -> String {
        let name = self.name().as_bytes();
        let mut s = cryptovec::CryptoVec::new();
        s.write_u32::<BigEndian>(name.len() as u32).unwrap();
        s.extend(name);
        match *self {
            key::KeyPair::Ed25519(ref key) => {
                let public = &key.key[32.. ];
                s.write_u32::<BigEndian>(32).unwrap();
                s.extend(&public);
            }
            key::KeyPair::RSA { ref key, .. } => {
                use encoding::Encoding;
                s.extend_ssh_mpint(&key.e().to_vec());
                s.extend_ssh_mpint(&key.n().to_vec());
            }
        }
        encode_config(&s, MIME)
    }
}

/// Write a public key onto the provided `Write`, encoded in base-64.
pub fn write_public_key_base64<W:Write>(mut w:W, publickey:&key::PublicKey) -> Result<()> {
    let name = publickey.name().as_bytes();
    w.write_all(name)?;
    w.write_all(b" ")?;
    w.write_all(publickey.public_key_base64().as_bytes())?;
    Ok(())
}


/// Load a secret key, deciphering it with the supplied password if necessary.
pub fn load_secret_key<P:AsRef<Path>>(secret_: P, password: Option<&[u8]>) -> Result<key::KeyPair> {
    let mut secret_file = std::fs::File::open(secret_)?;
    let mut secret = String::new();
    secret_file.read_to_string(&mut secret)?;
    decode_secret_key(&secret, password)
}

fn is_base64_char(c: char) -> bool {
    (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '/' || c == '+' || c == '='
}


/// Record a host's public key into a nonstandard location.
pub fn learn_known_hosts_path<P:AsRef<Path>>(host:&str, port:u16, pubkey:&key::PublicKey, path:P) -> Result<()> {

    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;

    // Test whether the known_hosts file ends with a \n
    let mut buf = [0;1];
    let mut ends_in_newline = false;
    if file.seek(SeekFrom::End(-1)).is_ok() {
        file.read_exact(&mut buf)?;
        ends_in_newline = buf[0] == b'\n';
    }

    // Write the key.
    file.seek(SeekFrom::Start(0))?;
    let mut file = std::io::BufWriter::new(file);
    if !ends_in_newline {
        file.write(b"\n")?;
    }
    if port != 22 {
        write!(file, "[{}]:{} ", host, port)?
    } else {
        write!(file, "{} ", host)?
    }
    write_public_key_base64(&mut file, pubkey)?;
    file.write(b"\n")?;
    Ok(())
}

/// Check that a server key matches the one recorded in file `path`.
pub fn check_known_hosts_path<P: AsRef<Path>>(host: &str,
                                              port: u16,
                                              pubkey: &key::PublicKey,
                                              path: P)
                                              -> Result<bool> {
    let mut f = if let Ok(f) = File::open(path) {
        BufReader::new(f)
    } else {
        return Ok(false)
    };
    let mut buffer = String::new();

    let host_port = if port == 22 {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("[{}]:{}", host, port))
    };
    let mut line = 1;
    while f.read_line(&mut buffer).unwrap() > 0 {
        {
            if buffer.as_bytes()[0] == b'#' {
                buffer.clear();
                continue;
            }
            let mut s = buffer.split(' ');
            let hosts = s.next();
            let _ = s.next();
            let key = s.next();
            match (hosts, key) {
                (Some(h), Some(k)) => {
                    let host_matches = h.split(',').any(|x| x == host_port);
                    if host_matches {
                        if &try!(parse_public_key_base64(k)) == pubkey {
                            return Ok(true);
                        } else {
                            return Err(Error::KeyChanged(line));
                        }
                    }

                }
                _ => {}
            }
        }
        buffer.clear();
        line += 1;
    }
    Ok(false)
}


/// Record a host's public key into the user's known_hosts file.
#[cfg(target_os = "windows")]
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<()> {
    if let Some(mut known_host_file) = dirs::home_dir() {
        known_host_file.push("ssh");
        known_host_file.push("known_hosts");
        learn_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

/// Record a host's public key into the user's known_hosts file.
#[cfg(not(target_os = "windows"))]
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<()> {
    if let Some(mut known_host_file) = dirs::home_dir() {
        known_host_file.push(".ssh");
        known_host_file.push("known_hosts");
        learn_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

/// Check whether the host is known, from its standard location.
#[cfg(target_os = "windows")]
pub fn check_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<bool> {
    if let Some(mut known_host_file) = dirs::home_dir() {
        known_host_file.push("ssh");
        known_host_file.push("known_hosts");
        check_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

/// Check whether the host is known, from its standard location.
#[cfg(not(target_os = "windows"))]
pub fn check_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<bool> {
    if let Some(mut known_host_file) = dirs::home_dir() {
        known_host_file.push(".ssh");
        known_host_file.push("known_hosts");
        check_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}


#[cfg(test)]
mod test {
    extern crate tempdir;
    use std::fs::File;
    use std::io::Write;
    use futures::Future;
    use super::*;


    const ED25519_KEY: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDLGyfA39
J2FcJygtYqi5ISAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIN+Wjn4+4Fcvl2Jl
KpggT+wCRxpSvtqqpVrQrKN1/A22AAAAkOHDLnYZvYS6H9Q3S3Nk4ri3R2jAZlQlBbUos5
FkHpYgNw65KCWCTXtP7ye2czMC3zjn2r98pJLobsLYQgRiHIv/CUdAdsqbvMPECB+wl/UQ
e+JpiSq66Z6GIt0801skPh20jxOO3F52SoX1IeO5D5PXfZrfSZlw6S8c7bwyp2FHxDewRx
7/wNsnDM0T7nLv/Q==
-----END OPENSSH PRIVATE KEY-----";


    #[test]
    fn test_decode_secret_key() {
        extern crate env_logger;
        env_logger::init().unwrap_or(());
        decode_secret_key(ED25519_KEY, Some(b"blabla")).unwrap();
    }

    #[test]
    fn test_check_known_hosts() {
        env_logger::init().unwrap_or(());
        let dir = tempdir::TempDir::new("thrussh").unwrap();
        let path = dir.path().join("known_hosts");
        {
            let mut f = File::create(&path).unwrap();
            f.write(b"[localhost]:13265 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n#pijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\npijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\n").unwrap();
        }

        // Valid key, non-standard port.
        let host = "localhost";
        let port = 13265;
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ")
            .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Valid key, several hosts, port 22
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X")
            .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Now with the key in a comment above, check that it's not recognized
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X")
            .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).is_err());
    }

    #[test]
    fn test_nikao() {
        env_logger::init().unwrap_or(());
        let key = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAw/FG8YLVoXhsUVZcWaY7iZekMxQ2TAfSVh0LTnRuzsumeLhb
0fh4scIt4C4MLwpGe/u3vj290C28jLkOtysqnIpB4iBUrFNRmEz2YuvjOzkFE8Ju
0l1VrTZ9APhpLZvzT2N7YmTXcLz1yWopCe4KqTHczEP4lfkothxEoACXMaxezt5o
wIYfagDaaH6jXJgJk1SQ5VYrROVpDjjX8/Zg01H1faFQUikYx0M8EwL1fY5B80Hd
6DYSok8kUZGfkZT8HQ54DBgocjSs449CVqkVoQC1aDB+LZpMWovY15q7hFgfQmYD
qulbZRWDxxogS6ui/zUR2IpX7wpQMKKkBS1qdQIDAQABAoIBAQCodpcCKfS2gSzP
uapowY1KvP/FkskkEU18EDiaWWyzi1AzVn5LRo+udT6wEacUAoebLU5K2BaMF+aW
Lr1CKnDWaeA/JIDoMDJk+TaU0i5pyppc5LwXTXvOEpzi6rCzL/O++88nR4AbQ7sm
Uom6KdksotwtGvttJe0ktaUi058qaoFZbels5Fwk5bM5GHDdV6De8uQjSfYV813P
tM/6A5rRVBjC5uY0ocBHxPXkqAdHfJuVk0uApjLrbm6k0M2dg1X5oyhDOf7ZIzAg
QGPgvtsVZkQlyrD1OoCMPwzgULPXTe8SktaP9EGvKdMf5kQOqUstqfyx+E4OZa0A
T82weLjBAoGBAOUChhaLQShL3Vsml/Nuhhw5LsxU7Li34QWM6P5AH0HMtsSncH8X
ULYcUKGbCmmMkVb7GtsrHa4ozy0fjq0Iq9cgufolytlvC0t1vKRsOY6poC2MQgaZ
bqRa05IKwhZdHTr9SUwB/ngtVNWRzzbFKLkn2W5oCpQGStAKqz3LbKstAoGBANsJ
EyrXPbWbG+QWzerCIi6shQl+vzOd3cxqWyWJVaZglCXtlyySV2eKWRW7TcVvaXQr
Nzm/99GNnux3pUCY6szy+9eevjFLLHbd+knzCZWKTZiWZWr503h/ztfFwrMzhoAh
z4nukD/OETugPvtG01c2sxZb/F8LH9KORznhlSlpAoGBAJnqg1J9j3JU4tZTbwcG
fo5ThHeCkINp2owPc70GPbvMqf4sBzjz46QyDaM//9SGzFwocplhNhaKiQvrzMnR
LSVucnCEm/xdXLr/y6S6tEiFCwnx3aJv1uQRw2bBYkcDmBTAjVXPdUcyOHU+BYXr
Jv6ioMlKlel8/SUsNoFWypeVAoGAXhr3Bjf1xlm+0O9PRyZjQ0RR4DN5eHbB/XpQ
cL8hclsaK3V5tuek79JL1f9kOYhVeVi74G7uzTSYbCY3dJp+ftGCjDAirNEMaIGU
cEMgAgSqs/0h06VESwg2WRQZQ57GkbR1E2DQzuj9FG4TwSe700OoC9o3gqon4PHJ
/j9CM8kCgYEAtPJf3xaeqtbiVVzpPAGcuPyajTzU0QHPrXEl8zr/+iSK4Thc1K+c
b9sblB+ssEUQD5IQkhTWcsXdslINQeL77WhIMZ2vBAH8Hcin4jgcLmwUZfpfnnFs
QaChXiDsryJZwsRnruvMRX9nedtqHrgnIsJLTXjppIhGhq5Kg4RQfOU=
-----END RSA PRIVATE KEY-----
";
        decode_secret_key(key, None).unwrap();
    }

    pub const PKCS8_RSA: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwBGetHjW+3bDQpVktdemnk7JXgu1NBWUM+ysifYLDBvJ9ttX
GNZSyQKA4v/dNr0FhAJ8I9BuOTjYCy1YfKylhl5D/DiSSXFPsQzERMmGgAlYvU2U
+FTxpBC11EZg69CPVMKKevfoUD+PZA5zB7Hc1dXFfwqFc5249SdbAwD39VTbrOUI
WECvWZs6/ucQxHHXP2O9qxWqhzb/ddOnqsDHUNoeceiNiCf2anNymovrIMjAqq1R
t2UP3f06/Zt7Jx5AxKqS4seFkaDlMAK8JkEDuMDOdKI36raHkKanfx8CnGMSNjFQ
QtvnpD8VSGkDTJN3Qs14vj2wvS477BQXkBKN1QIDAQABAoIBABb6xLMw9f+2ENyJ
hTggagXsxTjkS7TElCu2OFp1PpMfTAWl7oDBO7xi+UqvdCcVbHCD35hlWpqsC2Ui
8sBP46n040ts9UumK/Ox5FWaiuYMuDpF6vnfJ94KRcb0+KmeFVf9wpW9zWS0hhJh
jC+yfwpyfiOZ/ad8imGCaOguGHyYiiwbRf381T/1FlaOGSae88h+O8SKTG1Oahq4
0HZ/KBQf9pij0mfVQhYBzsNu2JsHNx9+DwJkrXT7K9SHBpiBAKisTTCnQmS89GtE
6J2+bq96WgugiM7X6OPnmBmE/q1TgV18OhT+rlvvNi5/n8Z1ag5Xlg1Rtq/bxByP
CeIVHsECgYEA9dX+LQdv/Mg/VGIos2LbpJUhJDj0XWnTRq9Kk2tVzr+9aL5VikEb
09UPIEa2ToL6LjlkDOnyqIMd/WY1W0+9Zf1ttg43S/6Rvv1W8YQde0Nc7QTcuZ1K
9jSSP9hzsa3KZtx0fCtvVHm+ac9fP6u80tqumbiD2F0cnCZcSxOb4+UCgYEAyAKJ
70nNKegH4rTCStAqR7WGAsdPE3hBsC814jguplCpb4TwID+U78Xxu0DQF8WtVJ10
SJuR0R2q4L9uYWpo0MxdawSK5s9Am27MtJL0mkFQX0QiM7hSZ3oqimsdUdXwxCGg
oktxCUUHDIPJNVd4Xjg0JTh4UZT6WK9hl1zLQzECgYEAiZRCFGc2KCzVLF9m0cXA
kGIZUxFAyMqBv+w3+zq1oegyk1z5uE7pyOpS9cg9HME2TAo4UPXYpLAEZ5z8vWZp
45sp/BoGnlQQsudK8gzzBtnTNp5i/MnnetQ/CNYVIVnWjSxRUHBqdMdRZhv0/Uga
e5KA5myZ9MtfSJA7VJTbyHUCgYBCcS13M1IXaMAt3JRqm+pftfqVs7YeJqXTrGs/
AiDlGQigRk4quFR2rpAV/3rhWsawxDmb4So4iJ16Wb2GWP4G1sz1vyWRdSnmOJGC
LwtYrvfPHegqvEGLpHa7UsgDpol77hvZriwXwzmLO8A8mxkeW5dfAfpeR5o+mcxW
pvnTEQKBgQCKx6Ln0ku6jDyuDzA9xV2/PET5D75X61R2yhdxi8zurY/5Qon3OWzk
jn/nHT3AZghGngOnzyv9wPMKt9BTHyTB6DlB6bRVLDkmNqZh5Wi8U1/IjyNYI0t2
xV/JrzLAwPoKk3bkqys3bUmgo6DxVC/6RmMwPQ0rmpw78kOgEej90g==
-----END RSA PRIVATE KEY-----
";

    #[test]
    fn test_loewenheim() {
        env_logger::init().unwrap_or(());
        let key = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,80E4FCAD049EE007CCE1C65D52CDB87A

ZKBKtex8+DA/d08TTPp4vY8RV+r+1nUC1La+r0dSiXsfunRNDPcYhHbyA/Fdr9kQ
+d1/E3cEb0k2nq7xYyMzy8hpNp/uHu7UfllGdaBusiPjHR+feg6AQfbM0FWpdGzo
9l/Vho5Ocw8abQq1Q9aPW5QQXBURC7HtCQXbpuYjUAQBeea1LzPCw6UIF80GUUkY
1AycXxVfx1AeURAKTZR4hsxC5pqI4yhAvVNXxP+tTTa9NE8lOP0yqVNurfIqyAnp
5ELMwNdHXZyUcT+EH5PsC69ocQgEZqLs0chvke62woMOjeSpsW5cIjGohW9lOD1f
nJkECVZ50kE0SDvcL4Y338tHwMt7wdwdj1dkAWSUjAJT4ShjqV/TzaLAiNAyRxLl
cm3mAccaFIIBZG/bPLGI0B5+mf9VExXGJrbGlvURhtE3nwmjLg1vT8lVfqbyL3a+
0tFvmDYn71L97t/3hcD2tVnKLv9g8+/OCsUAk3+/0eS7D6GpmlOMRHdLLUHc4SOm
bIDT/dE6MjsCSm7n/JkTb8P+Ta1Hp94dUnX4pfjzZ+O8V1H8wv7QW5KsuJhJ8cn4
eS3BEgNH1I4FCCjLsZdWve9ehV3/19WXh+BF4WXFq9b3plmfJgTiZslvjy4dgThm
OhEK44+fN1UhzguofxTR4Maz7lcehQxGAxp14hf1EnaAEt3LVjEPEShgK5dx1Ftu
LWFz9nR4vZcMsaiszElrevqMhPQHXY7cnWqBenkMfkdcQDoZjKvV86K98kBIDMu+
kf855vqRF8b2n/6HPdm3eqFh/F410nSB0bBSglUfyOZH1nS+cs79RQZEF9fNUmpH
EPQtQ/PALohicj9Vh7rRaMKpsORdC8/Ahh20s01xL6siZ334ka3BLYT94UG796/C
4K1S2kPdUP8POJ2HhaK2l6qaG8tcEX7HbwwZeKiEHVNvWuIGQO9TiDONLycp9x4y
kNM3sv2pI7vEhs7d2NapWgNha1RcTSv0CQ6Th/qhGo73LBpVmKwombVImHAyMGAE
aVF32OycVd9c9tDgW5KdhWedbeaxD6qkSs0no71083kYIS7c6iC1R3ZeufEkMhmx
dwrciWTJ+ZAk6rS975onKz6mo/4PytcCY7Df/6xUxHF3iJCnuK8hNpLdJcdOiqEK
zj/d5YGyw3J2r+NrlV1gs3FyvR3eMCWWH2gpIQISBpnEANY40PxA/ogH+nCUvI/O
n8m437ZeLTg6lnPqsE4nlk2hUEwRdy/SVaQURbn7YlcYIt0e81r5sBXb4MXkLrf0
XRWmpSggdcaaMuXi7nVSdkgCMjGP7epS7HsfP46OrTtJLHn5LxvdOEaW53nPOVQg
/PlVfDbwWl8adE3i3PDQOw9jhYXnYS3sv4R8M8y2GYEXbINrTJyUGrlNggKFS6oh
Hjgt0gsM2N/D8vBrQwnRtyymRnFd4dXFEYKAyt+vk0sa36eLfl0z6bWzIchkJbdu
raMODVc+NiJE0Qe6bwAi4HSpJ0qw2lKwVHYB8cdnNVv13acApod326/9itdbb3lt
KJaj7gc0n6gmKY6r0/Ddufy1JZ6eihBCSJ64RARBXeg2rZpyT+xxhMEZLK5meOeR
-----END RSA PRIVATE KEY-----
";
        decode_secret_key(key, Some(b"passphrase")).unwrap();
    }

    #[test]
    fn test_pkcs8() {
        env_logger::init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_RSA, Some(b"blabla")).unwrap();
    }

    const PKCS8_ENCRYPTED: &'static str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITo1O0b8YrS0CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBtLH4T1KOfo1GGr7salhR8BIIE
0KN9ednYwcTGSX3hg7fROhTw7JAJ1D4IdT1fsoGeNu2BFuIgF3cthGHe6S5zceI2
MpkfwvHbsOlDFWMUIAb/VY8/iYxhNmd5J6NStMYRC9NC0fVzOmrJqE1wITqxtORx
IkzqkgFUbaaiFFQPepsh5CvQfAgGEWV329SsTOKIgyTj97RxfZIKA+TR5J5g2dJY
j346SvHhSxJ4Jc0asccgMb0HGh9UUDzDSql0OIdbnZW5KzYJPOx+aDqnpbz7UzY/
P8N0w/pEiGmkdkNyvGsdttcjFpOWlLnLDhtLx8dDwi/sbEYHtpMzsYC9jPn3hnds
TcotqjoSZ31O6rJD4z18FOQb4iZs3MohwEdDd9XKblTfYKM62aQJWH6cVQcg+1C7
jX9l2wmyK26Tkkl5Qg/qSfzrCveke5muZgZkFwL0GCcgPJ8RixSB4GOdSMa/hAMU
kvFAtoV2GluIgmSe1pG5cNMhurxM1dPPf4WnD+9hkFFSsMkTAuxDZIdDk3FA8zof
Yhv0ZTfvT6V+vgH3Hv7Tqcxomy5Qr3tj5vvAqqDU6k7fC4FvkxDh2mG5ovWvc4Nb
Xv8sed0LGpYitIOMldu6650LoZAqJVv5N4cAA2Edqldf7S2Iz1QnA/usXkQd4tLa
Z80+sDNv9eCVkfaJ6kOVLk/ghLdXWJYRLenfQZtVUXrPkaPpNXgD0dlaTN8KuvML
Uw/UGa+4ybnPsdVflI0YkJKbxouhp4iB4S5ACAwqHVmsH5GRnujf10qLoS7RjDAl
o/wSHxdT9BECp7TT8ID65u2mlJvH13iJbktPczGXt07nBiBse6OxsClfBtHkRLzE
QF6UMEXsJnIIMRfrZQnduC8FUOkfPOSXc8r9SeZ3GhfbV/DmWZvFPCpjzKYPsM5+
N8Bw/iZ7NIH4xzNOgwdp5BzjH9hRtCt4sUKVVlWfEDtTnkHNOusQGKu7HkBF87YZ
RN/Nd3gvHob668JOcGchcOzcsqsgzhGMD8+G9T9oZkFCYtwUXQU2XjMN0R4VtQgZ
rAxWyQau9xXMGyDC67gQ5xSn+oqMK0HmoW8jh2LG/cUowHFAkUxdzGadnjGhMOI2
zwNJPIjF93eDF/+zW5E1l0iGdiYyHkJbWSvcCuvTwma9FIDB45vOh5mSR+YjjSM5
nq3THSWNi7Cxqz12Q1+i9pz92T2myYKBBtu1WDh+2KOn5DUkfEadY5SsIu/Rb7ub
5FBihk2RN3y/iZk+36I69HgGg1OElYjps3D+A9AjVby10zxxLAz8U28YqJZm4wA/
T0HLxBiVw+rsHmLP79KvsT2+b4Diqih+VTXouPWC/W+lELYKSlqnJCat77IxgM9e
YIhzD47OgWl33GJ/R10+RDoDvY4koYE+V5NLglEhbwjloo9Ryv5ywBJNS7mfXMsK
/uf+l2AscZTZ1mhtL38efTQCIRjyFHc3V31DI0UdETADi+/Omz+bXu0D5VvX+7c6
b1iVZKpJw8KUjzeUV8yOZhvGu3LrQbhkTPVYL555iP1KN0Eya88ra+FUKMwLgjYr
JkUx4iad4dTsGPodwEP/Y9oX/Qk3ZQr+REZ8lg6IBoKKqqrQeBJ9gkm1jfKE6Xkc
Cog3JMeTrb3LiPHgN6gU2P30MRp6L1j1J/MtlOAr5rux
-----END ENCRYPTED PRIVATE KEY-----";

    #[test]
    fn test_pkcs8_encrypted() {
        env_logger::init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_ENCRYPTED, Some(b"blabla")).unwrap();
    }

    fn test_client_agent(key: key::KeyPair) {
        env_logger::init().unwrap_or(());
        use std::process::Command;
        let dir = tempdir::TempDir::new("thrussh").unwrap();
        let agent_path = dir.path().join("agent");
        let mut agent = Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-d")
            .spawn()
            .expect("failed to execute process");

        std::thread::sleep(std::time::Duration::from_millis(10));
        tokio::run(futures::lazy(move || {
            let public = key.clone_public_key();
            tokio_uds::UnixStream::connect(&agent_path).from_err().and_then(move |stream| {
                agent::client::AgentClient::connect(stream)
                    .add_identity(&key, &[])
                    .and_then(move |(client, _)| {
                        debug!("connected");
                        client.request_identities().and_then(move |(client, _)| {
                            client.sign_request(&public, b"blabla").and_then(|(_, sig)| {
                                sig.unwrap();
                                futures::finished(())
                            })
                        })
                    })
            }).map_err(|_| ())
        }));
        agent.kill().unwrap();
        agent.wait().unwrap();
    }

    #[test]
    fn test_client_agent_ed25519() {
        let key = decode_secret_key(ED25519_KEY, Some(b"blabla")).unwrap();
        test_client_agent(key)
    }

    #[test]
    fn test_client_agent_rsa() {
        let key = decode_secret_key(PKCS8_ENCRYPTED, Some(b"blabla")).unwrap();
        test_client_agent(key)
    }

    #[test]
    fn test_agent() {
        env_logger::init().unwrap_or(());
        let dir = tempdir::TempDir::new("thrussh").unwrap();
        let agent_path = dir.path().join("agent");

        let mut core = tokio::runtime::Runtime::new().unwrap();
        use agent;
        let listener = tokio_uds::UnixListener::bind(&agent_path).unwrap().incoming();

        struct F(bool);
        impl std::convert::From<bool> for F {
            fn from(e: bool) -> Self {
                F(e)
            }
        }
        impl futures::Future for F {
            type Item = bool;
            type Error = Error;
            fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
                Ok(futures::Async::Ready(self.0))
            }
        }
        #[derive(Clone)]
        struct X{}
        impl agent::server::Agent for X {
            type F = F;
            fn confirm(&self, _: &key::KeyPair) -> Self::F {
                F(true)
            }
        }

        core.spawn(
            agent::server::AgentServer::new(listener, X{})
                .map_err(|e| error!("{:?}", e))
        );

        let key = decode_secret_key(PKCS8_ENCRYPTED, Some(b"blabla")).unwrap();
        let public = key.clone_public_key();
        core.block_on(
            tokio_uds::UnixStream::connect(&agent_path).from_err().and_then(move |stream| {
                agent::client::AgentClient::connect(stream)
                    .add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }]).and_then(move |(client, _)| {
                        client.request_identities().and_then(move |(client, _)| {
                            client.sign_request(&public, b"blabla").and_then(|(_, sig)| {
                                let sig = sig.unwrap();
                                println!("sig = {:?}", sig);
                                futures::finished(())
                            })
                        })
                    })
            })
        ).unwrap();
    }

}
