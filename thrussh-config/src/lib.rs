extern crate tokio;
extern crate futures;
extern crate thrussh;
extern crate regex;
#[macro_use]
extern crate log;
extern crate dirs;

use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    HostNotFound,
    NoHome
}

impl std::convert::From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IO(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::IO(ref e) => e.fmt(f),
            Error::HostNotFound => write!(f, "Host not found"),
            Error::NoHome => write!(f, "No home directory"),
        }
    }
}
impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IO(ref e) => e.description(),
            Error::HostNotFound => "Host not found",
            Error::NoHome => "No home directory",
        }
    }
    fn cause(&self) -> Option<&dyn std::error::Error> {
        if let Error::IO(ref e) = *self {
            Some(e)
        } else {
            None
        }
    }
}

mod proxy;
pub use proxy::*;

#[derive(Debug, Default)]
pub struct Config {
    pub user: Option<String>,
    pub host_name: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_command: Option<String>,
    pub add_keys_to_agent: AddKeysToAgent,
}

impl Config {
    pub fn update_proxy_command(&mut self) {
        if let Some(ref h) = self.host_name {
            if let Some(ref mut prox) = self.proxy_command {
                *prox = prox.replace("%h", h);
            }
        }
        if let Some(ref p) = self.port {
            if let Some(ref mut prox) = self.proxy_command {
                *prox = prox.replace("%p", &format!("{}", p));
            }
        }
    }
}

pub fn parse_home(host: &str) -> Result<Config, Error> {
    let mut home = if let Some(home) = dirs::home_dir() {
        home
    } else {
        return Err(Error::NoHome)
    };
    home.push(".ssh");
    home.push("config");
    parse_path(&home, host)
}

pub fn parse_path<P:AsRef<Path>>(path: P, host: &str) -> Result<Config, Error> {
    let mut s = String::new();
    let mut b = std::fs::File::open(path)?;
    b.read_to_string(&mut s)?;
    parse(&s, host)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddKeysToAgent {
    Yes,
    Confirm,
    Ask,
    No
}

impl Default for AddKeysToAgent {
    fn default() -> Self {
        AddKeysToAgent::No
    }
}

pub fn parse(file: &str, host: &str) -> Result<Config, Error> {
    let mut config: Option<Config> = None;
    for line in file.lines() {
        let line = line.trim();
        if let Some(n) = line.find(' ') {
            let (key, value) = line.split_at(n);
            let lower = key.to_lowercase();
            if let Some(ref mut config) = config {
                match lower.as_str() {
                    "host" => break,
                    "user" => config.user = Some(value.trim_start().to_string()),
                    "hostname" => config.host_name = Some(value.trim_start().to_string()),
                    "port" => config.port = value.trim_start().parse().ok(),
                    "identityfile" => config.identity_file = Some(value.trim_start().to_string()),
                    "proxycommand" => config.proxy_command = Some(value.trim_start().to_string()),
                    "addkeystoagent" => {
                        match value.to_lowercase().as_str() {
                            "yes" => config.add_keys_to_agent = AddKeysToAgent::Yes,
                            "confirm" => config.add_keys_to_agent = AddKeysToAgent::Confirm,
                            "ask" => config.add_keys_to_agent = AddKeysToAgent::Ask,
                            _ => config.add_keys_to_agent = AddKeysToAgent::No,
                        }
                    },
                    key => {
                        debug!("{:?}", key);
                    }
                }
            } else {
                match lower.as_str() {
                    "host" => {
                        if value.trim_start() == host {
                            config = Some(Config::default())
                        }
                    }
                    _ => {}
                }
            }
        }

    }
    if let Some(config) = config {
        Ok(config)
    } else {
        Err(Error::HostNotFound)
    }
}
