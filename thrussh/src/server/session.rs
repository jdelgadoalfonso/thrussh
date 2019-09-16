use super::*;
use msg;
use thrussh_keys::encoding::Encoding;
use std::sync::Arc;
use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// A connected server session. This type is unique to a client.
pub struct Session {
    pub(crate) common: CommonSession<Arc<Config>>,
    pub(crate) sender: Handle,
    pub(crate) receiver: UnboundedReceiver<Msg>,
}

pub(crate) enum Msg {
    Data {
        data: CryptoVec,
        extended: Option<u32>,
        channel: ChannelId,
    },
    Eof { channel: ChannelId },
}

#[derive(Clone)]
/// Handle to a session, used to send messages to a client outside of
/// the request/response cycle.
pub struct Handle {
    pub(crate) sender: UnboundedSender<Msg>
}

impl Handle {

    /// Send data to the session referenced by this handler.
    pub fn data(&mut self, channel: ChannelId, extended: Option<u32>, data: CryptoVec) -> Result<(), CryptoVec> {
        self.sender.unbounded_send(Msg::Data {
            channel, extended, data
        }).map_err(|e| match e.into_inner() {
            Msg::Data { data, .. } => data,
            _ => unreachable!()
        })
    }

    /// Send EOF to the session referenced by this handler.
    pub fn eof(&mut self, channel: ChannelId) -> Result<(), ()> {
        self.sender.unbounded_send(Msg::Eof { channel })
            .map_err(|_| ())
    }

}

impl Session {
    /// Get a handle to this session.
    pub fn handle(&self) -> Handle {
        self.sender.clone()
    }

    /// Flush the session, i.e. encrypt the pending buffer.
    pub fn flush(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if enc.flush(
                &self.common.config.as_ref().limits,
                &mut (self.common.cipher.lock().unwrap()),
                &self.common.mac,
                &mut self.common.write_buffer,
            )
            {
                if let Some(exchange) = enc.exchange.take() {
                    let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                    kexinit.server_write(
                        &self.common.config.as_ref(),
                        &mut (self.common.cipher.lock().unwrap()),
                        &self.common.mac,
                        &mut self.common.write_buffer,
                    )?;
                    enc.rekey = Some(Kex::KexInit(kexinit))
                }
            }
        }
        Ok(())
    }

    /// Retrieves the configuration of this session.
    pub fn config(&self) -> &Config {
        &self.common.config
    }

    /// Sends a disconnect message.
    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        self.common.disconnect(reason, description, language_tag);
    }

    /// Send a "success" reply to a /global/ request (requests without
    /// a channel number, such as TCP/IP forwarding or
    /// cancelling). Always call this function if the request was
    /// successful (it checks whether the client expects an answer).
    pub fn request_success(&mut self) {
        if self.common.wants_reply {
            if let Some(ref mut enc) = self.common.encrypted {
                self.common.wants_reply = false;
                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
            }
        }
    }

    /// Send a "failure" reply to a global request.
    pub fn request_failure(&mut self) {
        if let Some(ref mut enc) = self.common.encrypted {
            self.common.wants_reply = false;
            push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
        }
    }

    /// Send a "success" reply to a channel request. Always call this
    /// function if the request was successful (it checks whether the
    /// client expects an answer).
    pub fn channel_success(&mut self, channel: ChannelId) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get_mut(&channel) {
                assert!(channel.confirmed);
                if channel.wants_reply {
                    channel.wants_reply = false;
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_SUCCESS);
                        enc.write.push_u32_be(channel.recipient_channel);
                    })
                }
            }
        }
    }

    /// Send a "failure" reply to a global request.
    pub fn channel_failure(&mut self, channel: ChannelId) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get_mut(&channel) {
                assert!(channel.confirmed);
                if channel.wants_reply {
                    channel.wants_reply = false;
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_FAILURE);
                        enc.write.push_u32_be(channel.recipient_channel);
                    })
                }
            }
        }
    }

    /// Send a "failure" reply to a request to open a channel open.
    pub fn channel_open_failure(
        &mut self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::CHANNEL_OPEN_FAILURE);
                enc.write.push_u32_be(channel.0);
                enc.write.push_u32_be(reason as u32);
                enc.write.extend_ssh_string(description.as_bytes());
                enc.write.extend_ssh_string(language.as_bytes());
            })
        }
    }


    /// Close a channel.
    pub fn close(&mut self, channel: ChannelId) {
        self.common.byte(channel, msg::CHANNEL_CLOSE);
    }

    /// Send EOF to a channel
    pub fn eof(&mut self, channel: ChannelId) {
        self.common.byte(channel, msg::CHANNEL_EOF);
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///

    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub fn data(&mut self, channel: ChannelId, extended: Option<u32>, data: &[u8]) -> usize {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.data(channel, extended, data)
        } else {
            unreachable!()
        }
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub fn xon_xoff_request(&mut self, channel: ChannelId, client_can_do: bool) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"xon-xoff");
                    enc.write.push(0);
                    enc.write.push(if client_can_do { 1 } else { 0 });
                })
            }
        }
    }

    /// Send the exit status of a program.
    pub fn exit_status_request(&mut self, channel: ChannelId, exit_status: u32) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exit-status");
                    enc.write.push(0);
                    enc.write.push_u32_be(exit_status)
                })
            }
        }
    }

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub fn exit_signal_request(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        core_dumped: bool,
        error_message: &str,
        language_tag: &str,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exit-signal");
                    enc.write.push(0);
                    enc.write.extend_ssh_string(signal.name().as_bytes());
                    enc.write.push(if core_dumped { 1 } else { 0 });
                    enc.write.extend_ssh_string(error_message.as_bytes());
                    enc.write.extend_ssh_string(language_tag.as_bytes());
                })
            }
        }
    }

    /// Open a TCP/IP forwarding channel, when a connection comes to a
    /// local port for which forwarding has been requested. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub fn channel_open_forwarded_tcpip(
        &mut self,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        let result = if let Some(ref mut enc) = self.common.encrypted {
            match enc.state {
                Some(EncryptedState::Authenticated) => {
                    debug!("sending open request");

                    let sender_channel = enc.new_channel(
                        self.common.config.window_size,
                        self.common.config.maximum_packet_size,
                    );
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"forwarded-tcpip");

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel.0);

                        // window.
                        enc.write.push_u32_be(self.common.config.as_ref().window_size);

                        // max packet size.
                        enc.write.push_u32_be(
                            self.common.config.as_ref().maximum_packet_size,
                        );

                        enc.write.extend_ssh_string(connected_address.as_bytes());
                        enc.write.push_u32_be(connected_port); // sender channel id.
                        enc.write.extend_ssh_string(originator_address.as_bytes());
                        enc.write.push_u32_be(originator_port); // sender channel id.
                    });
                    sender_channel
                }
                _ => return Err(Error::Inconsistent),
            }
        } else {
            return Err(Error::Inconsistent);
        };
        Ok(result)
    }
}
