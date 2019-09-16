use super::*;
use negotiation::Select;
use cipher::CipherPair;
use mac::MacPair;
use negotiation;

use kex;

impl KexInit {
    pub fn client_parse(
        mut self,
        config: &Config,
        cipher: &mut CipherPair,
        mac: &MacPair,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<KexDhDone, Error> {
        debug!("client parse");
        let algo = if self.algo.is_none() {
            // read algorithms from packet.
            self.exchange.server_kex_init.extend(buf);
            super::negotiation::Client::read_kex(buf, &config.preferred)?
        } else {
            return Err(Error::Kex);
        };
        if !self.sent {
            self.client_write(config, cipher, mac, write_buffer)?
        }

        // This function is called from the public API.
        //
        // In order to simplify the public API, we reuse the
        // self.exchange.client_kex buffer to send an extra packet,
        // then truncate that buffer. Without that, we would need an
        // extra buffer.
        let i0 = self.exchange.client_kex_init.len();
        let kex = kex::Algorithm::client_dh(
            algo.kex,
            &mut self.exchange.client_ephemeral,
            &mut self.exchange.client_kex_init,
        )?;

        cipher.write(&self.exchange.client_kex_init[i0..], write_buffer, mac);
        self.exchange.client_kex_init.resize(i0);

        debug!("moving to kexdhdone");
        Ok(KexDhDone {
            exchange: self.exchange,
            names: algo,
            kex: kex,
            key: 0,
            session_id: self.session_id,
        })
    }

    pub fn client_write(
        &mut self,
        config: &Config,
        cipher: &mut CipherPair,
        mac: &MacPair,
        write_buffer: &mut SSHBuffer,
    ) -> Result<(), Error> {
        self.exchange.client_kex_init.clear();
        negotiation::write_kex(
            &config.preferred,
            &mut self.exchange.client_kex_init,
        )?;
        self.sent = true;
        cipher.write(&self.exchange.client_kex_init, write_buffer, mac);
        Ok(())
    }
}
