pub mod control;
pub mod receive;
pub mod send;

use dope_quic::conn::output::transmit;
use dope_quic::conn::wire::{packet::Batch, path::probe};
use dope_quic::{conn, conn::Connection};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum Error {
    Deadline(Instant, Duration),
    Probe(probe::Error),
    Output(transmit::Error),
    Input(super::Transfer),
    Unsettled,
}

#[derive(Default)]
pub struct Drain {
    pub client: Batch,
    pub server: Batch,
}

impl Drain {
    pub fn try_exchange(
        &mut self,
        client: &mut Connection,
        server: &mut Connection,
        work: &mut conn::Workspace,
        ready_at: Instant,
    ) -> Result<Instant, Error> {
        let sent_at = client.view().recovery().send_at(ready_at);
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut self.client, sent_at, 4, 1_200)
            })
            .map_err(Error::Output)?;
        super::Receiver::receive_all(&mut *server, work, &mut self.client, sent_at)
            .map_err(Error::Input)?;
        let delay = Duration::from_millis(1);
        let reply_at = sent_at
            .checked_add(delay)
            .ok_or(Error::Deadline(sent_at, delay))?;
        let reply_at = server.view().recovery().send_at(reply_at);
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut self.server, reply_at, 4, 1_200)
            })
            .map_err(Error::Output)?;
        super::Receiver::receive_all(client, work, &mut self.server, reply_at)
            .map_err(Error::Input)?;
        Ok(reply_at)
    }
}

pub struct Exchange {
    pub pair: super::Pair,
    requests: Batch,
    pub responses: Batch,
    pub at: Instant,
}

impl Exchange {
    pub fn try_new() -> Result<Self, super::Setup> {
        let pair = super::Pair::try_default()?;
        let at = Instant::now();
        let delay = Duration::from_secs(20);
        Ok(Self {
            pair,
            requests: Batch::default(),
            responses: Batch::default(),
            at: at
                .checked_add(delay)
                .ok_or(super::Setup::Deadline(at, delay))?,
        })
    }

    pub fn try_probe(&mut self, tokens: &[[u8; 8]]) -> Result<(), Error> {
        let delay = Duration::from_secs(1);
        self.at = self
            .at
            .checked_add(delay)
            .ok_or(Error::Deadline(self.at, delay))?;
        for &token in tokens {
            self.pair
                .client
                .with_scope(|mut scope| scope.path().try_probe(token))
                .map_err(Error::Probe)?;
        }
        self.try_send()
    }

    pub fn try_send(&mut self) -> Result<(), Error> {
        self.pair
            .client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut self.requests, self.at, 64, 1200)
            })
            .map_err(Error::Output)?;
        super::Receiver::receive_all(
            &mut self.pair.server,
            &mut self.pair.work,
            &mut self.requests,
            self.at,
        )
        .map_err(Error::Input)
    }

    pub fn try_respond(&mut self) -> Result<(), transmit::Error> {
        self.pair.server.with_scope(|mut scope| {
            scope
                .output()
                .send_batch(&mut self.responses, self.at, 64, 1200)
        })
    }

    pub fn try_finish(&mut self) -> Result<(), Error> {
        let delay = Duration::from_millis(50);
        for _ in 0..8 {
            super::Receiver::receive_all(
                &mut self.pair.client,
                &mut self.pair.work,
                &mut self.responses,
                self.at,
            )
            .map_err(Error::Input)?;
            self.at = self
                .at
                .checked_add(delay)
                .ok_or(Error::Deadline(self.at, delay))?;
            self.try_send()?;
            self.at = self
                .at
                .checked_add(delay)
                .ok_or(Error::Deadline(self.at, delay))?;
            self.try_respond().map_err(Error::Output)?;
            if self.responses.is_empty() {
                return Ok(());
            }
        }
        Err(Error::Unsettled)
    }
}
