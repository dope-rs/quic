use dope::core::driver::settings::errors::Claim;
use std::num;

use dope::core::driver::{self, schedule::clock, settings};
use dope::core::io::datagram::payload;
use dope::manifold::{self, network::datagram::plan};

use crate::proto::cid::{Rotation, Schedule};
use crate::proto::datagram::Size;
use crate::runtime::mux::builder;

#[derive(Clone, Copy)]
pub struct Config {
    pub max_conns: usize,
    pub outgoing_capacity: usize,
    pub outgoing_bytes_capacity: usize,
    pub packet_buffer_slots: u32,
    pub packet_buffer_bytes: u32,
    pub cid_rotation: Rotation,
}

/// Invalid relationship in an endpoint capacity plan.
///
/// This is a compact configuration error, not an I/O failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Error {
    Capacity(builder::Error),
    OutgoingBytes { got: usize, min: usize },
    Receive(Claim),
    PacketBytes { got: u32 },
    Datagram(manifold::ConfigError),
}

/// Validated endpoint settings retained after its lower plans are constructed.
#[derive(Clone, Copy)]
pub(crate) struct Validated {
    capacity: builder::Plan,
    receive: settings::Datagram,
    packet: Size,
    cid_rotation: Rotation,
}

/// Single-use validation result carrying one datagram plan's construction inputs.
#[derive(Clone, Copy)]
pub(crate) struct Validation {
    config: Validated,
    datagram: plan::Config,
    slots: num::NonZero<usize>,
}

impl Config {
    /// Driver baseline for a QUIC endpoint with a validated datagram layout.
    pub const fn driver(receive: settings::Datagram) -> settings::Config {
        settings::Config::new(
            settings::QueueLayout::fixed::<256, 1024>(),
            settings::Schedule::DEFAULT,
            settings::FileSlots::fixed::<0, 16>(),
            receive.receive(),
            settings::Domain::ONE,
            settings::Progress::Prompt,
        )
    }

    pub(crate) fn validated(self) -> Result<Validation, Error> {
        let capacity = builder::Plan::try_new(
            self.max_conns,
            self.outgoing_capacity,
            self.outgoing_bytes_capacity,
        )
        .map_err(Error::Capacity)?;
        if self.outgoing_bytes_capacity < 1200 {
            return Err(Error::OutgoingBytes {
                got: self.outgoing_bytes_capacity,
                min: 1200,
            });
        }
        let ring =
            settings::Ring::try_round(self.packet_buffer_slots.max(2)).map_err(Error::Receive)?;
        let entries = ring.buffers().into_nonzero();
        let Some(packet) = Size::new(self.packet_buffer_bytes) else {
            return Err(Error::PacketBytes {
                got: self.packet_buffer_bytes,
            });
        };
        let bytes = num::NonZero::<u16>::from(packet);
        let receive = settings::Datagram::new(ring, payload::Len::from(bytes));
        let datagram =
            plan::Config::new(capacity.outgoing(), capacity.bytes(), capacity.outgoing())
                .map_err(Error::Datagram)?;
        Ok(Validation {
            config: Validated {
                capacity,
                receive,
                packet,
                cid_rotation: self.cid_rotation,
            },
            datagram,
            slots: entries.into(),
        })
    }
}

impl Validated {
    pub(crate) const fn connections(self) -> usize {
        self.capacity.connections()
    }

    pub(crate) const fn capacity(self) -> builder::Plan {
        self.capacity
    }

    pub(crate) const fn receive(self) -> settings::Datagram {
        self.receive
    }

    pub(crate) const fn packet(self) -> Size {
        self.packet
    }

    pub(crate) fn cid_rotation<'d>(
        self,
        driver: &mut driver::Context<'_, 'd>,
    ) -> clock::Bound<'d, Schedule> {
        driver
            .driver_ref()
            .clock()
            .attach(|now| self.cid_rotation.schedule_at(now))
    }
}

impl Validation {
    pub(super) const fn into_parts(self) -> (Validated, plan::Config, num::NonZero<usize>) {
        (self.config, self.datagram, self.slots)
    }
}
