use dope_quic::conn::wire::ingress::events;
use dope_quic::errors::SendFailure;
use dope_quic::proto::datagram::Packet;
use dope_quic::stream::{release, send::admit};
use o3::buffer::hold::{self, evidence};
use std::convert::Infallible;

pub fn rejection<'a>(failure: &'a SendFailure<Packet<'_>>) -> SendFailure<&'a [u8]> {
    match failure {
        SendFailure::Admission(packet, cause) => {
            SendFailure::Admission(packet.payload(), cause.clone())
        }
        SendFailure::Closed(packet) => SendFailure::Closed(packet.payload()),
        SendFailure::Full(packet) => SendFailure::Full(packet.payload()),
        SendFailure::TooLarge(packet) => SendFailure::TooLarge(packet.payload()),
        SendFailure::Unsupported(packet) => SendFailure::Unsupported(packet.payload()),
        SendFailure::Crypto(cause) => SendFailure::Crypto(cause.clone()),
    }
}

pub struct Capture<'a>(pub &'a mut Vec<release::Event>, pub &'a mut Option<String>);

impl release::Sink for Capture<'_> {
    type Mode = evidence::On;

    fn release(&mut self, charge: hold::Charge, source: admit::Source, cause: release::Cause) {
        self.0.push(release::Event {
            source,
            charge,
            cause,
        });
    }
}

impl events::Sink for Capture<'_> {
    type Observer<'a>
        = Infallible
    where
        Self: 'a;

    fn certificate(&mut self, cause: &rustls::Error) {
        *self.1 = Some(format!("{cause:?}"));
    }

    fn observer(&mut self) -> Option<Self::Observer<'_>> {
        None
    }
}
