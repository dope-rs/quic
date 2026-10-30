#[derive(Clone, Copy)]
enum Sender {
    Either,
    Server,
}

#[derive(Clone, Copy)]
struct Rule {
    packet_mask: u8,
    sender: Sender,
    probing: bool,
}

impl Rule {
    const fn allows(self, packet: u8, local: Initiator) -> bool {
        self.packet_mask & (1 << packet) != 0
            && match self.sender {
                Sender::Either => true,
                Sender::Server => matches!(local, Initiator::Client),
            }
    }
}

const INITIAL: u8 = 1 << 0;
const HANDSHAKE: u8 = 1 << 1;
const ZERO_RTT: u8 = 1 << 2;
const ONE_RTT: u8 = 1 << 3;
const ALL_PACKETS: u8 = INITIAL | HANDSHAKE | ZERO_RTT | ONE_RTT;
const APPLICATION_DATA: u8 = ZERO_RTT | ONE_RTT;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    Padding,
    Ping,
    Ack,
    Crypto,
    NewToken,
    Datagram,
    HandshakeDone,
    TransportClose,
    ApplicationClose,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    Stream,
    ResetStream,
    StopSending,
    MaxData,
    MaxStreamData,
    DataBlocked,
    StreamDataBlocked,
    MaxStreams,
    StreamsBlocked,
}

impl Kind {
    pub(crate) const COUNT: usize = Self::StreamsBlocked as usize + 1;
    const RULES: [Rule; Self::COUNT] = [
        Rule {
            packet_mask: ALL_PACKETS,
            sender: Sender::Either,
            probing: true,
        },
        Rule {
            packet_mask: ALL_PACKETS,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: INITIAL | HANDSHAKE | ONE_RTT,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: INITIAL | HANDSHAKE | ONE_RTT,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: ONE_RTT,
            sender: Sender::Server,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: ONE_RTT,
            sender: Sender::Server,
            probing: false,
        },
        Rule {
            packet_mask: ALL_PACKETS,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: ONE_RTT,
            sender: Sender::Either,
            probing: true,
        },
        Rule {
            packet_mask: ONE_RTT,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: ONE_RTT,
            sender: Sender::Either,
            probing: true,
        },
        Rule {
            packet_mask: ONE_RTT,
            sender: Sender::Either,
            probing: true,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
        Rule {
            packet_mask: APPLICATION_DATA,
            sender: Sender::Either,
            probing: false,
        },
    ];

    const fn rule(self) -> Rule {
        Self::RULES[self as usize]
    }

    pub(crate) const fn is_allowed(self, packet: u8, local: Initiator) -> bool {
        self.rule().allows(packet, local)
    }

    pub(crate) const fn is_probing(self) -> bool {
        self.rule().probing
    }
}

/// Audits the RFC 9000 and RFC 9221 packet-space matrix at compile time.
const _: () = {
    let expected = [
        ALL_PACKETS,
        ALL_PACKETS,
        INITIAL | HANDSHAKE | ONE_RTT,
        INITIAL | HANDSHAKE | ONE_RTT,
        ONE_RTT,
        APPLICATION_DATA,
        ONE_RTT,
        ALL_PACKETS,
        APPLICATION_DATA,
        ONE_RTT,
        ONE_RTT,
        ONE_RTT,
        ONE_RTT,
        APPLICATION_DATA,
        APPLICATION_DATA,
        APPLICATION_DATA,
        APPLICATION_DATA,
        APPLICATION_DATA,
        APPLICATION_DATA,
        APPLICATION_DATA,
        APPLICATION_DATA,
        APPLICATION_DATA,
    ];
    assert!(expected.len() == Kind::COUNT);
    let mut index = 0;
    while index < expected.len() {
        assert!(Kind::RULES[index].packet_mask == expected[index]);
        index += 1;
    }

    assert!(Kind::NewToken.is_allowed(3, Initiator::Client));
    assert!(!Kind::NewToken.is_allowed(3, Initiator::Server));
    assert!(Kind::HandshakeDone.is_allowed(3, Initiator::Client));
    assert!(!Kind::HandshakeDone.is_allowed(3, Initiator::Server));
};
use crate::wire::stream::Initiator;
