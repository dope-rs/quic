pub(super) mod events;
pub(super) mod receive;
pub(super) mod table;
pub(super) mod transmit;

use crate::conn::control;
use crate::conn::event_queue;
use crate::conn::peer;
use crate::conn::recv;
use crate::conn::retired;
use crate::conn::send;
use crate::conn::stream_journal;
use crate::stream;
use std::ops;

#[derive(Clone, Copy)]
pub(super) enum Access {
    Receive,
    Send,
}

pub(super) struct Setup {
    pub(super) is_client: bool,
    pub(super) event_capacity: usize,
    pub(super) local_capacity: [usize; 2],
    pub(super) initial_max_streams: [u64; 2],
    pub(super) local_max_data: u64,
    pub(super) local_initial_stream_data: [u64; 3],
    pub(super) stream_journal_capacity: usize,
    pub(super) receive_segment_capacity: usize,
}

pub(super) struct Streams<B: stream::ReceiveBuffer> {
    pub(super) state: State<B>,
    pub(super) events: event_queue::Events,
}

#[derive(Default)]
#[repr(transparent)]
pub(super) struct ReceiveCredits(u8);

const _: () = assert!(std::mem::size_of::<ReceiveCredits>() == 1);

pub(super) struct State<B: stream::ReceiveBuffer> {
    pub(super) transmit: TransmitState,
    pub(super) receive: ReceiveState<B>,
    pub(super) peer_initiated: PeerInitiated,
    pub(super) local_initiated: LocalInitiated,
    pub(super) receive_credits: ReceiveCredits,
}

impl<B: stream::ReceiveBuffer> ops::Deref for Streams<B> {
    type Target = State<B>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<B: stream::ReceiveBuffer> ops::DerefMut for Streams<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

pub(super) struct TransmitState {
    pub(super) scratch_pending: Vec<send::Handle>,
    pub(super) schedule: send::Schedule,
    pub(super) deliveries: stream_journal::journal::Journal,
    pub(super) map: send::Map,
    pub(super) peer_data_credit: send::Credit<control::kind::DataBlocked>,
    pub(super) peer_total_sent: u64,
}

pub(super) struct ReceiveState<B: stream::ReceiveBuffer> {
    pub(super) map: recv::Map<B>,
    pub(super) ranges: crate::range_buffer::Arena<B>,
    pub(super) control_schedule: recv::ControlSchedule,
    pub(super) retired: retired::streams::Streams,
    pub(super) local_max_data: u64,
    pub(super) total: u64,
    pub(super) initial_stream_data: [u64; 3],
    pub(super) max_data: Option<control::OwnerKey<control::kind::MaxData>>,
}

pub(super) struct PeerInitiated {
    pub(super) opened: peer::Streams,
    pub(super) max: [u64; 2],
    pub(super) initial_max: [u64; 2],
    pub(super) closed: [u64; 2],
    pub(super) max_streams: [Option<control::OwnerKey<control::kind::MaxStreams>>; 2],
}

pub(super) struct LocalInitiated {
    pub(super) next: [u64; 2],
    pub(super) peer_max: [u64; 2],
    pub(super) opened: [u64; 2],
    pub(super) active: [u64; 2],
    pub(super) capacity: [u64; 2],
}

impl<B: stream::ReceiveBuffer> Streams<B> {
    pub(super) fn new(setup: Setup) -> Self {
        let [bidi_capacity, uni_capacity] = setup.local_capacity;
        let send_capacity = bidi_capacity
            .checked_add(uni_capacity)
            .and_then(|capacity| capacity.checked_add(setup.initial_max_streams[0] as usize))
            .expect("validated stream limits fit send-state capacity");
        let recv_capacity = bidi_capacity
            .checked_add(setup.initial_max_streams[0] as usize)
            .and_then(|capacity| capacity.checked_add(setup.initial_max_streams[1] as usize))
            .expect("validated stream limits fit receive-state capacity");
        Self {
            state: State {
                transmit: TransmitState {
                    scratch_pending: Vec::with_capacity(crate::conn::STREAM_SCHEDULE_CAPACITY),
                    schedule: send::Schedule::new(),
                    deliveries: stream_journal::journal::Journal::new(
                        setup.stream_journal_capacity,
                    ),
                    map: send::Map::new(send_capacity),
                    peer_data_credit: send::Credit::new(0),
                    peer_total_sent: 0,
                },
                receive: ReceiveState {
                    map: recv::Map::new(recv_capacity),
                    ranges: crate::range_buffer::Arena::with_capacity(
                        setup.receive_segment_capacity,
                    ),
                    control_schedule: recv::ControlSchedule::new(),
                    retired: retired::streams::Streams::new(
                        bidi_capacity,
                        setup.initial_max_streams[0] as usize,
                        setup.initial_max_streams[1] as usize,
                    ),
                    local_max_data: setup.local_max_data,
                    total: 0,
                    initial_stream_data: setup.local_initial_stream_data,
                    max_data: None,
                },
                peer_initiated: PeerInitiated {
                    opened: peer::Streams::default(),
                    max: setup.initial_max_streams,
                    initial_max: setup.initial_max_streams,
                    closed: [0; 2],
                    max_streams: [None; 2],
                },
                local_initiated: LocalInitiated {
                    next: if setup.is_client { [0, 2] } else { [1, 3] },
                    peer_max: [0; 2],
                    opened: [0; 2],
                    active: [0; 2],
                    capacity: [bidi_capacity as u64, uni_capacity as u64],
                },
                receive_credits: ReceiveCredits::default(),
            },
            events: event_queue::Events::new(setup.event_capacity),
        }
    }
}
