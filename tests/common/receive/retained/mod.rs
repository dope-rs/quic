pub mod run;

use dope::manifold::app::dispatch;
use dope::runtime::shutdown;
use dope_quic::conn::id;
use dope_quic::conn::life::tls::clients::Authority;
use dope_quic::conn::life::tls::clients::Pool;
use dope_quic::conn::stream::Event;
use dope_quic::conn::stream::{
    Error,
    recv::hold::{Detached, ErrorKind},
};
use dope_quic::errors;
use dope_quic::errors::detail;
use dope_quic::proto::param;
use dope_quic::runtime::endpoint;
use dope_quic::runtime::mux;
use dope_quic::runtime::mux::handler;
use dope_quic::runtime::mux::handler::hook::data::datagram;
use dope_quic::runtime::mux::handler::hook::data::stream;
use dope_quic::runtime::mux::handler::hook::life::create;
use dope_quic::runtime::mux::handler::hook::life::ready;
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::cert;
use dope_quic::runtime::mux::handler::hook::wire::ingress;
use dope_quic::runtime::mux::handler::hook::wire::packet;
use dope_quic::stream::Capacity;
use dope_quic::stream::RecvBuffer;
use dope_quic::stream::send::admit;
use dope_quic::wire::stream::Id;
use dope_test::alloc::{Activity, Tracker};
use o3::buffer;
use o3::buffer::Residency;
use o3::buffer::resident;
use std::cell::Cell;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;

#[derive(Default)]
pub struct Proof {
    pub certificates: usize,
    pub server_ready: bool,
    pub payload: Option<Vec<u8>>,
    pub received: Option<(Vec<u8>, usize)>,
    pub failures: Failures,
    pub timed_out: bool,
    pub read: Reading,
    pub stop: Option<shutdown::Trigger>,
}

#[derive(Default)]
pub struct Reading {
    pub stream: bool,
    pub len: Option<usize>,
    pub failed: bool,
    pub observed: Option<Read>,
    pub barrier: Option<Option<Vec<u8>>>,
}

#[derive(Debug)]
pub struct Read {
    pub expected: usize,
    pub before: bool,
    pub failed: Failed,
    pub resumed: Resumed,
    pub drained: Result<Option<Vec<u8>>, Capacity>,
}

#[derive(Debug)]
pub struct Failed {
    pub result: Result<Option<Vec<u8>>, Capacity>,
    pub activity: Activity,
    pub fin: bool,
    pub eof: bool,
}

#[derive(Debug)]
pub struct Resumed {
    pub activity: Activity,
    pub length: usize,
    pub eof: bool,
}

#[derive(Debug)]
pub enum Fault {
    MissingPayload,
    MissingOwner,
    MissingHold,
    MissingShutdown,
    Stream(Error),
    Receive(Capacity),
    Release(ErrorKind),
    Connect(errors::Connect),
    Datagram(errors::SendFailure<Vec<u8>>),
}

#[derive(Default, Debug)]
pub struct Failures {
    pub packet: Option<(SocketAddr, errors::Receive, usize)>,
    pub detail: Option<(SocketAddr, usize, detail::Diagnostic)>,
    pub fixture: Option<Fault>,
    pub shutdown: Option<shutdown::FireError>,
}

pub struct Connect {
    pub peer: SocketAddr,
    pub authority: Authority,
    pub params: param::Set,
}

pub struct Pooled<'tls> {
    pub peer: SocketAddr,
    pub pool: &'tls Pool,
    pub params: param::Set,
}

#[derive(Default)]
pub struct State<'d> {
    datagram: Option<RecvBuffer<'d>>,
    held_stream: Option<Detached<RecvBuffer<'d>>>,
}

#[pin_project::pin_project]
pub struct Capture<'d, const ID: u8, C = Connect> {
    client: bool,
    proof: Rc<RefCell<Proof>>,
    handle: Cell<Option<id::Handle<id::Driver<'d>, ID>>>,
    connect: Option<C>,
}

impl<'d, const ID: u8, C> Capture<'d, ID, C> {
    pub fn new(client: bool, proof: Rc<RefCell<Proof>>, connect: Option<C>) -> Self {
        Self {
            client,
            proof,
            handle: Cell::new(None),
            connect,
        }
    }
}

impl<'d, const ID: u8, C> handler::Handler<ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID, C>
{
    type Connection = State<'d>;
    type Create = create::Call;
    type Events =
        set::Set<set::On, set::On, set::On, set::Off, set::Off, set::Off, ingress::Off, packet::On>;
}

impl<'d, const ID: u8, C> create::Sink<ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID, C>
{
    fn create(
        _: create::Event<'_, Self, ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
    ) -> Self::Connection {
        State::default()
    }
}

impl<'d, const ID: u8, C> ready::Sink<ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID, C>
{
    fn established(
        event: ready::Event<'_, Self, ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, mut slot, handle, _) = event.into();
        this.handle.set(Some(handle));
        let payload = {
            let mut proof = this.proof.borrow_mut();
            if !this.client {
                proof.server_ready = true;
                return;
            }
            if !proof.read.stream {
                return;
            }
            let Some(payload) = proof.payload.take() else {
                proof.fail(Fault::MissingPayload);
                return;
            };
            payload
        };
        let mut streams = slot.transport().streams();
        let mut send = streams.send();
        let result = (|| {
            let data = send.open_uni()?;
            let gate = send.open_uni()?;
            send.send(data, &payload)?;
            send.finish(data)?;
            send.send(gate, b"retained stream lifetime barrier")?;
            send.finish(gate)
        })();
        if let Err(cause) = result {
            this.proof.borrow_mut().fail(Fault::Stream(cause));
        }
    }
}

impl<'d, const ID: u8, C> datagram::Sink<ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID, C>
{
    fn datagram(
        event: datagram::Event<'_, Self, ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, mut slot, _, data, _) = event.into();
        if this.client {
            return;
        }
        let Some(first) = slot.application().datagram.replace(data) else {
            return;
        };
        let mut proof = this.proof.borrow_mut();
        proof.finish(first.as_ref().to_vec(), first.resident());
    }
}

impl<'d, const ID: u8, C> stream::Sink<ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID, C>
{
    fn stream(
        event: stream::Event<'_, Self, ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
    ) -> mux::Disposition {
        let (this, mut slot, _, event, _) = event.into();
        if this.client || !this.proof.borrow().read.stream {
            return mux::Disposition::Accept;
        }
        let Event::Readable { id } = event.event() else {
            return mux::Disposition::Accept;
        };
        let (state, conn) = slot.split();
        let mut streams = conn.streams();
        let stream = match streams.view().resolve_recv(id) {
            Ok(stream) => stream,
            Err(cause) => {
                this.proof.borrow_mut().fail(Fault::Stream(cause));
                return mux::Disposition::Accept;
            }
        };
        let read_len = this.proof.borrow_mut().read.len.take();
        if let Some(expected) = read_len {
            if id.number() != 0 || !streams.view().has_recv_fin(stream) {
                this.proof.borrow_mut().read.len = Some(expected);
                return mux::Disposition::Accept;
            }
            let before = streams.view().is_recv_eof(stream);
            let (failure, failed) = Tracker::activity(|| {
                Tracker::fail_after(0, || streams.receive().recv_owned(stream))
            });
            let fin = streams.view().has_recv_fin(stream);
            let eof = streams.view().is_recv_eof(stream);
            let (result, resumed) = Tracker::activity(|| streams.receive().recv_owned(stream));
            let bytes = match result {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    this.proof.borrow_mut().fail(Fault::MissingOwner);
                    return mux::Disposition::Accept;
                }
                Err(cause) => {
                    this.proof.borrow_mut().fail(Fault::Receive(cause));
                    return mux::Disposition::Accept;
                }
            };
            let after = streams.view().is_recv_eof(stream);
            let drained = streams.receive().recv_owned(stream);
            let mut proof = this.proof.borrow_mut();
            proof.read.observed = Some(Read {
                expected,
                before,
                failed: Failed {
                    result: failure,
                    activity: failed,
                    fin,
                    eof,
                },
                resumed: Resumed {
                    activity: resumed,
                    length: bytes.len(),
                    eof: after,
                },
                drained,
            });
            proof.read.failed = true;
            proof.finish(bytes, expected);
            return mux::Disposition::Accept;
        }
        if state.held_stream.is_none() {
            let mut recv = streams.receive();
            state.held_stream = recv.hold(stream).map(|held| held.detach(&mut recv));
            if state.held_stream.is_none() {
                this.proof.borrow_mut().fail(Fault::MissingHold);
            }
            return mux::Disposition::Accept;
        }
        match streams.receive().recv_owned(stream) {
            Ok(barrier) => this.proof.borrow_mut().read.barrier = Some(barrier),
            Err(cause) => {
                this.proof.borrow_mut().fail(Fault::Receive(cause));
                return mux::Disposition::Accept;
            }
        }
        let Some(held) = state.held_stream.take() else {
            this.proof.borrow_mut().fail(Fault::MissingHold);
            return mux::Disposition::Accept;
        };
        let first = match held.release(&mut streams.receive()) {
            Ok(first) => first,
            Err(failure) => {
                let kind = failure.kind();
                state.held_stream = Some(failure.into_inner());
                this.proof.borrow_mut().fail(Fault::Release(kind));
                return mux::Disposition::Accept;
            }
        };
        let mut proof = this.proof.borrow_mut();
        proof.finish(first.as_ref().to_vec(), first.resident());
        mux::Disposition::Accept
    }
}

pub struct View<'step, 'd, const ID: u8, C>(&'step mut Capture<'d, ID, C>);

impl<'d, const ID: u8, C> View<'_, 'd, ID, C> {
    pub fn take_connect(&mut self) -> Option<C> {
        self.0.connect.take()
    }

    pub fn take_send(&mut self) -> Option<(id::Handle<id::Driver<'d>, ID>, Vec<u8>)> {
        let mut proof = self.0.proof.borrow_mut();
        if !proof.server_ready {
            return None;
        }
        let handle = self.0.handle.get()?;
        let payload = proof.payload.take()?;
        Some((handle, payload))
    }

    pub fn timeout(&mut self) {
        let mut proof = self.0.proof.borrow_mut();
        proof.timed_out = true;
        proof.stop();
    }

    pub fn fail(&mut self, cause: Fault) {
        self.0.proof.borrow_mut().fail(cause);
    }
}

impl<'d, const ID: u8, C> cert::Sink<ID, id::Driver<'d>> for Capture<'d, ID, C> {
    fn certificate(event: cert::Event<'_, '_, Self, ID, id::Driver<'d>>) {
        let (this, _, _, _) = event.into_parts();
        this.proof.borrow_mut().certificates += 1;
    }
}

impl<'d, const ID: u8, C> packet::Sink<ID, RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID, C>
{
    fn packet(event: packet::Event<'_, Self>) {
        let (this, from, error, len) = event.into_parts();
        let mut proof = this.proof.borrow_mut();
        match error {
            packet::Failure::Receive(error) => {
                if proof.failures.packet.is_none() {
                    proof.failures.packet = Some((from, error, len));
                }
            }
            packet::Failure::Diagnostic(detail) => {
                proof.failures.detail = Some((from, len, detail.clone()))
            }
        }
        if proof.stop.is_some() {
            proof.stop();
        }
    }
}

// SAFETY: the view borrows only test-owned command state for the loan lifetime;
// it cannot move or replace endpoint storage.
unsafe impl<'d, const ID: u8, C> endpoint::raw::Control<'d, ID, RecvBuffer<'d>>
    for Capture<'d, ID, C>
{
    type View<'step>
        = View<'step, 'd, ID, C>
    where
        Self: 'step,
        'd: 'step;

    fn view<'step>(handler: dispatch::raw::Loan<'step, 'd, Self>) -> Self::View<'step>
    where
        'd: 'step,
    {
        View(handler.into_pin().get_mut())
    }
}

/// Returns the source observed at the exact send ownership commit.
pub struct Commit;

impl<O: buffer::raw::Segment, W> admit::Commit<O, W> for Commit {
    type Retained = Id;
    type Discarded = admit::Discard<W>;

    fn retained(self, grant: admit::Admission<'_, O, W>) -> Id {
        grant.source().id()
    }

    fn discarded(self, cause: admit::Discard<W>) -> admit::Discard<W> {
        cause
    }
}

impl Proof {
    pub fn finish(&mut self, bytes: Vec<u8>, resident: usize) {
        self.received = Some((bytes, resident));
        self.stop();
    }

    fn fail(&mut self, cause: Fault) {
        if self.failures.fixture.is_none() {
            self.failures.fixture = Some(cause);
        }
        if self.stop.is_some() {
            self.stop();
        }
    }

    fn stop(&mut self) {
        match self.stop.take() {
            Some(stop) => self.failures.shutdown = stop.fire().err(),
            None => {
                if self.failures.fixture.is_none() {
                    self.failures.fixture = Some(Fault::MissingShutdown);
                }
            }
        }
    }
}
