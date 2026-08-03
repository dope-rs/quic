use dope_quic::Handler;

struct BorrowedHandler<'a> {
    state: &'a u64,
}

impl Handler for BorrowedHandler<'_> {
    type Connection = ();

    fn create_connection(
        &mut self,
        _conn: &mut dope_quic::Connection,
        _handle: dope_quic::conn::Handle,
    ) {
    }

    fn established(
        &mut self,
        _connection: &mut (),
        _conn: &mut dope_quic::Connection,
        _handle: dope_quic::conn::Handle,
    ) {
        std::hint::black_box(self.state);
    }
}

#[test]
fn handler_may_borrow_lexical_state() {
    let state = 42;
    let handler = BorrowedHandler { state: &state };

    fn accepts_handler(_: impl Handler) {}
    accepts_handler(handler);
}
