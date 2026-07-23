use dope_quic::Handler;

struct BorrowedHandler<'a> {
    state: &'a u64,
}

impl Handler for BorrowedHandler<'_> {
    fn established(&mut self, _conn: &mut dope_quic::Conn, _handle: dope_quic::ConnHandle) {
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
