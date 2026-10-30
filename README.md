# 通

QUIC x dope

Use `Connection::with_scope` to access a connection's stream, input, output,
datagram, path, security and lifecycle capabilities. Scoped
`stream::id::{Send, Receive, Bidi}` values cannot escape or cross connections.
Keep `wire::stream::Id` across asynchronous callbacks and resolve it inside the
next access.

A long-lived protocol keeps one `stream::resident::Origin` per connection and
one `Local` per resident stream. A resident `View` checks the origin to issue
an `Owner<'conn>`; subsequent `bind` operations reuse that authority and check
the stream generation. Shared inspection uses `Connection::view` and
`with_streams`.

`recv::hold::Held<'conn, B>` and `recv::credit::Credit<'conn, K>` retain the same
connection authority. Use `detach` when an owner-tagged value must outlive the
scoped access; rebinding checks its owner.

```sh
cargo test --tests --release
```

The optional interoperability test requires an OpenSSL executable supporting
`s_client -quic`. It verifies a QUIC v1 handshake and the server certificate:

```sh
cargo test --test openssl -- --ignored --nocapture
```

© 2026 inkyu
