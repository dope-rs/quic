use dope_quic::wire::{frame, stream, varint};
use dope_test::alloc;
use o3::buffer::write;

#[global_allocator]
static ALLOCATOR: alloc::Tracker = alloc::Tracker::new();

#[test]
fn decoded() {
    let cases: &[(&[u8], &[u8])] = &[
        (&[2, 10, 0, 0x40, 1, 2, 0, 2], &[2, 10, 0, 1, 2, 0, 2]),
        (&[6, 0, 0x40, 2, 0xab, 0xcd], &[6, 0, 2, 0xab, 0xcd]),
        (&[7, 0x40, 2, 0xab, 0xcd], &[7, 2, 0xab, 0xcd]),
        (&[0x31, 0x40, 2, 0xab, 0xcd], &[0x31, 2, 0xab, 0xcd]),
        (&[0x0a, 0, 0x40, 2, 0xab, 0xcd], &[0x0a, 0, 2, 0xab, 0xcd]),
        (&[0x1d, 0, 0x40, 2, 0xab, 0xcd], &[0x1d, 0, 2, 0xab, 0xcd]),
        (
            &[0x1c, 0, 0, 0x40, 2, 0xab, 0xcd],
            &[0x1c, 0, 0, 2, 0xab, 0xcd],
        ),
    ];
    let mut output = Vec::with_capacity(32);
    for &(wire, expected) in cases {
        let sample = alloc::Tracker::begin();
        let (borrowed, used) = frame::Frame::decode_ref(wire).expect("borrowed frame must decode");
        assert_eq!(used, wire.len());
        for _ in 0..2 {
            output.clear();
            borrowed.encode(&mut output).expect("wire encoding");
            assert_eq!(output, expected);
        }
        assert!(sample.finish() == alloc::Activity::default());

        let (owned, used) = frame::Frame::decode(wire).expect("owned frame must decode");
        assert_eq!(used, wire.len());
        output.clear();
        owned.encode(&mut output).expect("wire encoding");
        assert_eq!(output, expected);

        let mut packet = wire.to_vec();
        packet.push(frame::TYPE_PING);
        assert_eq!(
            frame::Frame::decode_ref(&packet).expect("first frame").1,
            wire.len()
        );
        let decoded = frame::Frame::decode_all(&packet).expect("retained suffix");
        assert_eq!(decoded.len(), 2);
        assert!(matches!(decoded[1].view(), frame::View::Ping));
    }
}

#[test]
fn rejects_short_output() {
    let frame = frame::Borrowed::crypto(varint::VarInt::ZERO, b"ab").expect("bounded frame");
    let mut bytes = [0xa5; 4];
    let mut output = write::Slice::new(&mut bytes);
    assert!(frame.encode(&mut output).is_err());
    assert_eq!(output.finish(), 0);
    assert_eq!(bytes, [0xa5; 4]);
}

#[test]
fn span_overflow() {
    use frame::decode::error;

    let maximum = varint::VarInt::MAX_VALUE;
    let bytes = [0xab, 0xcd];
    let expected = error::Fault::InvalidLength {
        offset: maximum.get(),
        length: bytes.len() as u64,
    };
    assert!(matches!(
        frame::Borrowed::crypto(maximum, &bytes),
        Err(error) if error == expected
    ));
    let id = stream::Id::ZERO;
    for length in [frame::Length::Implicit, frame::Length::Explicit] {
        assert!(matches!(
            frame::Borrowed::stream(id, maximum, frame::Boundary::More, length, &bytes),
            Err(error) if error == expected
        ));
    }
    for kind in [
        frame::TYPE_CRYPTO,
        frame::TYPE_STREAM_BASE | frame::STREAM_FLAG_OFF,
        frame::TYPE_STREAM_BASE | frame::STREAM_FLAG_OFF | frame::STREAM_FLAG_LEN,
    ] {
        let mut wire = vec![kind];
        if kind != frame::TYPE_CRYPTO {
            wire.push(0);
        }
        maximum.encode(&mut wire).expect("wire encoding");
        let explicit = kind == frame::TYPE_CRYPTO || kind & frame::STREAM_FLAG_LEN != 0;
        if explicit {
            wire.push(2);
        }
        wire.extend(bytes);
        let sample = alloc::Tracker::begin();
        assert!(matches!(
            frame::Frame::decode_ref(&wire),
            Err(error) if error == expected
        ));
        assert!(matches!(
            frame::Frame::decode(&wire),
            Err(error::Error::Fault(fault)) if fault == expected
        ));
        assert!(sample.finish() == alloc::Activity::default());
        if explicit {
            wire.pop();
            let expected = error::Fault::Underflow {
                offset: wire.len() - 1,
                actual: 1,
                required: 2,
            };
            assert!(matches!(
                frame::Frame::decode_ref(&wire),
                Err(error) if error == expected
            ));
            assert!(matches!(
                frame::Frame::decode(&wire),
                Err(error::Error::Fault(fault)) if fault == expected
            ));
        }
    }
}

#[test]
fn layouts() {
    use frame::ack::ranges;

    assert_eq!(size_of::<frame::Frame>(), 64);
    assert_eq!(size_of::<frame::Borrowed<'_>>(), 56);
    use dope_quic::wire::packet::cid;

    assert_eq!(
        size_of::<frame::Frame<&[u8], ranges::Set<'_>, cid::Ref<'_>>>(),
        56
    );
}

#[test]
fn announcement() {
    let mut output = Vec::with_capacity(40);
    for length in 1..=20_u8 {
        let mut wire = vec![frame::TYPE_NEW_CONNECTION_ID, 7, 3, length];
        wire.extend((0..length).map(|index| index + 1));
        wire.extend([0xa5; 16]);
        let sample = alloc::Tracker::begin();
        let bytes = {
            let (decoded, used) = frame::Frame::decode_ref(&wire).expect("valid CID announcement");
            assert_eq!(used, wire.len());
            output.clear();
            decoded.encode(&mut output).expect("wire encoding");
            assert_eq!(output, wire);
            match decoded.view() {
                frame::View::NewConnectionId { notice, .. } => Some(notice.id().into_slice()),
                _ => None,
            }
            .expect("decoded CID announcement")
        };
        assert!(std::ptr::eq(bytes.as_ptr(), wire[4..].as_ptr()));
        assert_eq!(bytes.len(), usize::from(length));
        let (owned, used) = frame::Frame::decode(&wire).expect("owned CID announcement");
        assert_eq!(used, wire.len());
        output.clear();
        owned.encode(&mut output).expect("wire encoding");
        assert_eq!(output, wire);
        assert!(sample.finish() == alloc::Activity::default());
    }
}

#[test]
fn announcement_errors() {
    use frame::decode::error;

    for (length, prior) in [(0_u8, 0_u8), (8, 8)] {
        let mut wire = vec![frame::TYPE_NEW_CONNECTION_ID, 7, prior, length];
        wire.resize(usize::from(length) + 20, 0);
        let expected = error::Fault::InvalidConnectionId {
            sequence_number: 7,
            retire_prior_to: u64::from(prior),
            length: usize::from(length),
        };
        assert!(matches!(
            frame::Frame::decode_ref(&wire),
            Err(error) if error == expected
        ));
        assert!(matches!(
            frame::Frame::decode(&wire),
            Err(error::Error::Fault(fault)) if fault == expected
        ));
    }
}

#[test]
fn announcement_truncation() {
    use frame::decode::error;

    let wire = [
        frame::TYPE_NEW_CONNECTION_ID,
        7,
        3,
        8,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
        0xa5,
    ];
    for end in 4..wire.len() {
        let (offset, required) = if end < 12 { (4, 24) } else { (12, 16) };
        let expected = error::Fault::Underflow {
            offset,
            actual: end - offset,
            required,
        };
        assert!(matches!(frame::Frame::decode_ref(&wire[..end]), Err(error) if error == expected));
        assert!(
            matches!(frame::Frame::decode(&wire[..end]), Err(error::Error::Fault(error)) if error == expected)
        );
    }
}

#[test]
fn ack_ecn_suffix() {
    use frame::decode::error;

    let wire = [
        frame::TYPE_ACK_ECN,
        20,
        0,
        1,
        2,
        1,
        2,
        0,
        0x40,
        0,
        0x80,
        0,
        0,
        0,
        frame::TYPE_PING,
    ];
    let (_, used) = frame::Frame::decode_ref(&wire).expect("ACK with ECN");
    assert_eq!(used, wire.len() - 1);
    let frames = frame::Frame::decode_all(&wire).expect("ACK suffix");
    assert_eq!(frames.len(), 2);
    assert!(matches!(frames[1].view(), frame::View::Ping));
    for (offset, width) in [(7, 1), (8, 2), (10, 4)] {
        for actual in 0..width {
            let expected = error::Fault::VarInt {
                offset,
                source: varint::Error::Underflow {
                    actual,
                    required: if actual == 0 { 1 } else { width },
                },
            };
            assert!(
                matches!(frame::Frame::decode_ref(&wire[..offset + actual]), Err(error) if error == expected)
            );
        }
    }
}

#[test]
fn announcement_capacity() {
    use frame::decode::error;

    for length in [21_u8, 255] {
        let mut wire = vec![frame::TYPE_NEW_CONNECTION_ID, 7, 3, length];
        wire.resize(usize::from(length) + 20, 0);
        let errors = [
            frame::Frame::decode_ref(&wire)
                .map_err(error::Error::Fault)
                .err()
                .expect("oversized borrowed CID"),
            frame::Frame::decode(&wire)
                .err()
                .expect("oversized owned CID"),
        ];
        for fault in errors {
            let parts = match fault {
                error::Error::Fault(error::Fault::ConnectionIdLength {
                    sequence_number: seq,
                    retire_prior_to: prior,
                    source,
                }) => Some((seq, prior, source.into_parts())),
                _ => None,
            }
            .expect("CID capacity retains exact source");
            assert_eq!(parts.0, 7);
            assert_eq!(parts.1, 3);
            assert_eq!(parts.2.0.get(), usize::from(length));
            assert_eq!(parts.2.1, 20);
        }
    }
}

#[test]
fn payload_length_bound() {
    use frame::decode::error;

    let prefixes: &[&[u8]] = &[
        &[frame::TYPE_CRYPTO, 0],
        &[frame::TYPE_STREAM_BASE | frame::STREAM_FLAG_LEN, 0],
        &[frame::TYPE_NEW_TOKEN],
        &[frame::TYPE_DATAGRAM_LEN],
        &[frame::TYPE_CONNECTION_CLOSE_APP, 0],
        &[frame::TYPE_CONNECTION_CLOSE, 0, 0],
    ];
    for prefix in prefixes {
        let mut wire = prefix.to_vec();
        varint::VarInt::MAX_VALUE
            .encode(&mut wire)
            .expect("wire length");
        let expected = error::Fault::Underflow {
            offset: wire.len(),
            actual: 0,
            required: varint::VarInt::MAX as usize,
        };
        let sample = alloc::Tracker::begin();
        assert!(matches!(frame::Frame::decode_ref(&wire), Err(error) if error == expected));
        assert!(matches!(
            frame::Frame::decode(&wire),
            Err(error::Error::Fault(error)) if error == expected
        ));
        assert!(sample.finish() == alloc::Activity::default());
    }
}
