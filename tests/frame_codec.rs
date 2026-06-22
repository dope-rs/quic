use dope_quic::frame::Frame;

#[test]
fn padding_and_ping_round_trip() {
    let mut buf = Vec::new();
    Frame::Padding.encode(&mut buf);
    Frame::Ping.encode(&mut buf);
    let frames = Frame::decode_all(&buf).unwrap();
    assert_eq!(frames, vec![Frame::Ping]);
}

#[test]
fn crypto_round_trip() {
    let f = Frame::Crypto {
        offset: 12345,
        data: b"client-hello-bytes".to_vec(),
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn ack_round_trip() {
    let f = Frame::Ack {
        largest: 7,
        delay: 0,
        first_range: 7,
        additional_ranges: vec![],
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn decode_all_handles_mixed_frames_and_trailing_padding() {
    let mut buf = Vec::new();
    Frame::Crypto {
        offset: 0,
        data: vec![1, 2, 3],
    }
    .encode(&mut buf);
    Frame::Ping.encode(&mut buf);
    Frame::Padding.encode(&mut buf);
    Frame::Padding.encode(&mut buf);

    let frames = Frame::decode_all(&buf).unwrap();
    assert_eq!(
        frames,
        vec![
            Frame::Crypto {
                offset: 0,
                data: vec![1, 2, 3]
            },
            Frame::Ping,
        ]
    );
}

#[test]
fn decode_rejects_unknown_type() {
    let buf = [0x99u8];
    assert!(Frame::decode(&buf).is_err());
}

#[test]
fn handshake_done_round_trip() {
    let f = Frame::HandshakeDone;
    let mut buf = Vec::new();
    f.encode(&mut buf);
    assert_eq!(buf, vec![0x1e]);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(decoded, f);
}

#[test]
fn connection_close_transport_round_trip() {
    let f = Frame::ConnectionClose {
        is_application: false,
        error_code: 0x10,
        frame_type: 0x06,
        reason: b"crypto error".to_vec(),
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn connection_close_application_round_trip() {
    let f = Frame::ConnectionClose {
        is_application: true,
        error_code: 42,
        frame_type: 0,
        reason: b"goodbye".to_vec(),
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn new_connection_id_round_trip() {
    let f = Frame::NewConnectionId {
        sequence_number: 7,
        retire_prior_to: 3,
        connection_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
        stateless_reset_token: [0xAA; 16],
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn retire_connection_id_round_trip() {
    let f = Frame::RetireConnectionId {
        sequence_number: 42,
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn ack_with_multiple_ranges_round_trip() {
    let f = Frame::Ack {
        largest: 100,
        delay: 1234,
        first_range: 5,
        additional_ranges: vec![(2, 3), (10, 0)],
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}
