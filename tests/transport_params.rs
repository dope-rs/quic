use dope_quic::transport_params;
use dope_quic::transport_params::{
    DEFAULT_ACK_DELAY_EXPONENT, DEFAULT_ACTIVE_CONNECTION_ID_LIMIT, DEFAULT_MAX_ACK_DELAY_MS,
    DEFAULT_MAX_UDP_PAYLOAD_SIZE, ID_INITIAL_SOURCE_CONNECTION_ID, ID_MAX_DATAGRAM_FRAME_SIZE,
    TpError,
};

#[test]
fn defaults_round_trip() {
    let tp = transport_params::Params::default();
    let mut buf = Vec::new();
    tp.encode(&mut buf);
    let decoded = transport_params::Params::decode(&buf).unwrap();
    assert_eq!(decoded, tp);
    assert_eq!(decoded.max_udp_payload_size, DEFAULT_MAX_UDP_PAYLOAD_SIZE);
    assert_eq!(decoded.ack_delay_exponent, DEFAULT_ACK_DELAY_EXPONENT);
    assert_eq!(decoded.max_ack_delay_ms, DEFAULT_MAX_ACK_DELAY_MS);
    assert_eq!(
        decoded.active_connection_id_limit,
        DEFAULT_ACTIVE_CONNECTION_ID_LIMIT
    );
}

#[test]
fn full_round_trip_with_all_optional_fields() {
    let tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_udp_payload_size: 1500,
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_stream_data_uni: 100_000,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        ack_delay_exponent: 2,
        max_ack_delay_ms: 50,
        disable_active_migration: true,
        active_connection_id_limit: 4,
        initial_source_connection_id: Some(vec![0xa1; 8]),
        original_destination_connection_id: Some(vec![0xb2; 8]),
        retry_source_connection_id: Some(vec![0xc3; 8]),
        max_datagram_frame_size: Some(65535),
        stateless_reset_token: Some([0xff; 16]),
    };
    let mut buf = Vec::new();
    tp.encode(&mut buf);
    let decoded = transport_params::Params::decode(&buf).unwrap();
    assert_eq!(decoded, tp);
}

#[test]
fn empty_input_yields_defaults() {
    let decoded = transport_params::Params::decode(&[]).unwrap();
    assert_eq!(decoded, transport_params::Params::default());
}

#[test]
fn duplicate_id_rejected() {
    let mut buf = Vec::new();
    let tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        ..transport_params::Params::default()
    };
    tp.encode(&mut buf);
    let dup = transport_params::Params {
        max_idle_timeout_ms: 99_999,
        ..transport_params::Params::default()
    };
    let mut dup_buf = Vec::new();
    dup.encode(&mut dup_buf);
    buf.push(0x01);
    buf.push(0x04);
    buf.extend_from_slice(&((99_999u32 | 0x8000_0000).to_be_bytes()));

    assert_eq!(
        transport_params::Params::decode(&buf),
        Err(TpError::Duplicate)
    );
}

#[test]
fn truncated_value_rejected() {
    let buf = vec![0x01, 0x04, 0x00, 0x00];
    assert_eq!(
        transport_params::Params::decode(&buf),
        Err(TpError::Underflow)
    );
}

#[test]
fn reserved_ids_are_silently_ignored() {
    let buf = vec![0x1b, 0x01, 0xaa, 0x1b, 0x01, 0xbb];
    let decoded = transport_params::Params::decode(&buf).unwrap();
    assert_eq!(decoded, transport_params::Params::default());
}

#[test]
fn unknown_id_is_ignored() {
    let buf = vec![0x40, 0xff, 0x01, 0x99];
    let decoded = transport_params::Params::decode(&buf).unwrap();
    assert_eq!(decoded, transport_params::Params::default());
}

#[test]
fn ack_delay_exponent_above_20_rejected() {
    let buf = vec![0x0a, 0x01, 21];
    assert_eq!(
        transport_params::Params::decode(&buf),
        Err(TpError::OutOfRange)
    );
}

#[test]
fn max_udp_payload_below_1200_rejected() {
    let buf = vec![0x03, 0x02, 0x44, 0xaf];
    assert_eq!(
        transport_params::Params::decode(&buf),
        Err(TpError::OutOfRange)
    );
}

#[test]
fn datagram_size_round_trip() {
    let tp = transport_params::Params {
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    };
    let mut buf = Vec::new();
    tp.encode(&mut buf);
    let decoded = transport_params::Params::decode(&buf).unwrap();
    assert_eq!(decoded.max_datagram_frame_size, Some(65535));
    assert!(buf.contains(&(ID_MAX_DATAGRAM_FRAME_SIZE as u8)));
}

#[test]
fn iscid_round_trip() {
    let tp = transport_params::Params {
        initial_source_connection_id: Some(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        ..transport_params::Params::default()
    };
    let mut buf = Vec::new();
    tp.encode(&mut buf);
    let decoded = transport_params::Params::decode(&buf).unwrap();
    assert_eq!(
        decoded.initial_source_connection_id,
        Some(vec![1, 2, 3, 4, 5, 6, 7, 8])
    );
    assert!(buf.contains(&(ID_INITIAL_SOURCE_CONNECTION_ID as u8)));
}
