#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split into pkt-line-style payloads: each newline-separated chunk
    // is a `Some(payload)`, empty chunks are treated as `None` which
    // represents a delim-pkt on the wire.
    let items: Vec<Option<&[u8]>> = data
        .split(|b| *b == b'\n')
        .map(|p| if p.is_empty() { None } else { Some(p) })
        .collect();
    drop(gix_protocol::upload_pack::fetch_request::parse_request(
        items.into_iter(),
    ));
});
