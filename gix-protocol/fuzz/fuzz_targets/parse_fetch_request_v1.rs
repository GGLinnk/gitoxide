#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let items: Vec<Option<&[u8]>> = data
        .split(|b| *b == b'\n')
        .map(|p| if p.is_empty() { None } else { Some(p) })
        .collect();
    drop(gix_protocol::upload_pack::fetch_request_v1::parse_request(
        items.into_iter(),
    ));
});
