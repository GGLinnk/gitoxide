#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let lines = data.split(|b| *b == b'\n').filter(|l| !l.is_empty());
    drop(gix_protocol::push::report_status::parse_report_v2(lines));
});
