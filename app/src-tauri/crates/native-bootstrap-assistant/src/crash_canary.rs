pub(crate) const CANARY_BYTES: usize = 96;

const SECRET_DOMAIN: u64 = 0xd6e8_feb8_6659_fd93;
const CONTROL_DOMAIN: u64 = 0xa076_1d64_78bd_642f;

pub(crate) fn secret_byte(pid: u32, index: usize) -> u8 {
    mixed_byte(pid, index, SECRET_DOMAIN)
}

pub(crate) fn control_byte(pid: u32, index: usize) -> u8 {
    mixed_byte(pid, index, CONTROL_DOMAIN)
}

fn mixed_byte(pid: u32, index: usize, domain: u64) -> u8 {
    let mut value = domain
        ^ u64::from(pid).rotate_left(17)
        ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (value ^ (value >> 31)) as u8
}
