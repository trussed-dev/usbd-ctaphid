pub const INTERRUPT_POLL_MILLISECONDS: u8 = 5;

pub const PACKET_SIZE: usize = 64;

// TODO: find the actual minimum ML-DSA sizes
pub const MESSAGE_SIZE: usize = (if cfg!(feature = "mldsa87") {
    20000
} else if cfg!(feature = "mldsa65") {
    15000
} else if cfg!(feature = "mldsa44") {
    10000
} else {
    // 7609
    PACKET_SIZE - 7 + 128 * (PACKET_SIZE - 5)
});
