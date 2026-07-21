/// Raw USB endpoint `bInterval` value.  This is a 4 ms interval at Full Speed
/// and a 1 ms interval at High Speed (`2^(4 - 1)` microframes).
pub const INTERRUPT_POLL_INTERVAL: u8 = 4;

pub const PACKET_SIZE: usize = 64;
