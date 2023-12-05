pub const INTERRUPT_POLL_MILLISECONDS: u8 = 5;

pub const PACKET_SIZE: usize = 64;

// 1200
// pub const MESSAGE_SIZE: usize = ctap_types::sizes::REALISTIC_MAX_MESSAGE_SIZE;
// pub const MESSAGE_SIZE: usize = 3072;
// 7609 bytes is max message size for ctaphid
// ctaphid_dispatch::types::Message.len() == 7069;
pub const MESSAGE_SIZE: usize = 7069;
