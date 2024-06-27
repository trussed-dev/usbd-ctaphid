#![no_main]

use ctaphid_dispatch::types::{Channel, Error, InterchangeResponse, Message, Responder};
use libfuzzer_sys::{arbitrary::{self, Arbitrary}, fuzz_target};
use usbd_ctaphid::buffer::{Buffer, BufferState};

#[derive(Debug, Arbitrary)]
enum Action {
    HandlePacket {
        data: [u8; 64],
        success: bool,
    },
    HandleResponse(bool),
    TrySendPacket(bool),
    CheckTimeout {
        milliseconds: u32,
        success: bool,
    },
    DidStartProcessing,
    SendKeepalive(bool),
    GenerateResponse(Vec<u8>),
}

impl Action {
    fn run(self, buffer: &mut Buffer<'_, '_>, rp: &mut Responder<'_>) {
        match self {
            Self::HandlePacket { data, success } => {
                let state = buffer.handle_packet(&data);
                self.handle_state(buffer, state, success);
            }
            Self::HandleResponse(success) => {
                let state = buffer.handle_response();
                self.handle_state(buffer, state, success);
            }
            Self::TrySendPacket(success) => {
                self.try_send_packet(buffer, success);
            }
            Self::CheckTimeout { milliseconds, success } => {
                let state = buffer.check_timeout(milliseconds);
                self.handle_state(buffer, state, success);
            }
            Self::DidStartProcessing => {
                buffer.did_start_processing();
            }
            Self::SendKeepalive(waiting) => {
                let _ = buffer.send_keepalive(waiting);
            }
            Self::GenerateResponse(response) => {
                if let Ok(_request) = rp.request() {
                    let response = Message::from_slice(&response).map_err(|_| Error::InvalidLength);
                    rp.respond(InterchangeResponse(response)).ok();
                }
            }
        }
    }

    fn handle_state(&self, buffer: &mut Buffer, state: BufferState, success: bool) {
        if state == BufferState::ResponseQueued {
            self.try_send_packet(buffer, success);
        }
    }

    fn try_send_packet(&self, buffer: &mut Buffer, success: bool) {
        buffer.try_send_packet(|_| if success { Ok(()) } else { Err(()) });
    }
}

fuzz_target!(|actions: Vec<Action>| {
    let channel = Channel::new();
    let (rq, mut rp) = channel.split().unwrap();
    let mut buffer = Buffer::new(rq, 0, None);
    for action in actions {
        action.run(&mut buffer, &mut rp);
    }
});
