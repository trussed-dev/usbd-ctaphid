/*!
The CTAP protocol is a series of atomic *transactions*, which consist
of a *request* message followed by a *response* message.

Messages may spread over multiple *packets*, starting with
an *initialization* packet, followed by zero or more *continuation* packets.

In the case of multiple clients, the first to get through its initialization
packet in device idle state locks the device for other channels (they will
receive busy errors).

No state is maintained between transactions.
*/

use ctaphid_dispatch::types::Requester;
use ref_swap::OptionRefSwap;
use trussed::interrupt::InterruptFlag;
use usb_device::{
    bus::UsbBus,
    endpoint::{EndpointAddress, EndpointIn, EndpointOut},
    UsbError,
};

use crate::{
    buffer::{Buffer, BufferState, Packet},
    constants::PACKET_SIZE,
    Version,
};

pub struct Pipe<'alloc, 'pipe, 'interrupt, Bus: UsbBus> {
    endpoints: Endpoints<'alloc, Bus>,
    buffer: Buffer<'pipe, 'interrupt>,
}

impl<'alloc, 'pipe, 'interrupt, Bus: UsbBus> Pipe<'alloc, 'pipe, 'interrupt, Bus> {
    pub fn new(
        read_endpoint: EndpointOut<'alloc, Bus>,
        write_endpoint: EndpointIn<'alloc, Bus>,
        interchange: Requester<'pipe>,
        initial_milliseconds: u32,
    ) -> Self {
        Self {
            endpoints: Endpoints::new(read_endpoint, write_endpoint),
            buffer: Buffer::new(interchange, initial_milliseconds, None),
        }
    }

    pub fn with_interrupt(
        read_endpoint: EndpointOut<'alloc, Bus>,
        write_endpoint: EndpointIn<'alloc, Bus>,
        interchange: Requester<'pipe>,
        interrupt: Option<&'interrupt OptionRefSwap<'interrupt, InterruptFlag>>,
        initial_milliseconds: u32,
    ) -> Self {
        Self {
            endpoints: Endpoints::new(read_endpoint, write_endpoint),
            buffer: Buffer::new(interchange, initial_milliseconds, interrupt),
        }
    }

    pub fn implements(&self) -> u8 {
        self.buffer.implements()
    }

    pub fn set_implements(&mut self, implements: u8) {
        self.buffer.set_implements(implements);
    }

    pub fn set_version(&mut self, version: Version) {
        self.buffer.set_version(version);
    }

    pub fn read_address(&self) -> EndpointAddress {
        self.endpoints.read.address()
    }

    pub fn write_address(&self) -> EndpointAddress {
        self.endpoints.write.address()
    }

    // used to generate the configuration descriptors
    pub fn read_endpoint(&self) -> &EndpointOut<'alloc, Bus> {
        &self.endpoints.read
    }

    // used to generate the configuration descriptors
    pub fn write_endpoint(&self) -> &EndpointIn<'alloc, Bus> {
        &self.endpoints.write
    }

    /// This method handles CTAP packets (64 bytes), until it has assembled
    /// a CTAP message, with which it then calls `dispatch_message`.
    ///
    /// During these calls, we can be in states: Idle, Receiving, Dispatching.
    pub fn read_and_handle_packet(&mut self) {
        // info_now!("got a packet!");
        let mut packet = [0u8; PACKET_SIZE];
        if self.endpoints.read(&mut packet).is_ok() {
            let state = self.buffer.handle_packet(&packet);
            self.handle(state);
        }
    }

    pub fn check_timeout(&mut self, milliseconds: u32) {
        let state = self.buffer.check_timeout(milliseconds);
        self.handle(state);
    }

    pub fn did_start_processing(&mut self) -> bool {
        self.buffer.did_start_processing()
    }

    pub fn send_keepalive(&mut self, is_waiting_for_user_presence: bool) -> bool {
        if let Some(packet) = self.buffer.send_keepalive(is_waiting_for_user_presence) {
            self.endpoints.write(packet).ok();
            true
        } else {
            false
        }
    }

    pub fn handle_and_write_response(&mut self) {
        let state = self.buffer.handle_response();
        self.handle(state);
    }

    fn handle(&mut self, state: BufferState) {
        match state {
            BufferState::Idle => (),
            BufferState::ResponseQueued => self.maybe_write_packet(),
            BufferState::Error(error) => {
                // TODO: should we block?
                self.endpoints.write(Packet::from(&error)).ok();
            }
        }
    }

    // called from poll, and when a packet has been sent
    #[inline(never)]
    pub fn maybe_write_packet(&mut self) {
        self.buffer
            .try_send_packet(|packet| self.endpoints.write(packet));
    }
}

struct Endpoints<'a, Bus: UsbBus> {
    read: EndpointOut<'a, Bus>,
    write: EndpointIn<'a, Bus>,
}

impl<'a, Bus: UsbBus> Endpoints<'a, Bus> {
    fn new(read: EndpointOut<'a, Bus>, write: EndpointIn<'a, Bus>) -> Self {
        Self { read, write }
    }

    fn read(&mut self, packet: &mut [u8; PACKET_SIZE]) -> Result<(), ()> {
        match self.read.read(packet) {
            Ok(PACKET_SIZE) => Ok(()),
            Ok(_size) => {
                // error handling?
                // from spec: "Packets are always fixed size (defined by the endpoint and
                // HID report descriptors) and although all bytes may not be needed in a
                // particular packet, the full size always has to be sent.
                // Unused bytes SHOULD be set to zero."
                // !("OK but size {}", size);
                info!("error unexpected size {}", _size);
                Err(())
            }
            // usb-device lists WouldBlock or BufferOverflow as possible errors.
            // both should not occur here, and we can't do anything anyway.
            // Err(UsbError::WouldBlock) => { return; },
            // Err(UsbError::BufferOverflow) => { return; },
            Err(_error) => {
                info!("error no {}", _error as i32);
                Err(())
            }
        }
    }

    fn write(&mut self, packet: Packet<'_>) -> Result<(), ()> {
        // zeros leftover bytes
        let mut buffer = [0u8; PACKET_SIZE];
        packet.serialize(&mut buffer);
        match self.write.write(&buffer) {
            Ok(PACKET_SIZE) => Ok(()),
            Ok(_) => {
                error!("short write");
                panic!("unexpected size writing packet!");
            }
            Err(UsbError::WouldBlock) => {
                // fine, can't write try later
                // this shouldn't happen probably
                info!("hid usb WouldBlock");
                Err(())
            }
            Err(_) => {
                // info_now!("weird USB error");
                panic!("unexpected error writing packet!");
            }
        }
    }
}
