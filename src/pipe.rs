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

use core::sync::atomic::Ordering;
// pub type ContactInterchange = usbd_ccid::types::ApduInterchange;
// pub type ContactlessInterchange = iso14443::types::ApduInterchange;

use ctaphid_dispatch::command::Command;
use ctaphid_dispatch::types::{Error as DispatchError, Requester};

use ctap_types::Error as AuthenticatorError;
use trussed::interrupt::InterruptFlag;

use ref_swap::OptionRefSwap;
// use serde::Serialize;
use usb_device::{
    bus::UsbBus,
    endpoint::{EndpointAddress, EndpointIn, EndpointOut},
    UsbError,
    // Result as UsbResult,
};

use crate::{
    constants::{
        // 3072
        MESSAGE_SIZE,
        // 64
        PACKET_SIZE,
    },
    types::KeepaliveStatus,
    Version,
};

/// The actual payload of given length is dealt with separately
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Request {
    channel: u32,
    command: Command,
    length: u16,
    timestamp: u32,
}

/// The actual payload of given length is dealt with separately
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Response {
    channel: u32,
    command: Command,
    length: u16,
}

impl Response {
    fn from_request_and_size(request: Request, size: usize) -> Self {
        Self {
            channel: request.channel,
            command: request.command,
            length: size as u16,
        }
    }

    fn error_from_request(request: Request) -> Self {
        Self::error_on_channel(request.channel)
    }

    fn error_on_channel(channel: u32) -> Self {
        Self {
            channel,
            command: Command::Error,
            length: 1,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct MessageState {
    // sequence number of next continuation packet
    next_sequence: u8,
    // number of bytes of message payload transmitted so far
    transmitted: usize,
}

impl Default for MessageState {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            transmitted: PACKET_SIZE - 7,
        }
    }
}

impl MessageState {
    // update state due to receiving a full new continuation packet
    #[must_use]
    pub fn absorb_packet(mut self) -> Self {
        self.next_sequence += 1;
        self.transmitted += PACKET_SIZE - 5;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Idle,

    // if request payload data is larger than one packet
    Receiving((Request, MessageState)),

    // Processing(Request),

    // // the request message is ready, need to dispatch to authenticator
    // Dispatching((Request, Ctap2Request)),

    // waiting for response from authenticator
    WaitingOnAuthenticator(Request),

    WaitingToSend(Response),

    Sending((Response, MessageState)),
}

pub struct Pipe<'alloc, 'pipe, 'interrupt, Bus: UsbBus> {
    endpoints: Endpoints<'alloc, Bus>,
    state: State,

    interchange: Requester<'pipe>,
    interrupt: Option<&'interrupt OptionRefSwap<'interrupt, InterruptFlag>>,

    // shared between requests and responses, due to size
    buffer: [u8; MESSAGE_SIZE],

    // we assign channel IDs one by one, this is the one last assigned
    // TODO: move into "app"
    last_channel: u32,

    // Indicator of implemented commands in INIT response.
    implements: u8,

    // timestamp that gets used for timing out CID's
    last_milliseconds: u32,

    // a "read once" indicator if now we're waiting on the application processing
    started_processing: bool,

    needs_keepalive: bool,

    version: Version,
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
            state: State::Idle,
            interchange,
            buffer: [0u8; MESSAGE_SIZE],
            last_channel: 0,
            interrupt: None,
            // Default to nothing implemented.
            implements: 0x80,
            last_milliseconds: initial_milliseconds,
            started_processing: false,
            needs_keepalive: false,
            version: Default::default(),
        }
    }
}

impl<'alloc, 'pipe, 'interrupt, Bus: UsbBus> Pipe<'alloc, 'pipe, 'interrupt, Bus> {
    // pub fn borrow_mut_authenticator(&mut self) -> &mut Authenticator {
    //     &mut self.authenticator
    // }

    pub fn with_interrupt(
        read_endpoint: EndpointOut<'alloc, Bus>,
        write_endpoint: EndpointIn<'alloc, Bus>,
        interchange: Requester<'pipe>,
        interrupt: Option<&'interrupt OptionRefSwap<'interrupt, InterruptFlag>>,
        initial_milliseconds: u32,
    ) -> Self {
        Self {
            endpoints: Endpoints::new(read_endpoint, write_endpoint),
            state: State::Idle,
            interchange,
            buffer: [0u8; MESSAGE_SIZE],
            last_channel: 0,
            interrupt,
            // Default to nothing implemented.
            implements: 0x80,
            last_milliseconds: initial_milliseconds,
            started_processing: false,
            needs_keepalive: false,
            version: Default::default(),
        }
    }

    pub fn implements(&self) -> u8 {
        self.implements
    }

    pub fn set_implements(&mut self, implements: u8) {
        self.implements = implements;
    }

    pub fn set_version(&mut self, version: Version) {
        self.version = version;
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

    fn cancel_ongoing_activity(&mut self) {
        if matches!(self.state, State::WaitingOnAuthenticator(_)) {
            info_now!("Interrupting request");
            if let Some(Some(i)) = self.interrupt.map(|i| i.load(Ordering::Relaxed)) {
                info_now!("Loaded some interrupter");
                i.interrupt();
            }
        }
    }

    /// This method handles CTAP packets (64 bytes), until it has assembled
    /// a CTAP message, with which it then calls `dispatch_message`.
    ///
    /// During these calls, we can be in states: Idle, Receiving, Dispatching.
    pub fn read_and_handle_packet(&mut self) {
        // info_now!("got a packet!");
        let mut packet = [0u8; PACKET_SIZE];
        if self.endpoints.read(&mut packet).is_err() {
            return;
        }
        info!(">> ");
        info!("{}", hex_str!(&packet[..16]));

        // packet is 64 bytes, reading 4 will not panic
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        // info_now!("channel {}", channel);

        let is_initialization = (packet[4] >> 7) != 0;
        // info_now!("is_initialization {}", is_initialization);

        if is_initialization {
            // case of initialization packet
            info!("init");

            let command_number = packet[4] & !0x80;
            // info_now!("command number {}", command_number);

            let command = match Command::try_from(command_number) {
                Ok(command) => command,
                // `solo ls` crashes here as it uses command 0x86
                Err(_) => {
                    info!("Received invalid command.");
                    self.start_sending_error_on_channel(
                        channel,
                        AuthenticatorError::InvalidCommand,
                    );
                    return;
                }
            };

            // can't actually fail
            let length = u16::from_be_bytes(packet[5..][..2].try_into().unwrap());

            let timestamp = self.last_milliseconds;
            let current_request = Request {
                channel,
                command,
                length,
                timestamp,
            };

            if !(self.state == State::Idle) {
                let request = match self.state {
                    State::WaitingOnAuthenticator(request) => request,
                    State::Receiving((request, _message_state)) => request,
                    _ => {
                        info_now!("Ignoring transaction as we're already transmitting.");
                        return;
                    }
                };
                if packet[4] == 0x86 {
                    info_now!("Resyncing!");
                    self.cancel_ongoing_activity();
                } else {
                    if channel == request.channel {
                        if command == Command::Cancel {
                            info_now!("Cancelling");
                            self.cancel_ongoing_activity();
                        } else {
                            info_now!("Expected seq, {:?}", request.command);
                            self.start_sending_error(request, AuthenticatorError::InvalidSeq);
                        }
                    } else {
                        info_now!("busy.");
                        self.send_error_now(current_request, AuthenticatorError::ChannelBusy);
                    }

                    return;
                }
            }

            if length > MESSAGE_SIZE as u16 {
                info!("Error message too big.");
                self.send_error_now(current_request, AuthenticatorError::InvalidLength);
                return;
            }

            if length > PACKET_SIZE as u16 - 7 {
                // store received part of payload,
                // prepare for continuation packets
                self.buffer[..PACKET_SIZE - 7].copy_from_slice(&packet[7..]);
                self.state = State::Receiving((current_request, { MessageState::default() }));
                // we're done... wait for next packet
            } else {
                // request fits in one packet
                self.buffer[..length as usize].copy_from_slice(&packet[7..][..length as usize]);
                self.dispatch_request(current_request);
            }
        } else {
            // case of continuation packet
            match self.state {
                State::Receiving((request, message_state)) => {
                    let sequence = packet[4];
                    // info_now!("receiving continuation packet {}", sequence);
                    if sequence != message_state.next_sequence {
                        // error handling?
                        // info_now!("wrong sequence for continuation packet, expected {} received {}",
                        //           message_state.next_sequence, sequence);
                        info!("Error invalid cont pkt");
                        self.start_sending_error(request, AuthenticatorError::InvalidSeq);
                        return;
                    }
                    if channel != request.channel {
                        // error handling?
                        // info_now!("wrong channel for continuation packet, expected {} received {}",
                        //           request.channel, channel);
                        info!("Ignore invalid channel");
                        return;
                    }

                    let payload_length = request.length as usize;
                    if message_state.transmitted + (PACKET_SIZE - 5) < payload_length {
                        // info_now!("transmitted {} + (PACKET_SIZE - 5) < {}",
                        //           message_state.transmitted, payload_length);
                        // store received part of payload
                        self.buffer[message_state.transmitted..][..PACKET_SIZE - 5]
                            .copy_from_slice(&packet[5..]);
                        let message_state = message_state.absorb_packet();
                        self.state = State::Receiving((request, message_state));
                        // info_now!("absorbed packet, awaiting next");
                    } else {
                        let missing = request.length as usize - message_state.transmitted;
                        self.buffer[message_state.transmitted..payload_length]
                            .copy_from_slice(&packet[5..][..missing]);
                        self.dispatch_request(request);
                    }
                }
                _ => {
                    // unexpected continuation packet
                    info!("Ignore unexpected cont pkt");
                }
            }
        }
    }

    pub fn check_timeout(&mut self, milliseconds: u32) {
        // At any point the RP application could crash or something,
        // so its up to the device to timeout those transactions.
        let last = self.last_milliseconds;
        self.last_milliseconds = milliseconds;
        if let State::Receiving((request, _message_state)) = &mut self.state {
            if (milliseconds - last) > 200 {
                // If there's a lapse in `check_timeout(...)` getting called (e.g. due to logging),
                // this could lead to inaccurate timestamps on requests.  So we'll
                // just "forgive" requests temporarily if this happens.
                debug!(
                    "lapse in hid check.. {} {} {}",
                    request.timestamp, milliseconds, last
                );
                request.timestamp = milliseconds;
            }
            // compare keeping in mind of possible overflow in timestamp.
            else if (milliseconds > request.timestamp && (milliseconds - request.timestamp) > 550)
                || (milliseconds < request.timestamp && milliseconds > 550)
            {
                debug!(
                    "Channel timeout. {}, {}, {}",
                    request.timestamp, milliseconds, last
                );
                let req = *request;
                self.start_sending_error(req, AuthenticatorError::Timeout);
            }
        }
    }

    fn dispatch_request(&mut self, request: Request) {
        info!("Got request: {:?}", request.command);
        match request.command {
            Command::Init => {}
            _ => {
                if request.channel == 0xffffffff {
                    self.start_sending_error(request, AuthenticatorError::InvalidChannel);
                    return;
                }
            }
        }
        // dispatch request further
        match request.command {
            Command::Init => {
                // info_now!("command INIT!");
                // info_now!("data: {:?}", &self.buffer[..request.length as usize]);
                match request.channel {
                    0 => {
                        // this is an error / reserved number
                        self.start_sending_error(request, AuthenticatorError::InvalidChannel);
                    }

                    // broadcast channel ID - request for assignment
                    cid => {
                        if request.length != 8 {
                            // error
                            info!("Invalid length for init.  ignore.");
                        } else {
                            self.last_channel += 1;
                            // info_now!(
                            //     "assigned channel {}", self.last_channel);
                            let _nonce = &self.buffer[..8];
                            let response = Response {
                                channel: cid,
                                command: request.command,
                                length: 17,
                            };

                            self.buffer[8..12].copy_from_slice(&self.last_channel.to_be_bytes());
                            // CTAPHID protocol version
                            self.buffer[12] = 2;
                            // major device version number
                            self.buffer[13] = self.version.major;
                            // minor device version number
                            self.buffer[14] = self.version.minor;
                            // build device version number
                            self.buffer[15] = self.version.build;
                            // capabilities flags
                            // 0x1: implements WINK
                            // 0x4: implements CBOR
                            // 0x8: does not implement MSG
                            // self.buffer[16] = 0x01 | 0x08;
                            self.buffer[16] = self.implements;
                            self.start_sending(response);
                        }
                    }
                }
            }

            Command::Ping => {
                let response = Response::from_request_and_size(request, request.length as usize);
                self.start_sending(response);
            }

            Command::Cancel => {
                info!("CTAPHID_CANCEL");
                self.cancel_ongoing_activity();
            }

            _ => {
                self.needs_keepalive = request.command == Command::Cbor;
                if self.interchange.state() == interchange::State::Responded {
                    info!("dumping stale response");
                    self.interchange.take_response();
                }
                match self.interchange.request((
                    request.command,
                    heapless::Vec::from_slice(&self.buffer[..request.length as usize]).unwrap(),
                )) {
                    Ok(_) => {
                        self.state = State::WaitingOnAuthenticator(request);
                        self.started_processing = true;
                    }
                    Err(_) => {
                        // busy
                        info_now!("STATE: {:?}", self.interchange.state());
                        info!("can't handle more than one authenticator request at a time.");
                        self.send_error_now(request, AuthenticatorError::ChannelBusy);
                    }
                }
            }
        }
    }

    pub fn did_start_processing(&mut self) -> bool {
        if self.started_processing {
            self.started_processing = false;
            true
        } else {
            false
        }
    }

    pub fn send_keepalive(&mut self, is_waiting_for_user_presence: bool) -> bool {
        if let State::WaitingOnAuthenticator(request) = &self.state {
            if !self.needs_keepalive {
                // let response go out normally in idle loop
                info!("cmd does not need keepalive messages");
                false
            } else {
                info!("keepalive");

                let response = Response {
                    channel: request.channel,
                    command: Command::KeepAlive,
                    length: 1,
                };
                let status = if is_waiting_for_user_presence {
                    KeepaliveStatus::UpNeeded
                } else {
                    KeepaliveStatus::Processing
                };
                self.endpoints
                    .write(Packet::init(response, &[status as u8]))
                    .ok();

                true
            }
        } else {
            info!("keepalive done");
            false
        }
    }

    #[inline(never)]
    pub fn handle_response(&mut self) {
        if let State::WaitingOnAuthenticator(request) = self.state {
            if let Ok(response) = self.interchange.response() {
                match &response.0 {
                    Err(DispatchError::InvalidCommand) => {
                        info!("Got waiting reply from authenticator??");
                        self.start_sending_error(request, AuthenticatorError::InvalidCommand);
                    }
                    Err(DispatchError::InvalidLength) => {
                        info!("Error, payload needed app command.");
                        self.start_sending_error(request, AuthenticatorError::InvalidLength);
                    }
                    Err(DispatchError::NoResponse) => {
                        info!("Got waiting noresponse from authenticator??");
                    }

                    Ok(message) => {
                        if message.len() > self.buffer.len() {
                            error!(
                                "Message is longer than buffer ({} > {})",
                                message.len(),
                                self.buffer.len(),
                            );
                            self.start_sending_error(request, AuthenticatorError::InvalidLength);
                        } else {
                            info!(
                                "Got {} bytes response from authenticator, starting send",
                                message.len()
                            );
                            let response = Response::from_request_and_size(request, message.len());
                            self.buffer[..message.len()].copy_from_slice(message);
                            self.start_sending(response);
                        }
                    }
                }
            }
        }
    }

    fn start_sending(&mut self, response: Response) {
        self.state = State::WaitingToSend(response);
        self.maybe_write_packet();
    }

    fn start_sending_error(&mut self, request: Request, error: AuthenticatorError) {
        self.start_sending_error_on_channel(request.channel, error);
    }

    fn start_sending_error_on_channel(&mut self, channel: u32, error: AuthenticatorError) {
        self.buffer[0] = error as u8;
        let response = Response::error_on_channel(channel);
        self.start_sending(response);
    }

    fn send_error_now(&mut self, request: Request, error: AuthenticatorError) {
        let response = Response::error_from_request(request);
        // TODO: should we block?
        self.endpoints
            .write(Packet::init(response, &[error as u8]))
            .ok();
    }

    // called from poll, and when a packet has been sent
    #[inline(never)]
    pub fn maybe_write_packet(&mut self) {
        let packet = match self.state {
            State::WaitingToSend(response) => Packet::init(response, &self.buffer),
            State::Sending((response, message_state)) => {
                Packet::cont(response, message_state, &self.buffer)
            }
            // nothing to send
            _ => {
                return;
            }
        };
        if self.endpoints.write(packet).is_ok() {
            self.state = packet.next_state();
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Packet<'a> {
    response: Response,
    message_state: Option<MessageState>,
    buffer: &'a [u8],
}

impl<'a> Packet<'a> {
    fn init(response: Response, buffer: &'a [u8]) -> Self {
        Self {
            response,
            message_state: None,
            buffer,
        }
    }

    fn cont(response: Response, message_state: MessageState, buffer: &'a [u8]) -> Self {
        Self {
            response,
            message_state: Some(message_state),
            buffer,
        }
    }

    fn has_more(&self) -> bool {
        if let Some(message_state) = self.message_state {
            let remaining = usize::from(self.response.length) - message_state.transmitted;
            remaining > PACKET_SIZE - 5
        } else {
            usize::from(self.response.length) > PACKET_SIZE - 7
        }
    }

    fn next_state(&self) -> State {
        if self.has_more() {
            let message_state = self
                .message_state
                .map(MessageState::absorb_packet)
                .unwrap_or_default();
            State::Sending((self.response, message_state))
        } else {
            State::Idle
        }
    }

    fn serialize(&self, buffer: &mut [u8; PACKET_SIZE]) {
        // buffer must be zeroed
        buffer[..4].copy_from_slice(&self.response.channel.to_be_bytes());
        if let Some(message_state) = self.message_state {
            buffer[4] = message_state.next_sequence;
            let remaining = usize::from(self.response.length) - message_state.transmitted;
            let n = remaining.min(PACKET_SIZE - 5);
            buffer[5..][..n].copy_from_slice(&self.buffer[message_state.transmitted..][..n]);
        } else {
            buffer[4] = self.response.command.into_u8() | 0x80;
            buffer[5..7].copy_from_slice(&self.response.length.to_be_bytes());
            let n = usize::from(self.response.length).min(PACKET_SIZE - 7);
            buffer[7..][..n].copy_from_slice(&self.buffer[..n]);
        }
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
