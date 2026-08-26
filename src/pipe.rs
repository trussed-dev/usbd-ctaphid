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

use core::convert::TryFrom;
use core::convert::TryInto;
use core::sync::atomic::Ordering;
// pub type ContactInterchange = usbd_ccid::types::ApduInterchange;
// pub type ContactlessInterchange = iso14443::types::ApduInterchange;

use ctaphid_dispatch::{app::Command, Requester};
use heapless_bytes::Bytes;
use ref_swap::OptionRefSwap;
use trussed_core::InterruptFlag;
// use serde::Serialize;
use usb_device::{
    bus::UsbBus,
    endpoint::{EndpointAddress, EndpointIn, EndpointOut},
    UsbError,
    // Result as UsbResult,
};

use crate::{constants::PACKET_SIZE, types::KeepaliveStatus};

// Immediate CTAPHID_ERROR replies do not use the main request/response state
// machine.  Keep enough small, fixed-size slots for several host applications
// contending for the authenticator without allocating in this no_std crate.
const PENDING_ERROR_CAPACITY: usize = 8;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-hid-error
// unused variants: InvalidParameter, LockRequired, Other
#[derive(Copy, Clone)]
enum AuthenticatorError {
    ChannelBusy,
    InvalidChannel,
    InvalidCommand,
    InvalidLength,
    InvalidSeq,
    Timeout,
}

impl From<AuthenticatorError> for u8 {
    fn from(error: AuthenticatorError) -> Self {
        match error {
            AuthenticatorError::InvalidCommand => 0x01,
            AuthenticatorError::InvalidLength => 0x03,
            AuthenticatorError::InvalidSeq => 0x04,
            AuthenticatorError::Timeout => 0x05,
            AuthenticatorError::ChannelBusy => 0x06,
            AuthenticatorError::InvalidChannel => 0x0B,
        }
    }
}

/// The actual payload of given length is dealt with separately
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Request {
    channel: u32,
    command: Command,
    length: u16,
    timestamp: u32,
}

/// The actual payload of given length is dealt with separately
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Response {
    channel: u32,
    command: Command,
    length: u16,
}

impl Response {
    pub fn from_request_and_size(request: Request, size: usize) -> Self {
        Self {
            channel: request.channel,
            command: request.command,
            length: size as u16,
        }
    }

    pub fn error_from_request(request: Request) -> Self {
        Self::error_on_channel(request.channel)
    }

    pub fn error_on_channel(channel: u32) -> Self {
        Self {
            channel,
            command: ctaphid_dispatch::app::Command::Error,
            length: 1,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageState {
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
    pub fn absorb_packet(&mut self) {
        self.next_sequence += 1;
        self.transmitted += PACKET_SIZE - 5;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
pub enum State {
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

pub struct Pipe<'alloc, 'pipe, 'interrupt, Bus: UsbBus, const N: usize> {
    read_endpoint: EndpointOut<'alloc, Bus>,
    write_endpoint: EndpointIn<'alloc, Bus>,
    state: State,

    interchange: Requester<'pipe, N>,
    interrupt: Option<&'interrupt OptionRefSwap<'interrupt, InterruptFlag>>,

    // shared between requests and responses, due to size
    buffer: [u8; N],

    // One-packet errors for competing channels.  These are kept separate from
    // `state` and `buffer` so replying to another channel cannot corrupt the
    // transaction currently being received, processed, or transmitted.
    pending_errors: [Option<(u32, AuthenticatorError)>; PENDING_ERROR_CAPACITY],

    // we assign channel IDs one by one, this is the one last assigned
    // TODO: move into "app"
    last_channel: u32,

    // Indicator of implemented commands in INIT response.
    pub(crate) implements: u8,

    // timestamp that gets used for timing out CID's
    pub(crate) last_milliseconds: u32,

    // a "read once" indicator if now we're waiting on the application processing
    started_processing: bool,

    needs_keepalive: bool,

    pub(crate) version: crate::Version,
}

impl<'alloc, 'pipe, Bus: UsbBus, const N: usize> Pipe<'alloc, 'pipe, '_, Bus, N> {
    pub(crate) fn new(
        read_endpoint: EndpointOut<'alloc, Bus>,
        write_endpoint: EndpointIn<'alloc, Bus>,
        interchange: Requester<'pipe, N>,
        initial_milliseconds: u32,
    ) -> Self {
        Self {
            read_endpoint,
            write_endpoint,
            state: State::Idle,
            interchange,
            buffer: [0u8; N],
            pending_errors: [None; PENDING_ERROR_CAPACITY],
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

impl<'alloc, 'pipe, 'interrupt, Bus: UsbBus, const N: usize>
    Pipe<'alloc, 'pipe, 'interrupt, Bus, N>
{
    // pub fn borrow_mut_authenticator(&mut self) -> &mut Authenticator {
    //     &mut self.authenticator
    // }

    pub(crate) fn with_interrupt(
        read_endpoint: EndpointOut<'alloc, Bus>,
        write_endpoint: EndpointIn<'alloc, Bus>,
        interchange: Requester<'pipe, N>,
        interrupt: Option<&'interrupt OptionRefSwap<'interrupt, InterruptFlag>>,
        initial_milliseconds: u32,
    ) -> Self {
        Self {
            read_endpoint,
            write_endpoint,
            state: State::Idle,
            interchange,
            buffer: [0u8; N],
            pending_errors: [None; PENDING_ERROR_CAPACITY],
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

    pub(crate) fn set_version(&mut self, version: crate::Version) {
        self.version = version;
    }

    pub fn read_address(&self) -> EndpointAddress {
        self.read_endpoint.address()
    }

    pub fn write_address(&self) -> EndpointAddress {
        self.write_endpoint.address()
    }

    // used to generate the configuration descriptors
    pub(crate) fn read_endpoint(&self) -> &EndpointOut<'alloc, Bus> {
        &self.read_endpoint
    }

    // used to generate the configuration descriptors
    pub(crate) fn write_endpoint(&self) -> &EndpointIn<'alloc, Bus> {
        &self.write_endpoint
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
    pub(crate) fn read_and_handle_packet(&mut self) {
        // info_now!("got a packet!");
        let mut packet = [0u8; PACKET_SIZE];
        match self.read_endpoint.read(&mut packet) {
            Ok(PACKET_SIZE) => {}
            Ok(_size) => {
                // error handling?
                // from spec: "Packets are always fixed size (defined by the endpoint and
                // HID report descriptors) and although all bytes may not be needed in a
                // particular packet, the full size always has to be sent.
                // Unused bytes SHOULD be set to zero."
                // !("OK but size {}", size);
                info!("error unexpected size {}", _size);
                return;
            }
            // usb-device lists WouldBlock or BufferOverflow as possible errors.
            // both should not occur here, and we can't do anything anyway.
            // Err(UsbError::WouldBlock) => { return; },
            // Err(UsbError::BufferOverflow) => { return; },
            Err(_error) => {
                info!("error no {}", _error as i32);
                return;
            }
        };
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
            let is_cancel = command_number == Command::Cancel.into_u8();
            // info_now!("command number {}", command_number);

            if self.state != State::Idle {
                let active_channel = match self.state {
                    State::WaitingOnAuthenticator(request) | State::Receiving((request, _)) => {
                        request.channel
                    }
                    State::WaitingToSend(response) | State::Sending((response, _)) => {
                        response.channel
                    }
                    State::Idle => unreachable!(),
                };

                // CTAPHID_CANCEL is not a transaction of its own.  The
                // specification requires a cancellation on a non-active CID to
                // be ignored rather than answered with CHANNEL_BUSY.
                if is_cancel && channel != active_channel {
                    info_now!("Ignoring cancellation on non-active channel.");
                    return;
                }

                if channel != active_channel {
                    info_now!("busy.");
                    self.send_error_now(channel, AuthenticatorError::ChannelBusy);
                    return;
                }

                if command_number == Command::Init.into_u8() {
                    info_now!("Resyncing!");
                    self.cancel_ongoing_activity();
                } else if is_cancel {
                    info_now!("Cancelling");
                    self.cancel_ongoing_activity();
                    return;
                } else {
                    info_now!("Expected continuation packet.");
                    self.start_sending_error_on_channel(
                        active_channel,
                        AuthenticatorError::InvalidSeq,
                    );
                    return;
                }
            }

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

            if length > N as u16 {
                info!("Error message too big.");
                self.send_error_now(current_request.channel, AuthenticatorError::InvalidLength);
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
                State::Receiving((mut request, mut message_state)) => {
                    let sequence = packet[4];
                    // info_now!("receiving continuation packet {}", sequence);
                    if channel != request.channel {
                        info!("Ignore invalid channel");
                        return;
                    }
                    if sequence != message_state.next_sequence {
                        // error handling?
                        // info_now!("wrong sequence for continuation packet, expected {} received {}",
                        //           message_state.next_sequence, sequence);
                        info!("Error invalid cont pkt");
                        self.start_sending_error(request, AuthenticatorError::InvalidSeq);
                        return;
                    }

                    // The receive timeout protects against a client that starts
                    // a fragmented message and then stops sending it.  It is an
                    // inactivity timeout, so every valid continuation packet on
                    // the active channel refreshes it.  Measuring from the init
                    // packet makes a maximum-size message time out even while it
                    // is making steady progress.
                    request.timestamp = self.last_milliseconds;

                    let payload_length = request.length as usize;
                    if message_state.transmitted + (PACKET_SIZE - 5) < payload_length {
                        // info_now!("transmitted {} + (PACKET_SIZE - 5) < {}",
                        //           message_state.transmitted, payload_length);
                        // store received part of payload
                        self.buffer[message_state.transmitted..][..PACKET_SIZE - 5]
                            .copy_from_slice(&packet[5..]);
                        message_state.absorb_packet();
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
            if milliseconds.wrapping_sub(last) > 200 {
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
            else if milliseconds.wrapping_sub(request.timestamp) > 550 {
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
                    Bytes::try_from(&self.buffer[..request.length as usize]).unwrap(),
                )) {
                    Ok(_) => {
                        self.state = State::WaitingOnAuthenticator(request);
                        self.started_processing = true;
                    }
                    Err(_) => {
                        // busy
                        info_now!("STATE: {:?}", self.interchange.state());
                        info!("can't handle more than one authenticator request at a time.");
                        self.send_error_now(request.channel, AuthenticatorError::ChannelBusy);
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

                let mut packet = [0u8; PACKET_SIZE];

                packet[..4].copy_from_slice(&request.channel.to_be_bytes());
                packet[4] = 0x80 | 0x3B;
                packet[5..7].copy_from_slice(&1u16.to_be_bytes());

                if is_waiting_for_user_presence {
                    packet[7] = KeepaliveStatus::UpNeeded as u8;
                } else {
                    packet[7] = KeepaliveStatus::Processing as u8;
                }

                self.write_endpoint.write(&packet).ok();

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
                    Err(ctaphid_dispatch::app::Error::InvalidCommand) => {
                        info!("Got waiting reply from authenticator??");
                        self.start_sending_error(request, AuthenticatorError::InvalidCommand);
                    }
                    Err(ctaphid_dispatch::app::Error::InvalidLength) => {
                        info!("Error, payload needed app command.");
                        self.start_sending_error(request, AuthenticatorError::InvalidLength);
                    }
                    Err(ctaphid_dispatch::app::Error::NoResponse) => {
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
        self.buffer[0] = error.into();
        let response = Response::error_on_channel(channel);
        self.start_sending(response);
    }

    fn send_error_now(&mut self, channel: u32, error: AuthenticatorError) {
        let error = (channel, error);
        if self.pending_errors[0].is_none() && self.write_error_packet(error) {
            return;
        }

        // Coalesce repeated retries from one channel until its existing error
        // has been sent.  A conforming client waits for that response before
        // starting another request on the same channel.
        if self
            .pending_errors
            .iter()
            .flatten()
            .any(|(channel, _)| *channel == error.0)
        {
            return;
        }

        if let Some(slot) = self.pending_errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            warn_now!("CTAPHID immediate error queue is full");
        }
    }

    fn write_error_packet(&mut self, (channel, error): (u32, AuthenticatorError)) -> bool {
        let mut packet = [0u8; PACKET_SIZE];
        packet[..4].copy_from_slice(&channel.to_be_bytes());
        packet[4] = ctaphid_dispatch::app::Command::Error.into_u8() | 0x80;
        packet[5..7].copy_from_slice(&1u16.to_be_bytes());
        packet[7] = error.into();

        match self.write_endpoint.write(&packet) {
            Err(UsbError::WouldBlock) => false,
            Err(_) => panic!("unexpected error writing packet!"),
            Ok(PACKET_SIZE) => true,
            Ok(_) => panic!("unexpected size writing packet!"),
        }
    }

    // called from poll, and when a packet has been sent
    #[inline(never)]
    pub(crate) fn maybe_write_packet(&mut self) {
        if let Some(error) = self.pending_errors[0] {
            if self.write_error_packet(error) {
                self.pending_errors.rotate_left(1);
                self.pending_errors[PENDING_ERROR_CAPACITY - 1] = None;
            }
            return;
        }

        match self.state {
            State::WaitingToSend(response) => {
                // zeros leftover bytes
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                // packet[4] = response.command.into() | 0x80u8;
                packet[4] = response.command.into_u8() | 0x80;
                packet[5..7].copy_from_slice(&response.length.to_be_bytes());

                let fits_in_one_packet = 7 + response.length as usize <= PACKET_SIZE;
                if fits_in_one_packet {
                    packet[7..][..response.length as usize]
                        .copy_from_slice(&self.buffer[..response.length as usize]);
                } else {
                    packet[7..].copy_from_slice(&self.buffer[..PACKET_SIZE - 7]);
                }

                // try actually sending
                // info_now!("attempting to write init packet {:?}, {:?}",
                //           &packet[..32], &packet[32..]);
                let result = self.write_endpoint.write(&packet);

                match result {
                    Err(UsbError::WouldBlock) => {
                        // fine, can't write try later
                        // this shouldn't happen probably
                        info!("hid usb WouldBlock");
                    }
                    Err(_) => {
                        // info_now!("weird USB errrorrr");
                        panic!("unexpected error writing packet!");
                    }
                    Ok(PACKET_SIZE) => {
                        // goodie, this worked
                        if fits_in_one_packet {
                            self.state = State::Idle;
                            // info_now!("StartSent {} bytes, idle again", response.length);
                            // info_now!("IDLE again");
                        } else {
                            self.state = State::Sending((response, MessageState::default()));
                            // info_now!(
                            //     "StartSent {} of {} bytes, waiting to send again",
                            //     PACKET_SIZE - 7, response.length);
                            // info_now!("State: {:?}", &self.state);
                        }
                    }
                    Ok(_) => {
                        // info_now!("short write");
                        panic!("unexpected size writing packet!");
                    }
                };
            }

            State::Sending((response, mut message_state)) => {
                // info_now!("in StillSending");
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                packet[4] = message_state.next_sequence;

                let sent = message_state.transmitted;
                let remaining = response.length as usize - sent;
                let last_packet = 5 + remaining <= PACKET_SIZE;
                if last_packet {
                    packet[5..][..remaining]
                        .copy_from_slice(&self.buffer[message_state.transmitted..][..remaining]);
                } else {
                    packet[5..].copy_from_slice(
                        &self.buffer[message_state.transmitted..][..PACKET_SIZE - 5],
                    );
                }

                // try actually sending
                // info_now!("attempting to write cont packet {:?}, {:?}",
                //           &packet[..32], &packet[32..]);
                let result = self.write_endpoint.write(&packet);

                match result {
                    Err(UsbError::WouldBlock) => {
                        // fine, can't write try later
                        // this shouldn't happen probably
                        // info_now!("can't send seq {}, write endpoint busy",
                        //           message_state.next_sequence);
                    }
                    Err(_) => {
                        // info_now!("weird USB error");
                        panic!("unexpected error writing packet!");
                    }
                    Ok(PACKET_SIZE) => {
                        // goodie, this worked
                        if last_packet {
                            self.state = State::Idle;
                            // info_now!("in IDLE state after {:?}", &message_state);
                        } else {
                            message_state.absorb_packet();
                            // DANGER! destructuring in the match arm copies out
                            // message state, so need to update state
                            // info_now!("sent one more, now {:?}", &message_state);
                            self.state = State::Sending((response, message_state));
                        }
                    }
                    Ok(_) => {
                        debug!("short write");
                        panic!("unexpected size writing packet!");
                    }
                };
            }

            // nothing to send
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use self::std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        vec::Vec,
    };
    use super::*;
    use usb_device::{
        bus::{PollResult, UsbBusAllocator},
        device::{UsbDeviceBuilder, UsbVidPid},
        endpoint::EndpointType,
        UsbDirection,
    };

    const MESSAGE_SIZE: usize = 7609;
    const ACTIVE_CHANNEL: u32 = 0x01020304;
    const OTHER_CHANNEL: u32 = 0x05060708;
    const THIRD_CHANNEL: u32 = 0x090a0b0c;

    #[derive(Default)]
    struct TestBusState {
        reads: VecDeque<[u8; PACKET_SIZE]>,
        writes: Vec<[u8; PACKET_SIZE]>,
        block_writes: bool,
    }

    struct TestBus {
        state: Arc<Mutex<TestBusState>>,
        next_in: usize,
        next_out: usize,
    }

    impl TestBus {
        fn new(state: Arc<Mutex<TestBusState>>) -> Self {
            Self {
                state,
                next_in: 1,
                next_out: 1,
            }
        }
    }

    impl UsbBus for TestBus {
        fn alloc_ep(
            &mut self,
            direction: UsbDirection,
            address: Option<EndpointAddress>,
            _endpoint_type: EndpointType,
            _max_packet_size: u16,
            _interval: u8,
        ) -> usb_device::Result<EndpointAddress> {
            if let Some(address) = address {
                return Ok(address);
            }
            let index = match direction {
                UsbDirection::In => {
                    let index = self.next_in;
                    self.next_in += 1;
                    index
                }
                UsbDirection::Out => {
                    let index = self.next_out;
                    self.next_out += 1;
                    index
                }
            };
            Ok(EndpointAddress::from_parts(index, direction))
        }

        fn enable(&mut self) {}
        fn reset(&self) {}
        fn set_device_address(&self, _address: u8) {}

        fn write(&self, _address: EndpointAddress, data: &[u8]) -> usb_device::Result<usize> {
            let mut state = self.state.lock().unwrap();
            if state.block_writes {
                return Err(UsbError::WouldBlock);
            }
            let packet: [u8; PACKET_SIZE] = data.try_into().unwrap();
            state.writes.push(packet);
            Ok(data.len())
        }

        fn read(&self, _address: EndpointAddress, data: &mut [u8]) -> usb_device::Result<usize> {
            let packet = self
                .state
                .lock()
                .unwrap()
                .reads
                .pop_front()
                .ok_or(UsbError::WouldBlock)?;
            data.copy_from_slice(&packet);
            Ok(packet.len())
        }

        fn set_stalled(&self, _address: EndpointAddress, _stalled: bool) {}
        fn is_stalled(&self, _address: EndpointAddress) -> bool {
            false
        }
        fn suspend(&self) {}
        fn resume(&self) {}
        fn poll(&self) -> PollResult {
            PollResult::None
        }
    }

    fn with_pipe(
        test: impl FnOnce(&mut Pipe<'_, '_, '_, TestBus, MESSAGE_SIZE>, &Arc<Mutex<TestBusState>>),
    ) {
        let state = Arc::new(Mutex::new(TestBusState::default()));
        let allocator = UsbBusAllocator::new(TestBus::new(Arc::clone(&state)));
        let channel = ctaphid_dispatch::Channel::<MESSAGE_SIZE>::new();
        let (requester, _responder) = channel.split().unwrap();
        let read_endpoint: EndpointOut<'_, TestBus> = allocator.interrupt(PACKET_SIZE as u16, 5);
        let write_endpoint: EndpointIn<'_, TestBus> = allocator.interrupt(PACKET_SIZE as u16, 5);
        let mut pipe = Pipe::new(read_endpoint, write_endpoint, requester, 0);
        let _device = UsbDeviceBuilder::new(&allocator, UsbVidPid(0x1209, 0xbeee)).build();

        test(&mut pipe, &state);
    }

    fn request(channel: u32, command: Command, length: u16) -> Request {
        Request {
            channel,
            command,
            length,
            timestamp: 0,
        }
    }

    fn initialization_packet(channel: u32, command: Command, length: u16) -> [u8; PACKET_SIZE] {
        let mut packet = [0u8; PACKET_SIZE];
        packet[..4].copy_from_slice(&channel.to_be_bytes());
        packet[4] = command.into_u8() | 0x80;
        packet[5..7].copy_from_slice(&length.to_be_bytes());
        packet
    }

    fn unknown_command_packet(channel: u32) -> [u8; PACKET_SIZE] {
        let mut packet = [0u8; PACKET_SIZE];
        packet[..4].copy_from_slice(&channel.to_be_bytes());
        packet[4] = 0xfe;
        packet
    }

    fn continuation_packet(channel: u32, sequence: u8) -> [u8; PACKET_SIZE] {
        let mut packet = [0u8; PACKET_SIZE];
        packet[..4].copy_from_slice(&channel.to_be_bytes());
        packet[4] = sequence;
        packet
    }

    fn assert_busy_error(packet: &[u8; PACKET_SIZE]) {
        assert_error(packet, OTHER_CHANNEL, 0x06);
    }

    fn assert_error(packet: &[u8; PACKET_SIZE], channel: u32, error: u8) {
        assert_eq!(&packet[..4], &channel.to_be_bytes());
        assert_eq!(packet[4], Command::Error.into_u8() | 0x80);
        assert_eq!(&packet[5..7], &1u16.to_be_bytes());
        assert_eq!(packet[7], error);
    }

    #[test]
    fn competing_channel_receives_channel_busy() {
        with_pipe(|pipe, bus| {
            let active = State::Receiving((
                request(ACTIVE_CHANNEL, Command::Ping, 100),
                MessageState::default(),
            ));
            pipe.state = active.clone();
            bus.lock().unwrap().reads.push_back(initialization_packet(
                OTHER_CHANNEL,
                Command::Ping,
                0,
            ));

            pipe.read_and_handle_packet();

            let bus = bus.lock().unwrap();
            assert_eq!(pipe.state, active);
            assert_eq!(bus.writes.len(), 1);
            assert_busy_error(&bus.writes[0]);
        });
    }

    #[test]
    fn foreign_continuation_does_not_abort_active_channel() {
        with_pipe(|pipe, bus| {
            let message_state = MessageState {
                next_sequence: 3,
                ..MessageState::default()
            };
            let active =
                State::Receiving((request(ACTIVE_CHANNEL, Command::Ping, 200), message_state));
            pipe.state = active.clone();
            bus.lock()
                .unwrap()
                .reads
                .push_back(continuation_packet(OTHER_CHANNEL, 0));

            pipe.read_and_handle_packet();

            let bus = bus.lock().unwrap();
            assert_eq!(pipe.state, active);
            assert!(bus.writes.is_empty());
        });
    }

    #[test]
    fn unknown_command_on_competing_channel_receives_busy() {
        with_pipe(|pipe, bus| {
            let active = State::Receiving((
                request(ACTIVE_CHANNEL, Command::Ping, 100),
                MessageState::default(),
            ));
            pipe.state = active.clone();
            bus.lock()
                .unwrap()
                .reads
                .push_back(unknown_command_packet(OTHER_CHANNEL));

            pipe.read_and_handle_packet();

            let bus = bus.lock().unwrap();
            assert_eq!(pipe.state, active);
            assert_eq!(bus.writes.len(), 1);
            assert_busy_error(&bus.writes[0]);
        });
    }

    #[test]
    fn cancel_on_non_active_channel_is_ignored() {
        with_pipe(|pipe, bus| {
            let active = State::Sending((
                Response::from_request_and_size(request(ACTIVE_CHANNEL, Command::Ping, 100), 100),
                MessageState::default(),
            ));
            pipe.state = active.clone();
            bus.lock().unwrap().reads.push_back(initialization_packet(
                OTHER_CHANNEL,
                Command::Cancel,
                0,
            ));

            pipe.read_and_handle_packet();

            let bus = bus.lock().unwrap();
            assert_eq!(pipe.state, active);
            assert!(bus.writes.is_empty());
        });
    }

    #[test]
    fn valid_continuations_refresh_receive_timeout() {
        with_pipe(|pipe, bus| {
            pipe.last_milliseconds = 500;
            pipe.state = State::Receiving((
                request(ACTIVE_CHANNEL, Command::Ping, 200),
                MessageState::default(),
            ));
            bus.lock()
                .unwrap()
                .reads
                .push_back(continuation_packet(ACTIVE_CHANNEL, 0));

            pipe.read_and_handle_packet();

            let State::Receiving((request, message_state)) = pipe.state else {
                panic!("pipe stopped receiving a message that was making progress");
            };
            assert_eq!(request.timestamp, 500);
            assert_eq!(message_state.next_sequence, 1);

            // More than 550 ms from the initialization packet, but only 400 ms
            // from the last valid continuation packet: the request is alive.
            pipe.check_timeout(700);
            pipe.check_timeout(900);
            assert!(matches!(pipe.state, State::Receiving(_)));
            assert!(bus.lock().unwrap().writes.is_empty());

            // It is aborted after 550 ms without another valid packet.
            pipe.check_timeout(1051);
            let bus = bus.lock().unwrap();
            assert_eq!(bus.writes.len(), 1);
            assert_eq!(&bus.writes[0][..4], &ACTIVE_CHANNEL.to_be_bytes());
            assert_eq!(bus.writes[0][4], Command::Error.into_u8() | 0x80);
            assert_eq!(&bus.writes[0][5..7], &1u16.to_be_bytes());
            assert_eq!(bus.writes[0][7], 0x05);
        });
    }

    #[test]
    fn competing_channel_receives_busy_while_response_is_sending() {
        with_pipe(|pipe, bus| {
            let active = State::Sending((
                Response::from_request_and_size(request(ACTIVE_CHANNEL, Command::Ping, 100), 100),
                MessageState::default(),
            ));
            pipe.state = active.clone();
            bus.lock().unwrap().reads.push_back(initialization_packet(
                OTHER_CHANNEL,
                Command::Ping,
                0,
            ));

            pipe.read_and_handle_packet();

            let bus = bus.lock().unwrap();
            assert_eq!(pipe.state, active);
            assert_eq!(bus.writes.len(), 1);
            assert_busy_error(&bus.writes[0]);
        });
    }

    #[test]
    fn busy_error_is_retried_when_endpoint_would_block() {
        with_pipe(|pipe, bus| {
            let active = State::Receiving((
                request(ACTIVE_CHANNEL, Command::Ping, 100),
                MessageState::default(),
            ));
            pipe.state = active.clone();
            {
                let mut bus = bus.lock().unwrap();
                bus.block_writes = true;
                bus.reads
                    .push_back(initialization_packet(OTHER_CHANNEL, Command::Ping, 0));
            }

            pipe.read_and_handle_packet();
            assert_eq!(pipe.state, active);
            assert_eq!(pipe.pending_errors.iter().flatten().count(), 1);

            bus.lock().unwrap().block_writes = false;
            pipe.maybe_write_packet();

            let bus = bus.lock().unwrap();
            assert_eq!(pipe.state, active);
            assert!(pipe.pending_errors.iter().all(Option::is_none));
            assert_eq!(bus.writes.len(), 1);
            assert_busy_error(&bus.writes[0]);
        });
    }

    #[test]
    fn pending_error_queue_keeps_out_endpoint_draining() {
        with_pipe(|pipe, bus| {
            pipe.state = State::Receiving((
                request(ACTIVE_CHANNEL, Command::Ping, 100),
                MessageState::default(),
            ));
            {
                let mut bus = bus.lock().unwrap();
                bus.block_writes = true;
                bus.reads
                    .push_back(initialization_packet(OTHER_CHANNEL, Command::Ping, 0));
                bus.reads
                    .push_back(initialization_packet(THIRD_CHANNEL, Command::Ping, 0));
            }

            pipe.read_and_handle_packet();
            pipe.read_and_handle_packet();
            assert_eq!(pipe.pending_errors.iter().flatten().count(), 2);
            assert!(bus.lock().unwrap().reads.is_empty());

            // Once IN accepts reports, drain the errors in arrival order.
            bus.lock().unwrap().block_writes = false;
            pipe.maybe_write_packet();
            assert_eq!(pipe.pending_errors.iter().flatten().count(), 1);
            pipe.maybe_write_packet();

            let bus = bus.lock().unwrap();
            assert!(pipe.pending_errors.iter().all(Option::is_none));
            assert!(bus.reads.is_empty());
            assert_eq!(bus.writes.len(), 2);
            assert_error(&bus.writes[0], OTHER_CHANNEL, 0x06);
            assert_error(&bus.writes[1], THIRD_CHANNEL, 0x06);
        });
    }

    #[test]
    fn pending_error_queue_coalesces_retries_from_one_channel() {
        with_pipe(|pipe, bus| {
            pipe.state = State::Receiving((
                request(ACTIVE_CHANNEL, Command::Ping, 100),
                MessageState::default(),
            ));
            {
                let mut bus = bus.lock().unwrap();
                bus.block_writes = true;
                bus.reads
                    .push_back(initialization_packet(OTHER_CHANNEL, Command::Ping, 0));
                bus.reads
                    .push_back(initialization_packet(OTHER_CHANNEL, Command::Ping, 0));
            }

            pipe.read_and_handle_packet();
            pipe.read_and_handle_packet();

            assert_eq!(pipe.pending_errors.iter().flatten().count(), 1);
            assert!(bus.lock().unwrap().reads.is_empty());
        });
    }

    #[test]
    fn single_packet_response_is_retried_when_endpoint_would_block() {
        with_pipe(|pipe, bus| {
            pipe.buffer[0] = 0x42;
            pipe.state = State::WaitingToSend(Response::from_request_and_size(
                request(ACTIVE_CHANNEL, Command::Ping, 1),
                1,
            ));
            bus.lock().unwrap().block_writes = true;

            pipe.maybe_write_packet();

            assert!(matches!(pipe.state, State::WaitingToSend(_)));
            assert!(bus.lock().unwrap().writes.is_empty());

            bus.lock().unwrap().block_writes = false;
            pipe.maybe_write_packet();

            let bus = bus.lock().unwrap();
            assert_eq!(pipe.state, State::Idle);
            assert_eq!(bus.writes.len(), 1);
            assert_eq!(&bus.writes[0][..4], &ACTIVE_CHANNEL.to_be_bytes());
            assert_eq!(bus.writes[0][4], Command::Ping.into_u8() | 0x80);
            assert_eq!(&bus.writes[0][5..7], &1u16.to_be_bytes());
            assert_eq!(bus.writes[0][7], 0x42);
        });
    }
}
