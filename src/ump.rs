//! Universal MIDI Packet (UMP) / MIDI 2.0 support
//!
//! This module provides support for MIDI 2.0 Universal MIDI Packets (UMP).
//! UMP is the new packet format introduced with MIDI 2.0 that supports both
//! legacy MIDI 1.0 messages and new MIDI 2.0 messages with extended features.

use libc::{c_int, c_uint, size_t, pollfd, c_short};
use super::error::*;
use super::poll;
use crate::alsa;
use core::ptr;
use core::ffi::CStr;
use ::alloc::string::{String, ToString};

/// [snd_ump_t](https://www.alsa-project.org/alsa-doc/alsa-lib/ump_8c.html) wrapper
///
/// Represents a UMP (Universal MIDI Packet) device for MIDI 2.0 communication.
#[derive(Debug)]
pub struct Ump(*mut alsa::snd_ump_t);

unsafe impl Send for Ump {}

impl Drop for Ump {
    fn drop(&mut self) {
        unsafe { alsa::snd_ump_close(self.0) };
    }
}

impl Ump {
    /// Opens a UMP device
    ///
    /// # Arguments
    /// * `name` - Device name (e.g., "hw:0,0")
    /// * `dir` - Direction (input, output, or bidirectional)
    /// * `mode` - Open mode flags
    pub fn open(name: &CStr, dir: UmpDirection, mode: c_int) -> Result<Self> {
        let mut input_ptr: *mut alsa::snd_ump_t = ptr::null_mut();
        let mut output_ptr: *mut alsa::snd_ump_t = ptr::null_mut();
        
        let (inp, outp) = match dir {
            UmpDirection::Input => (&mut input_ptr as *mut *mut alsa::snd_ump_t, ptr::null_mut()),
            UmpDirection::Output => (ptr::null_mut(), &mut output_ptr as *mut *mut alsa::snd_ump_t),
            UmpDirection::Bidirection => (&mut input_ptr as *mut *mut alsa::snd_ump_t, &mut output_ptr as *mut *mut alsa::snd_ump_t),
        };
        
        acheck!(snd_ump_open(inp, outp, name.as_ptr(), mode))?;
        
        let ptr = if !input_ptr.is_null() {
            input_ptr
        } else {
            output_ptr
        };
        
        Ok(Ump(ptr))
    }

    /// Gets the UMP device name
    pub fn name(&self) -> Result<String> {
        let c = unsafe { alsa::snd_ump_name(self.0) };
        from_const("snd_ump_name", c).map(|s| s.to_string())
    }

    /// Gets the underlying rawmidi handle
    pub fn rawmidi(&self) -> *mut alsa::snd_rawmidi_t {
        unsafe { alsa::snd_ump_rawmidi(self.0) }
    }

    /// Sets non-blocking mode
    pub fn nonblock(&self, nonblock: bool) -> Result<()> {
        acheck!(snd_ump_nonblock(self.0, if nonblock { 1 } else { 0 })).map(|_| ())
    }

    /// Drops all pending data
    pub fn drop(&self) -> Result<()> {
        acheck!(snd_ump_drop(self.0)).map(|_| ())
    }

    /// Drains all pending data
    pub fn drain(&self) -> Result<()> {
        acheck!(snd_ump_drain(self.0)).map(|_| ())
    }

    /// Writes UMP packets
    ///
    /// The buffer should contain 32-bit words representing UMP packets.
    /// Returns the number of 32-bit words written.
    pub fn write(&self, buffer: &[u32]) -> Result<usize> {
        let size = buffer.len() * 4; // Convert words to bytes
        let r = unsafe {
            alsa::snd_ump_write(
                self.0,
                buffer.as_ptr() as *const ::core::ffi::c_void,
                size as size_t
            )
        };
        from_code("snd_ump_write", r as c_int).map(|_| (r as usize) / 4)
    }

    /// Reads UMP packets
    ///
    /// The buffer will be filled with 32-bit words representing UMP packets.
    /// Returns the number of 32-bit words read.
    pub fn read(&self, buffer: &mut [u32]) -> Result<usize> {
        let size = buffer.len() * 4; // Convert words to bytes
        let r = unsafe {
            alsa::snd_ump_read(
                self.0,
                buffer.as_mut_ptr() as *mut ::core::ffi::c_void,
                size as size_t
            )
        };
        from_code("snd_ump_read", r as c_int).map(|_| (r as usize) / 4)
    }

    /// Reads UMP packets with timestamp
    ///
    /// Returns a tuple of (number of words read, timestamp).
    pub fn tread(&self, buffer: &mut [u32]) -> Result<(usize, libc::timespec)> {
        let size = buffer.len() * 4;
        let mut tstamp: libc::timespec = unsafe { core::mem::zeroed() };
        let r = unsafe {
            alsa::snd_ump_tread(
                self.0,
                &mut tstamp,
                buffer.as_mut_ptr() as *mut ::core::ffi::c_void,
                size as size_t
            )
        };
        from_code("snd_ump_tread", r as c_int).map(|_| ((r as usize) / 4, tstamp))
    }

    /// Gets endpoint information
    pub fn endpoint_info(&self) -> Result<UmpEndpointInfo> {
        let info = UmpEndpointInfo::new()?;
        acheck!(snd_ump_endpoint_info(self.0, info.0)).map(|_| info)
    }

    /// Gets block information for a specific block
    pub fn block_info(&self, block_id: u32) -> Result<UmpBlockInfo> {
        let info = UmpBlockInfo::new()?;
        unsafe { alsa::snd_ump_block_info_set_block_id(info.0, block_id as c_uint) };
        acheck!(snd_ump_block_info(self.0, info.0)).map(|_| info)
    }
}

impl poll::Descriptors for Ump {
    fn count(&self) -> usize {
        unsafe { alsa::snd_ump_poll_descriptors_count(self.0) as usize }
    }

    fn fill(&self, p: &mut [pollfd]) -> Result<usize> {
        let z = unsafe {
            alsa::snd_ump_poll_descriptors(self.0, p.as_mut_ptr(), p.len() as c_uint)
        };
        from_code("snd_ump_poll_descriptors", z).map(|_| z as usize)
    }

    fn revents(&self, p: &[pollfd]) -> Result<poll::Flags> {
        let mut r = 0;
        let z = unsafe {
            alsa::snd_ump_poll_descriptors_revents(
                self.0,
                p.as_ptr() as *mut pollfd,
                p.len() as c_uint,
                &mut r
            )
        };
        from_code("snd_ump_poll_descriptors_revents", z)
            .map(|_| poll::Flags::from_bits_truncate(r as c_short))
    }
}

/// UMP direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UmpDirection {
    Input = alsa::SND_UMP_DIR_INPUT as isize,
    Output = alsa::SND_UMP_DIR_OUTPUT as isize,
    Bidirection = alsa::SND_UMP_DIR_BIDIRECTION as isize,
}

/// [snd_ump_endpoint_info_t](https://www.alsa-project.org/alsa-doc/alsa-lib/ump_8c.html) wrapper
///
/// Contains information about a UMP endpoint.
#[derive(Debug)]
pub struct UmpEndpointInfo(pub(crate) *mut alsa::snd_ump_endpoint_info_t);

unsafe impl Send for UmpEndpointInfo {}

impl Drop for UmpEndpointInfo {
    fn drop(&mut self) {
        unsafe { alsa::snd_ump_endpoint_info_free(self.0) };
    }
}

impl UmpEndpointInfo {
    fn new() -> Result<Self> {
        let mut p = ptr::null_mut();
        acheck!(snd_ump_endpoint_info_malloc(&mut p)).map(|_| UmpEndpointInfo(p))
    }

    /// Creates a new UmpEndpointInfo with all fields cleared
    pub fn empty() -> Result<Self> {
        let info = Self::new()?;
        unsafe { alsa::snd_ump_endpoint_info_clear(info.0) };
        Ok(info)
    }

    pub fn get_card(&self) -> i32 {
        unsafe { alsa::snd_ump_endpoint_info_get_card(self.0) }
    }

    pub fn get_device(&self) -> i32 {
        unsafe { alsa::snd_ump_endpoint_info_get_device(self.0) }
    }

    pub fn get_flags(&self) -> u32 {
        unsafe { alsa::snd_ump_endpoint_info_get_flags(self.0) }
    }

    pub fn get_protocol_caps(&self) -> u32 {
        unsafe { alsa::snd_ump_endpoint_info_get_protocol_caps(self.0) }
    }

    pub fn get_protocol(&self) -> u32 {
        unsafe { alsa::snd_ump_endpoint_info_get_protocol(self.0) }
    }

    pub fn get_num_blocks(&self) -> u32 {
        unsafe { alsa::snd_ump_endpoint_info_get_num_blocks(self.0) }
    }

    pub fn get_version(&self) -> u32 {
        unsafe { alsa::snd_ump_endpoint_info_get_version(self.0) }
    }

    pub fn get_manufacturer_id(&self) -> u32 {
        unsafe { alsa::snd_ump_endpoint_info_get_manufacturer_id(self.0) }
    }

    pub fn get_family_id(&self) -> u32 {
        unsafe { alsa::snd_ump_endpoint_info_get_family_id(self.0) }
    }

    pub fn get_model_id(&self) -> u32 {
        unsafe { alsa::snd_ump_endpoint_info_get_model_id(self.0) }
    }

    pub fn get_sw_revision(&self) -> [u8; 4] {
        unsafe {
            let ptr = alsa::snd_ump_endpoint_info_get_sw_revision(self.0);
            let mut result = [0u8; 4];
            for i in 0..4 {
                result[i] = *ptr.offset(i as isize);
            }
            result
        }
    }

    pub fn get_name(&self) -> Result<&str> {
        let c = unsafe { alsa::snd_ump_endpoint_info_get_name(self.0) };
        from_const("snd_ump_endpoint_info_get_name", c)
    }

    pub fn get_product_id(&self) -> Result<&str> {
        let c = unsafe { alsa::snd_ump_endpoint_info_get_product_id(self.0) };
        from_const("snd_ump_endpoint_info_get_product_id", c)
    }

    pub fn set_card(&self, card: u32) {
        unsafe { alsa::snd_ump_endpoint_info_set_card(self.0, card) };
    }

    pub fn set_device(&self, device: u32) {
        unsafe { alsa::snd_ump_endpoint_info_set_device(self.0, device) };
    }

    pub fn set_flags(&self, flags: u32) {
        unsafe { alsa::snd_ump_endpoint_info_set_flags(self.0, flags) };
    }

    pub fn set_protocol_caps(&self, caps: u32) {
        unsafe { alsa::snd_ump_endpoint_info_set_protocol_caps(self.0, caps) };
    }

    pub fn set_protocol(&self, protocol: u32) {
        unsafe { alsa::snd_ump_endpoint_info_set_protocol(self.0, protocol) };
    }

    pub fn set_name(&self, name: &CStr) {
        unsafe { alsa::snd_ump_endpoint_info_set_name(self.0, name.as_ptr()) };
    }

    pub fn set_product_id(&self, product_id: &CStr) {
        unsafe { alsa::snd_ump_endpoint_info_set_product_id(self.0, product_id.as_ptr()) };
    }
}

/// [snd_ump_block_info_t](https://www.alsa-project.org/alsa-doc/alsa-lib/ump_8c.html) wrapper
///
/// Contains information about a UMP function block.
#[derive(Debug)]
pub struct UmpBlockInfo(pub(crate) *mut alsa::snd_ump_block_info_t);

unsafe impl Send for UmpBlockInfo {}

impl Drop for UmpBlockInfo {
    fn drop(&mut self) {
        unsafe { alsa::snd_ump_block_info_free(self.0) };
    }
}

impl UmpBlockInfo {
    fn new() -> Result<Self> {
        let mut p = ptr::null_mut();
        acheck!(snd_ump_block_info_malloc(&mut p)).map(|_| UmpBlockInfo(p))
    }

    /// Creates a new UmpBlockInfo with all fields cleared
    pub fn empty() -> Result<Self> {
        let info = Self::new()?;
        unsafe { alsa::snd_ump_block_info_clear(info.0) };
        Ok(info)
    }

    pub fn get_card(&self) -> i32 {
        unsafe { alsa::snd_ump_block_info_get_card(self.0) }
    }

    pub fn get_device(&self) -> i32 {
        unsafe { alsa::snd_ump_block_info_get_device(self.0) }
    }

    pub fn get_block_id(&self) -> u32 {
        unsafe { alsa::snd_ump_block_info_get_block_id(self.0) }
    }

    pub fn get_active(&self) -> u32 {
        unsafe { alsa::snd_ump_block_info_get_active(self.0) }
    }

    pub fn get_flags(&self) -> u32 {
        unsafe { alsa::snd_ump_block_info_get_flags(self.0) }
    }

    pub fn get_direction(&self) -> UmpDirection {
        let dir = unsafe { alsa::snd_ump_block_info_get_direction(self.0) };
        match dir {
            alsa::SND_UMP_DIR_INPUT => UmpDirection::Input,
            alsa::SND_UMP_DIR_OUTPUT => UmpDirection::Output,
            _ => UmpDirection::Bidirection,
        }
    }

    pub fn get_first_group(&self) -> u32 {
        unsafe { alsa::snd_ump_block_info_get_first_group(self.0) }
    }

    pub fn get_num_groups(&self) -> u32 {
        unsafe { alsa::snd_ump_block_info_get_num_groups(self.0) }
    }

    pub fn get_midi_ci_version(&self) -> u32 {
        unsafe { alsa::snd_ump_block_info_get_midi_ci_version(self.0) }
    }

    pub fn get_sysex8_streams(&self) -> u32 {
        unsafe { alsa::snd_ump_block_info_get_sysex8_streams(self.0) }
    }

    pub fn get_ui_hint(&self) -> UmpBlockUIHint {
        let hint = unsafe { alsa::snd_ump_block_info_get_ui_hint(self.0) };
        match hint {
            alsa::SND_UMP_BLOCK_UI_HINT_RECEIVER => UmpBlockUIHint::Receiver,
            alsa::SND_UMP_BLOCK_UI_HINT_SENDER => UmpBlockUIHint::Sender,
            alsa::SND_UMP_BLOCK_UI_HINT_BOTH => UmpBlockUIHint::Both,
            _ => UmpBlockUIHint::Unknown,
        }
    }

    pub fn get_name(&self) -> Result<&str> {
        let c = unsafe { alsa::snd_ump_block_info_get_name(self.0) };
        from_const("snd_ump_block_info_get_name", c)
    }

    pub fn set_card(&self, card: u32) {
        unsafe { alsa::snd_ump_block_info_set_card(self.0, card) };
    }

    pub fn set_device(&self, device: u32) {
        unsafe { alsa::snd_ump_block_info_set_device(self.0, device) };
    }

    pub fn set_block_id(&self, block_id: u32) {
        unsafe { alsa::snd_ump_block_info_set_block_id(self.0, block_id) };
    }

    pub fn set_active(&self, active: u32) {
        unsafe { alsa::snd_ump_block_info_set_active(self.0, active) };
    }

    pub fn set_direction(&self, direction: UmpDirection) {
        unsafe { alsa::snd_ump_block_info_set_direction(self.0, direction as c_uint) };
    }

    pub fn set_first_group(&self, group: u32) {
        unsafe { alsa::snd_ump_block_info_set_first_group(self.0, group) };
    }

    pub fn set_num_groups(&self, num: u32) {
        unsafe { alsa::snd_ump_block_info_set_num_groups(self.0, num) };
    }

    pub fn set_ui_hint(&self, hint: UmpBlockUIHint) {
        unsafe { alsa::snd_ump_block_info_set_ui_hint(self.0, hint as c_uint) };
    }

    pub fn set_name(&self, name: &CStr) {
        unsafe { alsa::snd_ump_block_info_set_name(self.0, name.as_ptr()) };
    }
}

/// UMP block UI hint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UmpBlockUIHint {
    Unknown = alsa::SND_UMP_BLOCK_UI_HINT_UNKNOWN as isize,
    Receiver = alsa::SND_UMP_BLOCK_UI_HINT_RECEIVER as isize,
    Sender = alsa::SND_UMP_BLOCK_UI_HINT_SENDER as isize,
    Both = alsa::SND_UMP_BLOCK_UI_HINT_BOTH as isize,
}

/// Expands a SysEx message from UMP format
///
/// # Arguments
/// * `ump` - UMP packet data (array of u32 words)
/// * `buf` - Output buffer for expanded SysEx data
///
/// Returns the number of bytes written to the buffer.
pub fn sysex_expand(ump: &[u32], buf: &mut [u8]) -> Result<usize> {
    let mut consumed = 0usize;
    let r = unsafe {
        alsa::snd_ump_msg_sysex_expand(
            ump.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as size_t,
            &mut consumed
        )
    };
    from_code("snd_ump_msg_sysex_expand", r).map(|_| r as usize)
}

/// Gets the packet length for a given UMP message type
///
/// Returns the number of 32-bit words in a packet of the given type.
pub fn packet_length(msg_type: u32) -> Result<usize> {
    let r = unsafe { alsa::snd_ump_packet_length(msg_type) };
    from_code("snd_ump_packet_length", r).map(|_| r as usize)
}

#[test]
fn test_ump_endpoint_info() {
    let info = UmpEndpointInfo::empty().unwrap();
    info.set_card(0);
    info.set_device(0);
    assert_eq!(info.get_card(), 0);
    assert_eq!(info.get_device(), 0);
}

#[test]
fn test_ump_block_info() {
    let info = UmpBlockInfo::empty().unwrap();
    info.set_block_id(0);
    info.set_direction(UmpDirection::Bidirection);
    assert_eq!(info.get_block_id(), 0);
    assert_eq!(info.get_direction(), UmpDirection::Bidirection);
}
