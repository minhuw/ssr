use chrono::DateTime;
use chrono::NaiveDateTime;
use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;
use pin_project::pin_project;
use std::fs::File;
use std::mem::transmute;
use std::mem::MaybeUninit;
use std::pin::Pin;

use crate::common::{ConnectionFilterConfig, EventPoller, Flow, FlowBPF, RecordWriter};
use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/sendstory.skel.rs"
    ));
}

use bpf::{OpenSendstorySkel, SendstorySkel, SendstorySkelBuilder};

#[repr(C)]
#[derive(Clone, Debug)]

pub struct BufferEvent {
    timestamp_ns: u64,
    flow: FlowBPF,
    event_type: i32,
    snd_nxt: u32,
    snd_una: u32,
    write_seq: u32,
    seq: u32,
    len: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    Packet = 1,
    PacketDone = 2,
    AppSend = 3,
    AppSendDone = 4,
    Ack = 5,
}

impl TryFrom<i32> for EventType {
    type Error = anyhow::Error;

    fn try_from(event_type: i32) -> Result<Self> {
        match event_type {
            1 => Ok(EventType::Packet),
            2 => Ok(EventType::PacketDone),
            3 => Ok(EventType::AppSend),
            4 => Ok(EventType::AppSendDone),
            5 => Ok(EventType::Ack),
            _ => Err(anyhow::anyhow!("Invalid event type: {}", event_type)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BufferMessage {
    time: NaiveDateTime,
    #[serde(flatten)]
    flow: Flow,
    event_type: EventType,
    snd_nxt: u32,
    snd_una: u32,
    write_seq: u32,
    sent_len: u32,
    wait_len: u32,
    seq: u32,
    len: u32,
}

impl Default for BufferMessage {
    fn default() -> Self {
        Self {
            time: DateTime::from_timestamp(0, 0)
                .unwrap_or_default()
                .naive_utc(),
            flow: Flow::default(),
            event_type: EventType::Packet,
            snd_nxt: 0,
            snd_una: 0,
            write_seq: 0,
            sent_len: 0,
            wait_len: 0,
            seq: 0,
            len: 0,
        }
    }
}

impl TryFrom<&[u8]> for BufferMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<BufferEvent>() {
            return Err(anyhow::anyhow!("Data size mismatch"));
        }
        let buffer_event = unsafe { &*(data.as_ptr() as *const BufferEvent) };
        Ok(Self {
            time: DateTime::from_timestamp(
                buffer_event.timestamp_ns as i64 / 1_000_000_000,
                (buffer_event.timestamp_ns % 1_000_000_000) as u32,
            )
            .unwrap_or_default()
            .naive_utc(),
            flow: Flow::from(&buffer_event.flow),
            event_type: EventType::try_from(buffer_event.event_type)?,
            snd_nxt: buffer_event.snd_nxt,
            snd_una: buffer_event.snd_una,
            write_seq: buffer_event.write_seq,
            sent_len: u32::wrapping_sub(buffer_event.snd_nxt, buffer_event.snd_una),
            wait_len: u32::wrapping_sub(buffer_event.write_seq, buffer_event.snd_nxt),
            seq: buffer_event.seq,
            len: buffer_event.len,
        })
    }
}

#[pin_project]
pub struct SendStoryEventTracker {
    #[pin]
    skel: SendstorySkel<'static>, // Using 'static lifetime
    ringbuf: RingBuffer<'static>,
    open_object: Box<MaybeUninit<OpenObject>>,
}

impl SendStoryEventTracker {
    pub fn new(
        filter_config: &ConnectionFilterConfig,
        result_file: File,
    ) -> Result<Pin<Box<Self>>> {
        let skel_builder = SendstorySkelBuilder::default();

        let mut open_object: Box<MaybeUninit<OpenObject>> = Box::new(MaybeUninit::uninit());
        let open_skel: OpenSendstorySkel =
            unsafe { transmute(skel_builder.open(&mut open_object)?) };

        open_skel.maps.rodata_data.tgt_src_port = filter_config.src_port;
        open_skel.maps.rodata_data.tgt_dst_port = filter_config.dst_port.to_be();

        let mut skel = open_skel.load()?;
        skel.attach()?;

        let mut writer: RecordWriter<'_, BufferMessage, File> = RecordWriter::new(result_file)?;
        let mut builder = RingBufferBuilder::new();

        builder.add(&skel.maps.events, move |data| {
            if let Ok(data) = data.try_into() {
                writer.handle_event(data);
                0
            } else {
                println!("Error parsing event data");
                -1
            }
        })?;
        let ringbuf: RingBuffer<'_> = builder.build()?;
        Ok(Box::pin(Self {
            skel,
            ringbuf,
            open_object,
        }))
    }
}

impl EventPoller for Pin<Box<SendStoryEventTracker>> {
    fn poll(&mut self) -> Result<()> {
        Ok(self.ringbuf.poll(Duration::from_millis(1))?)
    }
}
