use chrono::DateTime;
use chrono::NaiveDateTime;
use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;
use pin_project::pin_project;
use std::fs::File;
use std::mem::transmute;
use std::mem::MaybeUninit;
use std::pin::Pin;

use crate::common::{
    ConnectionFilterConfig, EventPoller, Flow, FlowBPF, RecordWriter, BOOT_TIME_NS,
};
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
        "/src/bpf/tcpbuffer.skel.rs"
    ));
}

use bpf::{OpenTcpbufferSkel, TcpbufferSkel, TcpbufferSkelBuilder};

#[repr(C)]
#[derive(Clone, Debug)]
pub struct BufferEvent {
    timestamp_ns: u64,
    flow: FlowBPF,
    event_type: i32,
    rx_buffer: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    Packet = 1,
    PacketDone = 2,
    App = 3,
    AppDone = 4,
}

impl TryFrom<i32> for EventType {
    type Error = anyhow::Error;

    fn try_from(event_type: i32) -> Result<Self> {
        match event_type {
            1 => Ok(EventType::Packet),
            2 => Ok(EventType::PacketDone),
            3 => Ok(EventType::App),
            4 => Ok(EventType::AppDone),
            _ => Err(anyhow::anyhow!("Unknown event type")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BufferMessage {
    time: NaiveDateTime,
    flow: Flow,
    rx_buffer: u32,
    event_type: EventType,
}

impl Default for BufferMessage {
    fn default() -> Self {
        BufferMessage {
            time: DateTime::from_timestamp(0, 0)
                .unwrap_or_default()
                .naive_utc(),
            flow: Flow::default(),
            rx_buffer: 0,
            event_type: EventType::Packet,
        }
    }
}

// impl from trait for BufferMessage
impl TryFrom<&[u8]> for BufferMessage {
    type Error = anyhow::Error;
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<BufferEvent>() {
            return Err(anyhow::anyhow!("Data size mismatch"));
        }

        let event = unsafe { &*(data.as_ptr() as *const BufferEvent) };

        let absolute_timestamp_ns = *BOOT_TIME_NS + event.timestamp_ns;
        let naive_datetime = DateTime::from_timestamp(
            (absolute_timestamp_ns / 1_000_000_000) as i64,
            (absolute_timestamp_ns % 1_000_000_000) as u32,
        )
        .unwrap_or_default()
        .naive_utc();

        Ok(BufferMessage {
            time: naive_datetime,
            flow: Flow::from(&event.flow),
            rx_buffer: event.rx_buffer,
            event_type: event.event_type.try_into()?,
        })
    }
}

#[pin_project]
pub struct TCPBufferEventTracker {
    #[pin]
    skel: TcpbufferSkel<'static>, // Using 'static lifetime
    ringbuf: RingBuffer<'static>,
    open_object: Box<MaybeUninit<OpenObject>>,
}

impl TCPBufferEventTracker {
    pub fn new(
        filter_config: &ConnectionFilterConfig,
        result_file: File,
    ) -> Result<Pin<Box<Self>>> {
        let skel_builder = TcpbufferSkelBuilder::default();
        let mut open_object: Box<MaybeUninit<OpenObject>> = Box::new(MaybeUninit::uninit());
        let open_skel: OpenTcpbufferSkel =
            unsafe { transmute(skel_builder.open(&mut open_object)?) };

        open_skel.maps.rodata_data.tgt_src_port = filter_config.src_port;
        open_skel.maps.rodata_data.tgt_dst_port = filter_config.dst_port;

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

        // Create and pin the struct
        let tracker = TCPBufferEventTracker {
            open_object,
            skel,
            ringbuf,
        };

        Ok(Box::pin(tracker))
    }
}

impl EventPoller for Pin<Box<TCPBufferEventTracker>> {
    fn poll(&mut self) -> Result<()> {
        Ok(self.ringbuf.poll(Duration::from_millis(100))?)
    }
}
