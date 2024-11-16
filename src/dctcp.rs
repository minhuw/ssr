use anyhow::Result;
use chrono::DateTime;
use chrono::NaiveDateTime;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;
use pin_project::pin_project;
use std::fs::File;
use std::mem::{transmute, MaybeUninit};
use std::pin::Pin;

use libbpf_rs::OpenObject;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/dctcp.skel.rs"
    ));
}

use bpf::{DctcpSkel, DctcpSkelBuilder, OpenDctcpSkel};

use crate::common::{ConnectionFilterConfig, EventPoller, Flow, FlowBPF, RecordWriter};

#[repr(C)]
struct DctcpEvent {
    timestamp_ns: u64,
    flow: FlowBPF,
    snd_cwnd: u32,
    ssthresh: u32,
    in_flight: u32,
    delivered: u32,
    delivered_ce: u32,
    srtt: u32,
    mdev: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DctcpMessage {
    time: NaiveDateTime,
    #[serde(flatten)]
    flow: Flow,
    snd_cwnd: u32,
    ssthresh: u32,
    in_flight: u32,
    delivered: u32,
    delivered_ce: u32,
    srtt: u32,
    mdev: u32,
}

impl Default for DctcpMessage {
    fn default() -> Self {
        Self {
            time: DateTime::from_timestamp(0, 0)
                .unwrap_or_default()
                .naive_utc(),
            flow: Flow::default(),
            snd_cwnd: 0,
            ssthresh: 0,
            in_flight: 0,
            delivered: 0,
            delivered_ce: 0,
            srtt: 0,
            mdev: 0,
        }
    }
}

impl TryFrom<&[u8]> for DctcpMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<DctcpEvent>() {
            return Err(anyhow::anyhow!("Data size mismatch"));
        }

        let event = unsafe { &*(data.as_ptr() as *const DctcpEvent) };

        let absolute_timestamp_ns = event.timestamp_ns;
        let naive_datetime = DateTime::from_timestamp(
            (absolute_timestamp_ns / 1_000_000_000) as i64,
            (absolute_timestamp_ns % 1_000_000_000) as u32,
        )
        .unwrap_or_default()
        .naive_utc();

        Ok(DctcpMessage {
            time: naive_datetime,
            flow: Flow::from(&event.flow),
            snd_cwnd: event.snd_cwnd,
            ssthresh: event.ssthresh,
            in_flight: event.in_flight,
            delivered: event.delivered,
            delivered_ce: event.delivered_ce,
            srtt: event.srtt,
            mdev: event.mdev,
        })
    }
}

#[pin_project]
pub struct DctcpEventTracker {
    #[pin]
    skel: DctcpSkel<'static>, // Using 'static lifetime
    ringbuf: RingBuffer<'static>,
    open_object: Box<MaybeUninit<OpenObject>>,
}

impl DctcpEventTracker {
    pub fn new(
        filter_config: &ConnectionFilterConfig,
        result_file: File,
    ) -> Result<Pin<Box<Self>>> {
        let skel_builder = DctcpSkelBuilder::default();
        let mut open_object = Box::new(MaybeUninit::uninit());
        let open_skel: OpenDctcpSkel = unsafe { transmute(skel_builder.open(&mut open_object)?) };

        open_skel.maps.rodata_data.tgt_src_port = filter_config.src_port.to_be();
        open_skel.maps.rodata_data.tgt_dst_port = filter_config.dst_port.to_be();

        let mut skel = open_skel.load()?;
        skel.attach()?;

        let mut writer: RecordWriter<'_, DctcpMessage, File> = RecordWriter::new(result_file)?;

        let mut builder = RingBufferBuilder::new();

        builder.add(&skel.maps.events, move |data| {
            if let Ok(data) = data.try_into() {
                writer.handle_event(data);
                0
            } else {
                -1
            }
        })?;
        let ringbuf = builder.build()?;

        Ok(Box::pin(Self {
            open_object,
            skel,
            ringbuf,
        }))
    }
}

impl EventPoller for Pin<Box<DctcpEventTracker>> {
    fn poll(&mut self) -> Result<()> {
        Ok(self.ringbuf.poll(Duration::from_millis(100))?)
    }
}
