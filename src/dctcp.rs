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

use crate::common::ConnectionFilterConfig;
use crate::common::EventPoller;
use crate::common::NetTuple;
use crate::common::RecordWriter;
use crate::common::BOOT_TIME_NS;

#[repr(C)]
struct DctcpEvent {
    pid: u32,
    comm: [u8; 16],
    timestamp_ns: u64,
    cookie: u64,
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
    pid: u32,
    comm: String,
    conn_cookie: u64,
    conn_tuple: NetTuple,
    time: NaiveDateTime,
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
            pid: 0,
            comm: String::new(),
            conn_cookie: 0,
            conn_tuple: NetTuple::default(),
            time: DateTime::from_timestamp(0, 0)
                .unwrap_or_default()
                .naive_utc(),
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

        let comm = String::from_utf8_lossy(&event.comm).to_string();

        let absolute_timestamp_ns = *BOOT_TIME_NS + event.timestamp_ns;
        let naive_datetime = DateTime::from_timestamp(
            (absolute_timestamp_ns / 1_000_000_000) as i64,
            (absolute_timestamp_ns % 1_000_000_000) as u32,
        )
        .unwrap_or_default()
        .naive_utc();

        Ok(DctcpMessage {
            pid: event.pid,
            comm,
            conn_cookie: event.cookie,
            conn_tuple: NetTuple::default(),
            time: naive_datetime,
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
    open_object: Box<MaybeUninit<OpenObject>>,
    #[pin]
    skel: DctcpSkel<'static>, // Using 'static lifetime
    ringbuf: RingBuffer<'static>,
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
