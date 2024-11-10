use chrono::DateTime;
use chrono::NaiveDateTime;
use libbpf_rs::Link;
use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;
use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::pin::Pin;

use crate::common::{ConnectionFilterConfig, EventPoller, FlowBPF, RecordWriter, BOOT_TIME_NS};
use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    OpenObject,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcppacket.skel.rs"
    ));
}
use bpf::{OpenTcppacketSkel, TcppacketSkelBuilder};

#[repr(C)]
pub struct PacketEvent {
    timestamp_ns: u64,
    flow: FlowBPF,
    seq: u32,
    ack: u32,
    len: u32,
    direction: u8,
    flags: u8,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PacketMessage {
    time: NaiveDateTime,
    cookie: u64,
    seq: u32,
    ack: u32,
    len: u32,
    direction: u8,
    flags: u8,
}

impl TryFrom<&[u8]> for PacketMessage {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<PacketEvent>() {
            return Err(anyhow::anyhow!("Data size mismatch"));
        }
        let event = unsafe { &*(data.as_ptr() as *const PacketEvent) };

        let absolute_timestamp_ns = *BOOT_TIME_NS + event.timestamp_ns;
        let naive_datetime = DateTime::from_timestamp(
            (absolute_timestamp_ns / 1_000_000_000) as i64,
            (absolute_timestamp_ns % 1_000_000_000) as u32,
        )
        .unwrap_or_default()
        .naive_utc();
        Ok(PacketMessage {
            time: naive_datetime,
            cookie: event.flow.socket_cookie,
            seq: event.seq,
            ack: event.ack,
            len: event.len,
            direction: event.direction,
            flags: event.flags,
        })
    }
}

pub struct TCPPacketEventTracker {
    ringbuf: RingBuffer<'static>,
    _ingress_link: Link,
    _egress_link: Link,
    _open_object: Box<MaybeUninit<OpenObject>>,
}

impl TCPPacketEventTracker {
    pub fn new(
        filter_config: &ConnectionFilterConfig,
        result_file: File,
    ) -> Result<Pin<Box<Self>>> {
        let skel_builder = TcppacketSkelBuilder::default();
        let mut open_object: Box<MaybeUninit<OpenObject>> = Box::new(MaybeUninit::uninit());
        let open_skel: OpenTcppacketSkel = skel_builder.open(&mut open_object)?;

        open_skel.maps.rodata_data.tgt_src_port = filter_config.src_port;
        open_skel.maps.rodata_data.tgt_dst_port = filter_config.dst_port;

        let skel = open_skel.load()?;

        let cgroup = std::fs::File::open("/sys/fs/cgroup")?;
        let ingress_link = { skel.progs.tcp_ingress.attach_cgroup(cgroup.as_raw_fd())? };
        let egress_link = { skel.progs.tcp_egress.attach_cgroup(cgroup.as_raw_fd())? };

        let mut writer: RecordWriter<'_, PacketMessage, File> = RecordWriter::new(result_file)?;

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
            ringbuf,
            _ingress_link: ingress_link,
            _egress_link: egress_link,
            _open_object: Box::new(MaybeUninit::uninit()),
        }))
    }
}

impl EventPoller for Pin<Box<TCPPacketEventTracker>> {
    fn poll(&mut self) -> Result<()> {
        Ok(self.ringbuf.poll(Duration::from_millis(100))?)
    }
}
