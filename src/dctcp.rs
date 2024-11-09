use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;
use pin_project::pin_project;
use std::fs::File;
use std::mem::{transmute, MaybeUninit};
use std::path::Path;
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
use crate::common::RecordWriter;

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DctcpMessage {
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

#[pin_project]
pub struct DctcpEventTracker {
    open_object: Box<MaybeUninit<OpenObject>>,
    #[pin]
    skel: DctcpSkel<'static>, // Using 'static lifetime
    ringbuf: RingBuffer<'static>,
}

impl DctcpEventTracker {
    pub fn new(
        filter_config: ConnectionFilterConfig,
        result_file: &Path,
    ) -> Result<Pin<Box<Self>>> {
        let skel_builder = DctcpSkelBuilder::default();
        let mut open_object = Box::new(MaybeUninit::uninit());
        let open_skel: OpenDctcpSkel = unsafe { transmute(skel_builder.open(&mut open_object)?) };

        open_skel.maps.rodata_data.tgt_src_port = filter_config.src_port.to_be();
        open_skel.maps.rodata_data.tgt_dst_port = filter_config.dst_port.to_be();

        let mut skel = open_skel.load()?;
        skel.attach()?;

        let mut builder = RingBufferBuilder::new();

        let mut writer: RecordWriter<'_, DctcpMessage, File> =
            RecordWriter::new(File::create(result_file)?)?;

        builder.add(&skel.maps.events, move |data| writer.handle_event(data))?;
        let ringbuf = builder.build()?;

        Ok(Box::pin(Self {
            open_object,
            skel: skel,
            ringbuf,
        }))
    }

    pub fn poll(&mut self) -> Result<()> {
        Ok(self.ringbuf.poll(Duration::from_millis(100))?)
    }
}
