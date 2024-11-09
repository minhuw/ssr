use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;
use pin_project::pin_project;
use std::fs::File;
use std::mem::transmute;
use std::mem::MaybeUninit;
use std::path::Path;
use std::pin::Pin;

use crate::common::ConnectionFilterConfig;
use crate::common::RecordWriter;
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BufferMessage {
    pid: u32,
    rx_buffer: u32,
    timestamp_ns: u64,
    socket_cookie: u64,
    event_type: i32,
    comm: [u8; 16],
}

#[pin_project]
pub struct TCPBufferEventTracker {
    open_object: Box<MaybeUninit<OpenObject>>,
    #[pin]
    skel: TcpbufferSkel<'static>, // Using 'static lifetime
    ringbuf: RingBuffer<'static>,
}

impl TCPBufferEventTracker {
    pub fn new(
        filter_config: ConnectionFilterConfig,
        result_file: &Path,
    ) -> Result<Pin<Box<Self>>> {
        let skel_builder = TcpbufferSkelBuilder::default();
        let mut open_object = Box::new(MaybeUninit::uninit());
        let open_skel: OpenTcpbufferSkel =
            unsafe { transmute(skel_builder.open(&mut open_object)?) };

        open_skel.maps.rodata_data.tgt_src_port = filter_config.src_port;
        open_skel.maps.rodata_data.tgt_dst_port = filter_config.dst_port;

        let mut skel = open_skel.load()?;
        skel.attach()?;

        let mut writer: RecordWriter<'_, BufferMessage, File> =
            RecordWriter::new(File::create(result_file)?)?;

        let mut builder = RingBufferBuilder::new();

        builder.add(&skel.maps.events, move |data| writer.handle_event(data))?;
        let ringbuf = builder.build()?;

        // Create and pin the struct
        let tracker = TCPBufferEventTracker {
            open_object,
            skel,
            ringbuf,
        };

        Ok(Box::pin(tracker))
    }

    pub fn poll(&mut self) -> Result<()> {
        Ok(self.ringbuf.poll(Duration::from_millis(100))?)
    }
}
