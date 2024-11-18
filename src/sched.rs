use chrono::DateTime;
use chrono::NaiveDateTime;
use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;
use pin_project::pin_project;
use std::collections::hash_map::Entry;
use std::fs::File;
use std::mem::transmute;
use std::mem::MaybeUninit;
use std::pin::Pin;

use crate::common::{EventPoller, RecordWriter};
use crate::utils::corelist::CoreList;
use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// store PID -> comm mapping
lazy_static::lazy_static! {
    static ref PID_COMM_MAP: std::sync::Mutex<std::collections::HashMap<u32, String>> = std::sync::Mutex::new(std::collections::HashMap::new());
}

pub mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/sched.skel.rs"
    ));
}

use bpf::{OpenSchedSkel, SchedSkel, SchedSkelBuilder};

#[repr(C)]
#[derive(Clone, Debug)]
pub struct SchedEvent {
    timestamp_ns: u64,
    event_type: i32,
    pid: u32,
    prev_pid: u32,
    next_pid: u32,
    softirq_vec: u32,
    cpu_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    SchedSwitch = 1,
    SchedExec = 2,
    SchedExit = 3,
    SoftirqEntry = 4,
    SoftirqExit = 5,
    Unknown = 6,
}

impl TryFrom<i32> for EventType {
    type Error = anyhow::Error;

    fn try_from(event_type: i32) -> Result<Self> {
        match event_type {
            1 => Ok(EventType::SchedSwitch),
            2 => Ok(EventType::SchedExec),
            3 => Ok(EventType::SchedExit),
            4 => Ok(EventType::SoftirqEntry),
            5 => Ok(EventType::SoftirqExit),
            _ => Err(anyhow::anyhow!("Unknown event type")),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Process {
    pid: u32,
    name: String,
}

impl TryFrom<u32> for Process {
    type Error = anyhow::Error;

    fn try_from(pid: u32) -> Result<Self> {
        // insert if not exist
        let values = match PID_COMM_MAP.lock().unwrap().entry(pid) {
            Entry::Occupied(o) => o.into_mut().clone(),
            Entry::Vacant(v) => v
                .insert({
                    if let Ok(name) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                        name
                    } else {
                        "unknown".to_string()
                    }
                })
                .clone(),
        };
        Ok(Process {
            pid,
            name: values.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchedMessage {
    time: NaiveDateTime,
    #[serde(flatten)]
    pid: Process,
    prev_pid: u32,
    next_pid: u32,
    softirq_vec: u32,
    cpu_id: u32,
    event_type: EventType,
}

impl Default for SchedMessage {
    fn default() -> Self {
        SchedMessage {
            time: DateTime::from_timestamp(0, 0)
                .unwrap_or_default()
                .naive_utc(),
            pid: Process::default(),
            prev_pid: 0,
            next_pid: 0,
            softirq_vec: 0,
            cpu_id: 0,
            event_type: EventType::SchedSwitch,
        }
    }
}

impl TryFrom<&[u8]> for SchedMessage {
    type Error = anyhow::Error;
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<SchedEvent>() {
            return Err(anyhow::anyhow!("Data size mismatch"));
        }
        let event = unsafe { &*(data.as_ptr() as *const SchedEvent) };

        let absolute_timestamp_ns = event.timestamp_ns;
        let naive_datetime = DateTime::from_timestamp(
            (absolute_timestamp_ns / 1_000_000_000) as i64,
            (absolute_timestamp_ns % 1_000_000_000) as u32,
        )
        .unwrap_or_default()
        .naive_utc();

        Ok(SchedMessage {
            time: naive_datetime,
            pid: event.pid.try_into()?,
            prev_pid: event.prev_pid,
            next_pid: event.next_pid,
            softirq_vec: event.softirq_vec,
            cpu_id: event.cpu_id,
            event_type: event.event_type.try_into()?,
        })
    }
}

#[pin_project]
pub struct SchedTracker {
    #[pin]
    skel: SchedSkel<'static>,
    ringbuf: RingBuffer<'static>,
    open_object: Box<MaybeUninit<OpenObject>>,
}

impl SchedTracker {
    pub fn new(result_file: File, cores: CoreList) -> Result<Pin<Box<Self>>> {
        let skel_builder = SchedSkelBuilder::default();
        let mut open_object: Box<MaybeUninit<OpenObject>> = Box::new(MaybeUninit::uninit());
        let open_skel: OpenSchedSkel = unsafe { transmute(skel_builder.open(&mut open_object)?) };

        open_skel.maps.rodata_data.core_bitmap = cores.to_bitmap()?;

        let mut skel = open_skel.load()?;
        skel.attach()?;

        let mut writer: RecordWriter<'_, SchedMessage, File> = RecordWriter::new(result_file)?;

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

        Ok(Box::pin(SchedTracker {
            open_object,
            skel,
            ringbuf,
        }))
    }
}

impl EventPoller for Pin<Box<SchedTracker>> {
    fn poll(&mut self) -> Result<()> {
        Ok(self.ringbuf.poll(Duration::from_millis(1))?)
    }
}
