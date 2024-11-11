use anyhow::Result;
use arrow::datatypes::{FieldRef, Schema};
use lazy_static::lazy_static;
use parquet::{arrow::ArrowWriter, basic::Compression, file::properties::WriterProperties};
use serde::{Deserialize, Serialize};
use serde_arrow::schema::{SchemaLike, TracingOptions};
use std::{
    collections::HashMap,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, RwLock},
};

lazy_static! {
    pub static ref BOOT_TIME_NS: u64 = get_boot_time_ns().unwrap();
    pub static ref CONNECTION_MAP: RwLock<HashMap<u64, NetTuple>> = RwLock::new(HashMap::new());
}

fn get_boot_time_ns() -> Result<u64, Box<dyn std::error::Error>> {
    let stat_contents = std::fs::read_to_string("/proc/stat")?;
    for line in stat_contents.lines() {
        if line.starts_with("btime ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                let btime = parts[1].parse::<u64>()?;
                // Convert btime (seconds since epoch) to nanoseconds
                return Ok(btime * 1_000_000_000);
            }
        }
    }
    Err("Could not find btime in /proc/stat".into())
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowBPF {
    pub pid: u32,
    pub comm: [u8; 16],
    pub socket_cookie: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Flow {
    pub pid: u32,
    pub comm: String,
    pub conn_cookie: u64,
    pub conn_tuple: NetTuple,
}

impl From<&FlowBPF> for Flow {
    fn from(flow: &FlowBPF) -> Self {
        let comm = String::from_utf8_lossy(&flow.comm).to_string();
        Flow {
            pid: flow.pid,
            comm,
            conn_cookie: flow.socket_cookie,
            conn_tuple: CONNECTION_MAP
                .read()
                .unwrap()
                .get(&flow.socket_cookie)
                .unwrap_or(&NetTuple::default())
                .clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetTuple {
    pub saddr: IpAddr,
    pub daddr: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
}

impl std::fmt::Display for NetTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.saddr, self.sport, self.daddr, self.dport, self.protocol
        )
    }
}

impl Default for NetTuple {
    fn default() -> Self {
        Self {
            saddr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            daddr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            sport: 0,
            dport: 0,
            protocol: 0,
        }
    }
}

pub struct ConnectionFilterConfig {
    pub src_port: u16,
    pub dst_port: u16,
}
pub struct RecordWriter<'a, T: Serialize + Deserialize<'a> + Clone + Default, W: Write + Send> {
    schema: Vec<FieldRef>,
    buffer: Vec<T>,
    writer: ArrowWriter<W>,
    phantom: std::marker::PhantomData<&'a T>,
}

impl<'a, T: Serialize + Deserialize<'a> + Clone + Default, W: Write + Send> RecordWriter<'a, T, W> {
    pub fn new(output_file: W) -> Result<Self> {
        let fields = Vec::<FieldRef>::from_samples(
            &[T::default()],
            TracingOptions::default()
                .allow_null_fields(true)
                .enums_without_data_as_strings(true),
        )?;

        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build();

        let writer = ArrowWriter::try_new(
            output_file,
            Arc::new(Schema::new(fields.clone())),
            Some(props),
        )?;

        Ok(Self {
            schema: fields,
            buffer: Vec::new(),
            writer,
            phantom: std::marker::PhantomData,
        })
    }

    pub fn add(&mut self, record: T) -> Result<()> {
        self.buffer.push(record);
        if self.buffer.len() > 128 {
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        let batch = serde_arrow::to_record_batch(&self.schema, &self.buffer)?;
        self.writer.write(&batch)?;
        self.buffer.clear();
        Ok(())
    }

    pub fn handle_event(&mut self, msg: T) -> i32 {
        match self.add(msg) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("Error writing to file: {:?}", e);
                -1
            }
        }
    }
}

impl<'a, T: Serialize + Deserialize<'a> + Clone + Default, W: Write + Send> Drop
    for RecordWriter<'a, T, W>
{
    fn drop(&mut self) {
        println!("flush records to the disk");
        self.writer.finish().unwrap();
    }
}

pub trait EventPoller {
    fn poll(&mut self) -> Result<()>;
}

// generate test case
#[cfg(test)]
mod tests {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReader;

    use super::*;
    use bytes::Bytes;
    use std::io::Cursor;

    #[derive(Serialize, Deserialize, Clone, Debug, Default)]
    struct Record {
        a: f32,
        b: i32,
    }

    #[test]
    fn test_record_writer() {
        let mut cursor = Cursor::new(Vec::new());
        let mut writer = RecordWriter::new(&mut cursor).unwrap();

        for i in 0..512 {
            writer.add(Record { a: i as f32, b: i }).unwrap();
        }

        writer.flush().unwrap();
    }

    #[test]
    fn test_record_reader() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = RecordWriter::new(&mut cursor).unwrap();

            for i in 0..512 {
                writer.add(Record { a: i as f32, b: i }).unwrap();
            }

            writer.flush().unwrap();
        }

        let mut reader =
            ParquetRecordBatchReader::try_new(Bytes::from(cursor.into_inner()), 512).unwrap();

        let batch = reader.next().unwrap().unwrap();
        let records: Vec<Record> = serde_arrow::from_record_batch(&batch).unwrap();

        assert_eq!(records.len(), 512);
        for (i, record) in records.iter().enumerate() {
            assert_eq!(record.a, i as f32);
            assert_eq!(record.b, i as i32);
        }
    }
}
