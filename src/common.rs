use anyhow::Result;
use arrow::datatypes::{FieldRef, Schema};
use parquet::arrow::ArrowWriter;
use serde::{Deserialize, Serialize};
use serde_arrow::schema::{SchemaLike, TracingOptions};
use std::{io::Write, sync::Arc};

pub struct ConnectionFilterConfig {
    pub src_port: u16,
    pub dst_port: u16,
}
pub struct RecordWriter<'a, T: Serialize + Deserialize<'a> + Clone, W: Write + Send> {
    schema: Vec<FieldRef>,
    buffer: Vec<T>,
    writer: ArrowWriter<W>,
    phantom: std::marker::PhantomData<&'a T>,
}

impl<'a, T: Serialize + Deserialize<'a> + Clone, W: Write + Send> RecordWriter<'a, T, W> {
    pub fn new(output_file: W) -> Result<Self> {
        let fields = Vec::<FieldRef>::from_type::<T>(TracingOptions::default())?;
        let writer =
            ArrowWriter::try_new(output_file, Arc::new(Schema::new(fields.clone())), None)?;

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

    pub fn handle_event(&mut self, data: &[u8]) -> i32 {
        if data.len() < std::mem::size_of::<T>() {
            return -1;
        }

        let msg = unsafe { &*(data.as_ptr() as *const T) };

        match self.add(msg.clone()) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("Error writing to file: {:?}", e);
                -1
            }
        }
    }
}

impl<'a, T: Serialize + Deserialize<'a> + Clone, W: Write + Send> Drop for RecordWriter<'a, T, W> {
    fn drop(&mut self) {
        self.writer.finish().unwrap();
    }
}

// generate test case
#[cfg(test)]
mod tests {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReader;

    use super::*;
    use bytes::Bytes;
    use std::io::Cursor;

    #[derive(Serialize, Deserialize, Clone, Debug)]
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
