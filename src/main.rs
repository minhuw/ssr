use chrono::{DateTime, Local, TimeZone};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Map, MapCore, MapFlags, PrintLevel, RingBufferBuilder};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::CStr;
use std::fs::File;
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

mod common;
mod dctcp;
mod tcpbuffer;

#[repr(C)]
struct BufferMessage {
    pid: u32,
    rx_buffer: u32,
    timestamp_ns: u64,
    socket_cookie: u64,
    event_type: i32,
    comm: [u8; 16],
}

fn log_event(event_code: i32) -> &'static str {
    match event_code {
        1 => "+ Packet",
        2 => "+ Packet (Done)",
        3 => "- App",
        4 => "- App (Done)",
        _ => "Unknown event",
    }
}

#[repr(C)]
struct DctcpEvent {
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

// Define the FiveTuple struct
#[derive(Debug, Clone)]
struct FiveTuple {
    saddr: IpAddr,
    daddr: IpAddr,
    sport: u16,
    dport: u16,
    protocol: u8,
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.saddr, self.sport, self.daddr, self.dport, self.protocol
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EbpfFiveTuple {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
    protocol: u8,
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

fn get_five_tuple_from_map(sock_info_map: &Map, sock_cookie: u64) -> Result<FiveTuple, ()> {
    match sock_info_map.lookup(&sock_cookie.to_ne_bytes(), MapFlags::ANY) {
        Ok(Some(value)) => {
            let ebpf_tuple =
                unsafe { std::ptr::read_unaligned(value.as_ptr() as *const EbpfFiveTuple) };
            let saddr = IpAddr::V4(Ipv4Addr::from(u32::from_be(ebpf_tuple.saddr)));
            let daddr = IpAddr::V4(Ipv4Addr::from(u32::from_be(ebpf_tuple.daddr)));
            let five_tuple = FiveTuple {
                saddr,
                daddr,
                sport: ebpf_tuple.sport,
                dport: ebpf_tuple.dport,
                protocol: ebpf_tuple.protocol,
            };
            Ok(five_tuple)
        }
        Ok(None) | Err(_) => Err(()),
    }
}

fn handle_event(
    data: &[u8],
    boot_time_ns: u64,
    socket_map: &mut HashMap<u64, FiveTuple>,
    sock_info_map: &Map,
    result_file: &mut File,
    verbose: bool,
) -> i32 {
    if data.len() < std::mem::size_of::<BufferMessage>() {
        eprintln!("Data size mismatch");
        return 0;
    }

    // Cast the data to our Data struct
    let event = unsafe { &*(data.as_ptr() as *const BufferMessage) };

    let absolute_timestamp_ns = boot_time_ns + event.timestamp_ns;

    let naive_datetime = DateTime::from_timestamp(
        (absolute_timestamp_ns / 1_000_000_000) as i64,
        (absolute_timestamp_ns % 1_000_000_000) as u32,
    )
    .unwrap_or_default()
    .naive_utc();

    // Convert to Local datetime
    let datetime: DateTime<Local> = Local.from_utc_datetime(&naive_datetime);

    let sock_cookie: u64 = event.socket_cookie;

    let five_tuple = {
        // Check if the five-tuple is already in the user space cache
        if socket_map.get(&sock_cookie).is_none() {
            if let Ok(five_tuple) = get_five_tuple_from_map(sock_info_map, sock_cookie) {
                // Cache the five-tuple
                socket_map.insert(sock_cookie, five_tuple.clone());
            }
        }

        socket_map.get(&sock_cookie)
    };

    if five_tuple.is_some() {
        let comm = match CStr::from_bytes_until_nul(&event.comm) {
            Ok(comm) => comm.to_string_lossy(),
            Err(_) => "Unknown".into(),
        };

        if verbose {
            println!(
                "[{}] Timestamp: {}, Process: {} ({}), cookie: {}, event: {}, rx buffer size: {}",
                five_tuple.unwrap(),
                datetime.format("%+"),
                comm,
                event.pid,
                event.socket_cookie,
                log_event(event.event_type),
                event.rx_buffer
            );
        }

        let _ = result_file.write_fmt(format_args!(
            "{},{},{},{},{},{}\n",
            datetime.format("%+"),
            event.pid,
            comm,
            event.socket_cookie,
            event.event_type,
            event.rx_buffer,
        ));
    }

    0
}

fn handle_dctcp_event(data: &[u8], boot_time_ns: u64, result_file: &mut File) -> i32 {
    if data.len() < std::mem::size_of::<DctcpEvent>() {
        eprintln!("Data size mismatch");
        return 0;
    }

    // Cast the data to our Data struct
    let event = unsafe { &*(data.as_ptr() as *const DctcpEvent) };

    let absolute_timestamp_ns = boot_time_ns + event.timestamp_ns;

    let naive_datetime = DateTime::from_timestamp(
        (absolute_timestamp_ns / 1_000_000_000) as i64,
        (absolute_timestamp_ns % 1_000_000_000) as u32,
    )
    .unwrap_or_default()
    .naive_utc();

    // Convert to Local datetime
    let datetime: DateTime<Local> = Local.from_utc_datetime(&naive_datetime);

    let _ = result_file.write_fmt(format_args!(
        "{},{},{},{},{},{},{},{},{}\n",
        datetime.format("%+"),
        event.cookie,
        event.snd_cwnd,
        event.ssthresh,
        event.in_flight,
        event.delivered,
        event.delivered_ce,
        event.srtt,
        event.mdev
    ));

    0
}

#[derive(Parser, Debug)]
#[command(
    author = "Minhu Wang <minhuw@hey.com>",
    version = "0.1",
    about = "An example CLI using clap",
    long_about = None
)]
struct Args {
    /// Number of times to greet
    #[arg(short, long, default_value = "tcpbuffer.csv")]
    result: String,

    #[arg(short, long, default_value = "false")]
    verbose: bool,

    #[arg(short, long, default_value = "0")]
    src_port: u16,

    #[arg(short, long, default_value = "0")]
    dst_port: u16,

    #[arg(short, long)]
    cc_result: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Optional: Set up logging from libbpf
    libbpf_rs::set_print(Some((PrintLevel::Debug, libbpf_print_fn)));

    Ok(())
}

fn libbpf_print_fn(level: PrintLevel, msg: std::string::String) {
    println!("[{:?}] {}", level, msg);
}
