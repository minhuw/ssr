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

mod tcpbuffer {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcpbuffer.skel.rs"
    ));
}

use tcpbuffer::*;

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
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Optional: Set up logging from libbpf
    libbpf_rs::set_print(Some((PrintLevel::Debug, libbpf_print_fn)));
    let mut result_file = File::create(args.result)?;

    // Load and open the BPF application
    let skel_builder = TcpbufferSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.tgt_src_port = args.src_port;
    open_skel.maps.rodata_data.tgt_dst_port = args.dst_port;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    result_file.write_all("timestamp,pid,comm,cookie,event_type,rx_buffer\n".as_bytes())?;
    println!("eBPF attached. Monitoring events...");

    let mut socket_map: HashMap<u64, FiveTuple> = HashMap::new();
    let sock_info_map = skel.maps.sock_info_map;

    let boot_time_ns = get_boot_time_ns()?;

    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.events, move |data| {
        handle_event(
            data,
            boot_time_ns,
            &mut socket_map,
            &sock_info_map,
            &mut result_file,
            args.verbose,
        )
    })?;
    let ringbuf = builder.build()?;

    loop {
        ringbuf.poll(Duration::from_millis(100))?;
    }
}

fn libbpf_print_fn(level: PrintLevel, msg: std::string::String) {
    println!("[{:?}] {}", level, msg);
}
