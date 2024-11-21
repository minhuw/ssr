use clap::Parser;
use common::EventPoller;
use dctcp::DctcpEventTracker;
use fivetuple::CookieTracker;
use libbpf_rs::PrintLevel;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tcpbuffer::TCPBufferEventTracker;
use tcppacket::TCPPacketEventTracker;
use utils::corelist::CoreList;

mod common;
mod dctcp;
mod fivetuple;
mod sched;
mod tcpbuffer;
mod tcppacket;
pub mod utils;

fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

#[derive(Parser, Debug)]
#[command(
    author = "Minhu Wang <minhuw@hey.com>",
    version = "0.1",
    about = "An example CLI using clap",
    long_about = None
)]
struct Args {
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    #[arg(short, long, default_value = "0")]
    src_port: u16,

    #[arg(short, long, default_value = "0")]
    dst_port: u16,

    #[arg(short, long,  value_parser = parse_key_val::<String, String>)]
    events: Vec<(String, String)>,

    #[arg(long, value_parser = CoreList::parser(), default_value="")]
    cores: CoreList,

    #[arg(long, default_value = "")]
    cores_file: String,

    #[arg(long, default_value = "false")]
    with_softirq: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Optional: Set up logging from libbpf
    libbpf_rs::set_print(Some((PrintLevel::Debug, libbpf_print_fn)));

    let filter = common::ConnectionFilterConfig {
        src_port: args.src_port,
        dst_port: args.dst_port,
    };

    let mut poller: HashMap<String, Box<dyn EventPoller>> = HashMap::new();
    let cookie_poller = Box::new(CookieTracker::new()?);
    poller.insert("cookie".to_string(), cookie_poller);

    for (key, value) in &args.events {
        println!("{}={}", key, value);
        poller.insert(key.clone(), {
            let result_file = File::create(value)?;
            match key.as_str() {
                "tcpbuffer" => Box::new(TCPBufferEventTracker::new(&filter, result_file)?),
                "dctcp" => Box::new(DctcpEventTracker::new(&filter, result_file)?),
                "tcppacket" => Box::new(TCPPacketEventTracker::new(&filter, result_file)?),
                _ => panic!("Unknown event type"),
            }
        });
    }

    if !args.cores.is_empty() {
        poller.insert(
            "core".into(),
            Box::new(sched::SchedTracker::new(
                File::create({
                    if args.cores_file.is_empty() {
                        "sched.parquet".to_string()
                    } else {
                        args.cores_file.clone()
                    }
                })?,
                args.cores,
                args.with_softirq,
            )?),
        );
    }

    let exit: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let exit_clone = Arc::clone(&exit);

    ctrlc::set_handler(move || {
        println!("got ctrl-c, exiting...");
        exit_clone.store(true, Ordering::SeqCst);
    })?;

    while !exit.load(Ordering::SeqCst) {
        for poller in poller.values_mut() {
            poller.poll()?;
        }
    }

    Ok(())
}

fn libbpf_print_fn(level: PrintLevel, msg: std::string::String) {
    print!("[{:?}] {}", level, msg);
}
