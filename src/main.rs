use libbpf_rs::PrintLevel;
use std::error::Error;
use std::mem::MaybeUninit;
use std::time::Duration;

mod tcpbuffer {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tcpbuffer.skel.rs"
    ));
}
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use tcpbuffer::*;

fn main() -> Result<(), Box<dyn Error>> {
    // Optional: Set up logging from libbpf
    libbpf_rs::set_print(Some((PrintLevel::Debug, libbpf_print_fn)));

    // Load and open the BPF application
    let skel_builder = TcpbufferSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("kprobe attached. Monitoring events...");

    // Keep the application running
    loop {
        // Your user-space logic here
        std::thread::sleep(Duration::from_secs(1));
    }

    // The BPF programs are detached automatically when `skel` goes out of scope
}

fn libbpf_print_fn(level: PrintLevel, msg: std::string::String) {
    println!("[{:?}] {}", level, msg);
}
