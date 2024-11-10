use crate::common::{EventPoller, NetTuple};
use anyhow::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Link, OpenObject, RingBuffer, RingBufferBuilder,
};
use libc::{in6_addr, in_addr, AF_INET, AF_INET6};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::time::Duration;

pub mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/fivetuple.skel.rs"
    ));
}

use bpf::{FivetupleSkelBuilder, OpenFivetupleSkel};

use crate::common::CONNECTION_MAP;

#[repr(C)]
pub struct SockInfo {
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr: AddrUnion,
    pub daddr: AddrUnion,
}

#[repr(C)]
pub union AddrUnion {
    pub v4: in_addr,
    pub v6: in6_addr,
}

pub struct CookieEvent {
    pub cookie: u64,
    pub info: SockInfo,
    pub event_type: i32,
}

impl From<&SockInfo> for NetTuple {
    fn from(info: &SockInfo) -> Self {
        let saddr = match info.family as i32 {
            AF_INET => unsafe { IpAddr::V4(Ipv4Addr::from(u32::from_be(info.saddr.v4.s_addr))) },
            AF_INET6 => {
                let addr = unsafe { info.saddr.v6.s6_addr };
                IpAddr::V6(Ipv6Addr::from([
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                    addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
                ]))
            }
            _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        };

        let daddr = match info.family as i32 {
            AF_INET => unsafe { IpAddr::V4(Ipv4Addr::from(u32::from_be(info.daddr.v4.s_addr))) },
            AF_INET6 => {
                let addr = unsafe { info.daddr.v6.s6_addr };
                IpAddr::V6(Ipv6Addr::from([
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                    addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
                ]))
            }
            _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        };

        NetTuple {
            saddr,
            daddr,
            sport: info.sport,
            dport: info.dport,
            protocol: 0,
        }
    }
}

// #[pin_project]
pub struct CookieTracker {
    ringbuf: RingBuffer<'static>,
    link: Link,
    open_object: Box<MaybeUninit<OpenObject>>,
}

impl CookieTracker {
    pub fn new() -> Result<Pin<Box<Self>>> {
        let skel_builder = FivetupleSkelBuilder::default();
        let mut open_object: Box<MaybeUninit<OpenObject>> = Box::new(MaybeUninit::uninit());
        let open_skel: OpenFivetupleSkel = skel_builder.open(&mut open_object)?;
        let skel = open_skel.load()?;

        let cgroup = std::fs::File::open("/sys/fs/cgroup")?;
        let link = { skel.progs.socket_ops.attach_cgroup(cgroup.as_raw_fd())? };

        // attach to the root cgroup

        let mut builder = RingBufferBuilder::new();

        builder.add(&skel.maps.events, move |data| {
            if data.len() < std::mem::size_of::<CookieEvent>() {
                return -1;
            }

            let event = unsafe { &*(data.as_ptr() as *const CookieEvent) };

            match event.event_type {
                1 | 2 => {
                    let tuple = NetTuple::from(&event.info);
                    println!("Adding connection: {} {:?}", event.cookie, tuple);
                    CONNECTION_MAP.write().unwrap().insert(event.cookie, tuple);
                    0
                }
                3 => {
                    CONNECTION_MAP.write().unwrap().remove(&event.cookie);
                    0
                }
                _ => -1,
            }
        })?;

        let ringbuf: RingBuffer<'_> = builder.build()?;

        Ok(Box::pin(Self {
            ringbuf,
            link,
            // skel,
            open_object: Box::new(MaybeUninit::uninit()),
        }))
    }
}

impl EventPoller for Pin<Box<CookieTracker>> {
    fn poll(&mut self) -> Result<()> {
        Ok(self.ringbuf.poll(Duration::from_millis(100))?)
    }
}
