use libc::{c_char, strlen, wchar_t, wcslen};
use memalloc::{allocate, deallocate};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, AF_INET, AF_INET6, AF_UNSPEC, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{SOCKADDR_IN, SOCKADDR_IN6};

use crate::interface::{Interface, InterfaceType, MacAddr};
use crate::ip::{Ipv4Net, Ipv6Net};


// rd-engine: API output size is not the allocation's ownership size.
struct AdapterAllocation {
    ptr: *mut IP_ADAPTER_ADDRESSES_LH,
    allocated_size: usize,
}

impl AdapterAllocation {
    fn new(allocated_size: usize) -> Self {
        Self {
            ptr: unsafe { allocate(allocated_size) } as *mut IP_ADAPTER_ADDRESSES_LH,
            allocated_size,
        }
    }
}

impl Drop for AdapterAllocation {
    fn drop(&mut self) {
        unsafe { deallocate(self.ptr as *mut u8, self.allocated_size) };
    }
}

// Get network interfaces using the IP Helper API
// Reference: https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
pub fn interfaces() -> Vec<Interface> {
    let mut interfaces: Vec<Interface> = vec![];
    let mut dwsize: u32 = 2000;
    let mut mem = AdapterAllocation::new(dwsize as usize);
    let mut retries = 3;
    let mut ret_val;
    loop {
        ret_val = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                Default::default(),
                std::ptr::null_mut::<std::ffi::c_void>(),
                mem.ptr,
                &mut dwsize,
            )
        };
        if ret_val != ERROR_BUFFER_OVERFLOW.0 || retries <= 0 {
            break;
        }
        mem = AdapterAllocation::new(dwsize as usize);
        retries -= 1;
    }
    if ret_val == NO_ERROR.0 {
        // Enumerate all adapters
        let mut cur = mem.ptr;
        while !cur.is_null() {
            let if_type: u32 = unsafe { (*cur).IfType };
            match InterfaceType::try_from(if_type) {
                Ok(_) => {}
                Err(_) => {
                    cur = unsafe { (*cur).Next };
                    continue;
                }
            }
            // Index
            let anon1 = unsafe { (*cur).Anonymous1 };
            let anon = unsafe { anon1.Anonymous };
            let index = anon.IfIndex;
            // Flags
            let anon2 = unsafe { (*cur).Anonymous2 };
            let flags = unsafe { anon2.Flags };
            // Name
            let p_aname = unsafe { (*cur).AdapterName.0 };
            let aname_len = unsafe { strlen(p_aname as *const c_char) };
            let aname_slice = unsafe { std::slice::from_raw_parts(p_aname, aname_len) };
            let adapter_name = String::from_utf8(aname_slice.to_vec()).unwrap();
            // Friendly Name
            let p_fname = unsafe { (*cur).FriendlyName.0 };
            let fname_len = unsafe { wcslen(p_fname as *const wchar_t) };
            let fname_slice = unsafe { std::slice::from_raw_parts(p_fname, fname_len) };
            let friendly_name = String::from_utf16(fname_slice).unwrap();
            // Description
            let p_desc = unsafe { (*cur).Description.0 };
            let desc_len = unsafe { wcslen(p_desc as *const wchar_t) };
            let desc_slice = unsafe { std::slice::from_raw_parts(p_desc, desc_len) };
            let description = String::from_utf16(desc_slice).unwrap();
            // MAC address
            let mac_addr_arr: [u8; 6] = unsafe { (*cur).PhysicalAddress }[..6]
                .try_into()
                .unwrap_or([0, 0, 0, 0, 0, 0]);
            let mac_addr: MacAddr = MacAddr::new(mac_addr_arr);
            // TransmitLinkSpeed (bits per second)
            let transmit_speed = unsafe { (*cur).TransmitLinkSpeed };
            // ReceiveLinkSpeed (bits per second)
            let receive_speed = unsafe { (*cur).ReceiveLinkSpeed };
            let mut ipv4_vec: Vec<Ipv4Net> = vec![];
            let mut ipv6_vec: Vec<Ipv6Net> = vec![];
            // Enumerate all IPs
            let mut cur_a = unsafe { (*cur).FirstUnicastAddress };
            while !cur_a.is_null() {
                let addr = unsafe { (*cur_a).Address };
                let prefix_len = unsafe { (*cur_a).OnLinkPrefixLength };
                let sockaddr = unsafe { *addr.lpSockaddr };
                if sockaddr.sa_family == AF_INET.0 as u16 {
                    let sockaddr: *mut SOCKADDR_IN = addr.lpSockaddr as *mut SOCKADDR_IN;
                    let a = unsafe { (*sockaddr).sin_addr.S_un.S_addr };
                    let ipv4 = if cfg!(target_endian = "little") {
                        Ipv4Addr::from(a.swap_bytes())
                    } else {
                        Ipv4Addr::from(a)
                    };
                    let ipv4_net: Ipv4Net = Ipv4Net::new(ipv4, prefix_len);
                    ipv4_vec.push(ipv4_net);
                } else if sockaddr.sa_family == AF_INET6.0 as u16 {
                    let sockaddr: *mut SOCKADDR_IN6 = addr.lpSockaddr as *mut SOCKADDR_IN6;
                    let a = unsafe { (*sockaddr).sin6_addr.u.Byte };
                    let ipv6 = Ipv6Addr::from(a);
                    let ipv6_net: Ipv6Net = Ipv6Net::new(ipv6, prefix_len);
                    ipv6_vec.push(ipv6_net);
                }
                cur_a = unsafe { (*cur_a).Next };
            }
            let interface: Interface = Interface {
                index: index,
                name: adapter_name,
                friendly_name: Some(friendly_name),
                description: Some(description),
                if_type: InterfaceType::try_from(if_type).unwrap_or(InterfaceType::Unknown),
                mac_addr: Some(mac_addr),
                ipv4: ipv4_vec,
                ipv6: ipv6_vec,
                flags: flags,
                transmit_speed: Some(transmit_speed),
                receive_speed: Some(receive_speed),
                gateway: None,
            };
            interfaces.push(interface);
            cur = unsafe { (*cur).Next };
        }
    }
    return interfaces;
}
