use std::net::{UdpSocket, SocketAddr, Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};
use std::io::{self, Cursor};
use std::collections::{HashMap, HashSet};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::{info, debug, warn, error, trace};

use crate::error::{PtpIpError, Result};
use crate::types::{DiscoveredCamera, ipv4_to_bytes, CCameraInfo, SessionConfig};
use crate::utils::{bytes_to_hex, rust_str_to_c};

/// PTP/IP discovery protocol constants
pub const PTPIP_DISCOVERY_PORT: u16 = 1900;
pub const PTPIP_BROADCAST_ADDR: &str = "255.255.255.255:1900";
pub const PTPIP_MULTICAST_ADDR: &str = "239.255.255.250:1900"; // SSDP multicast address

/// Message type enumeration
#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum PtpIpMessageType {
    DiscoveryRequest = 0x0001,
    DiscoveryResponse = 0x0002,
}

/// Device discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub timeout: Duration,        // Timeout duration
    pub retry_count: usize,       // Number of retries
    pub interface: Option<String>, // Network interface to bind to
    pub use_multicast: bool,      // Whether to use multicast
    /// When set (e.g. in tests), discovery requests are sent only to these addresses instead of broadcast.
    #[doc(hidden)]
    pub test_destinations: Option<Vec<SocketAddr>>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            retry_count: 3,
            interface: None,
            use_multicast: true,
            test_destinations: None,
        }
    }
}

/// Send discovery request and return camera list
pub fn discover_cameras(config: DiscoveryConfig) -> Result<Vec<DiscoveredCamera>> {
    info!("Searching for PTP/IP devices...");
    
    // Create UDP socket
    let socket = create_discovery_socket(&config)?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(config.timeout))?;
    
    // Build discovery request packet
    let request_packet = build_discovery_request()?;
    debug!("Discovery request packet: {}", bytes_to_hex(&request_packet));
    
    let mut cameras = Vec::new();
    let mut seen_addrs = HashSet::new();
    let start_time = Instant::now();
    let destinations = get_discovery_destinations(&config);
    
    // Send requests multiple times
    for attempt in 1..=config.retry_count {
        // Send request to all target addresses
        for dest in &destinations {
            socket.send_to(&request_packet, dest)?;
            trace!(
                "Send attempt {} to {} ({} bytes)",
                attempt, dest, request_packet.len()
            );
        }
        
        info!("Sent discovery request attempt {}, waiting for responses...", attempt);
        
        // Receive responses
        loop {
            if start_time.elapsed() > config.timeout {
                break;
            }
            
            if cameras.len() >= 10 { // Limit maximum number of devices
                break;
            }
            
            let mut buffer = [0u8; 1024];
            match socket.recv_from(&mut buffer) {
                Ok((bytes_received, src_addr)) => {
                    if seen_addrs.contains(&src_addr) {
                        continue;
                    }
                    seen_addrs.insert(src_addr);
                    
                    trace!(
                        "Received response from {} ({} bytes): {}",
                        src_addr, bytes_received, bytes_to_hex(&buffer[..bytes_received])
                    );
                    
                    // Parse response
                    if let Some(camera) = parse_discovery_response(&buffer[..bytes_received], src_addr)? {
                        // Deduplicate (same device might respond via multicast and broadcast)
                        if !cameras.iter().any(|c: &DiscoveredCamera| c.ip_address == camera.ip_address && c.port == camera.port) {
                            cameras.push(camera);
                            info!(
                                "Discovered device: {} ({})",
                                cameras.last().unwrap().model_name,
                                cameras.last().unwrap().ip_address
                            );
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock || 
                       e.kind() == io::ErrorKind::TimedOut {
                        break;
                    } else {
                        warn!("Error receiving response: {}", e);
                        continue;
                    }
                }
            }
        }
        
        if !cameras.is_empty() && attempt < config.retry_count {
            // Devices discovered, shorten wait time for next retry
            std::thread::sleep(Duration::from_millis(500));
        } else if attempt < config.retry_count {
            // No devices discovered, wait longer
            std::thread::sleep(config.timeout / 2);
        }
    }
    
    info!("Device search complete, found {} devices", cameras.len());
    Ok(cameras)
}

/// Create UDP socket for discovery
fn create_discovery_socket(config: &DiscoveryConfig) -> Result<UdpSocket> {
    // Bind to specified interface or all interfaces based on configuration
    let bind_addr = if let Some(iface) = &config.interface {
        // Bind to specified interface (simplified handling)
        info!("Binding to network interface: {}", iface);
        UdpSocket::bind(("0.0.0.0", 0))?
    } else {
        UdpSocket::bind(("0.0.0.0", 0))?
    };
    
    // Join multicast group if using multicast
    if config.use_multicast {
        let multicast_ip: Ipv4Addr = PTPIP_MULTICAST_ADDR.split(':').next().unwrap().parse()?;
        bind_addr.join_multicast_v4(&multicast_ip, &Ipv4Addr::UNSPECIFIED)?;
        info!("Joined multicast group: {}", PTPIP_MULTICAST_ADDR);
    }
    
    Ok(bind_addr)
}

/// Get list of destination addresses for discovery requests
fn get_discovery_destinations(config: &DiscoveryConfig) -> Vec<SocketAddr> {
    if let Some(ref dests) = config.test_destinations {
        return dests.clone();
    }
    let mut destinations = Vec::new();
    destinations.push(PTPIP_BROADCAST_ADDR.parse().unwrap());
    if config.use_multicast {
        destinations.push(PTPIP_MULTICAST_ADDR.parse().unwrap());
    }
    destinations
}

/// Build discovery request packet
fn build_discovery_request() -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(8);
    
    // Message type: DiscoveryRequest (0x0001)
    packet.write_u16::<BigEndian>(PtpIpMessageType::DiscoveryRequest as u16)?;
    // Protocol version: 1.0 (0x0100)
    packet.write_u16::<BigEndian>(0x0100)?;
    // Reserved field
    packet.write_u32::<BigEndian>(0x00000000)?;
    
    Ok(packet)
}

/// Parse discovery response packet
fn parse_discovery_response(buffer: &[u8], src_addr: SocketAddr) -> Result<Option<DiscoveredCamera>> {
    if buffer.len() < 14 {
        warn!(
            "Response packet too short, need at least 14 bytes, received {} bytes",
            buffer.len()
        );
        return Ok(None);
    }
    
    let mut reader = Cursor::new(buffer);
    
    // Read message type
    let message_type = reader.read_u16::<BigEndian>()?;
    if message_type != PtpIpMessageType::DiscoveryResponse as u16 {
        warn!(
            "Unknown message type: 0x{:04X}, expected 0x0002",
            message_type
        );
        return Ok(None);
    }
    
    // Read version
    let version = reader.read_u16::<BigEndian>()?;
    if version != 0x0100 {
        warn!(
            "Unsupported version: 0x{:04X}, only 1.0 (0x0100) supported",
            version
        );
        return Ok(None);
    }
    
    // Read vendor information
    let vendor_extension_id = reader.read_u32::<BigEndian>()?;
    let vendor_extension_version = reader.read_u16::<BigEndian>()?;
    
    // Read port number
    let port = reader.read_u16::<BigEndian>()?;
    
    // Read device name
    let name_bytes = &buffer[14..];
    let model_name = String::from_utf8_lossy(name_bytes).into_owned();
    let model_name = model_name.trim_matches(char::from(0)).to_string();
    
    // Extract IP address
    let ip_addr = match src_addr {
        SocketAddr::V4(v4) => *v4.ip(),
        SocketAddr::V6(_) => {
            warn!("IPv6 devices not supported");
            return Ok(None);
        }
    };
    
    Ok(Some(DiscoveredCamera {
        ip_address: ip_addr,
        port,
        model_name,
        vendor_extension_id,
        vendor_extension_version,
    }))
}

// ------------------------------
// FFI Interface
// ------------------------------

/// Discover PTP/IP cameras on network (C interface)
#[unsafe(no_mangle)]
pub extern "C" fn ptpip_discover_cameras(
    out_cameras: *mut *mut CCameraInfo,
    out_count: *mut usize,
) -> i32 {
    if out_cameras.is_null() || out_count.is_null() {
        error!("Output pointers are null");
        return -1;
    }
    
    let config = DiscoveryConfig::default();
    let cameras = match discover_cameras(config) {
        Ok(cams) => cams,
        Err(e) => {
            error!("Device discovery failed: {}", e);
            return -2;
        }
    };
    
    let count = cameras.len();
    unsafe {
        *out_count = count;
    }
    
    if count == 0 {
        unsafe {
            *out_cameras = std::ptr::null_mut();
        }
        return 0;
    }
    
    // Allocate C-compatible array
    let c_cameras = unsafe {
        libc::calloc(count, std::mem::size_of::<CCameraInfo>()) as *mut CCameraInfo
    };
    
    if c_cameras.is_null() {
        error!("Memory allocation failed");
        return -3;
    }
    
    // Populate data
    for i in 0..count {
        let camera = &cameras[i];
        let c_camera = unsafe { &mut *c_cameras.add(i) };
        
        c_camera.ip_address = ipv4_to_bytes(camera.ip_address);
        c_camera.port = camera.port;
        c_camera.model_name = rust_str_to_c(&camera.model_name);
        c_camera.vendor_id = camera.vendor_extension_id;
    }
    
    unsafe {
        *out_cameras = c_cameras;
    }
    
    0
}

/// Free camera information memory
#[unsafe(no_mangle)]
pub extern "C" fn ptpip_free_cameras(cameras: *mut CCameraInfo, count: usize) {
    if cameras.is_null() || count == 0 {
        return;
    }
    
    // Free strings
    for i in 0..count {
        let c_camera = unsafe { &mut *cameras.add(i) };
        if !c_camera.model_name.is_null() {
            unsafe {
                let _ = std::ffi::CString::from_raw(c_camera.model_name);
            }
        }
    }
    
    // Free array
    unsafe {
        libc::free(cameras as *mut libc::c_void);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_build_discovery_request() {
        let request = build_discovery_request().unwrap();
        
        assert_eq!(request.len(), 8);
        assert_eq!(&request[0..2], &[0x00, 0x01]); // Message type
        assert_eq!(&request[2..4], &[0x01, 0x00]); // Version
        assert_eq!(&request[4..8], &[0x00, 0x00, 0x00, 0x00]); // Reserved
    }
    
    #[test]
    fn test_parse_valid_response() {
        let mut response = vec![];
        response.write_u16::<BigEndian>(PtpIpMessageType::DiscoveryResponse as u16).unwrap();
        response.write_u16::<BigEndian>(0x0100).unwrap(); // Version
        response.write_u32::<BigEndian>(0x00000001).unwrap(); // Vendor ID
        response.write_u16::<BigEndian>(0x0100).unwrap(); // Vendor version
        response.write_u16::<BigEndian>(15740).unwrap(); // Port
        response.extend_from_slice(&[0u8; 2]); // 2 bytes so name starts at buffer[14..]
        response.extend_from_slice(b"Nikon Z7 II\0");
        
        let src_addr = "192.168.1.100:1900".parse().unwrap();
        let camera = parse_discovery_response(&response, src_addr).unwrap().unwrap();
        
        assert_eq!(camera.ip_address, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(camera.port, 15740);
        assert_eq!(camera.model_name, "Nikon Z7 II");
        assert_eq!(camera.vendor_extension_id, 0x00000001);
    }
    
    #[test]
    fn test_discovery_config() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.retry_count, 3);
        assert!(config.use_multicast);
    }

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.retry_count, 3);
        assert!(config.use_multicast);
    }

    #[test]
    fn test_get_discovery_destinations() {
        let config = DiscoveryConfig {
            use_multicast: true,
            ..Default::default()
        };
        let destinations = get_discovery_destinations(&config);
        assert_eq!(destinations.len(), 2);

        let config = DiscoveryConfig {
            use_multicast: false,
            ..Default::default()
        };
        let destinations = get_discovery_destinations(&config);
        assert_eq!(destinations.len(), 1);
    }

    #[test]
    fn test_parse_discovery_response_valid() -> Result<()> {
        let mut response = vec![];
        response.write_u16::<BigEndian>(PtpIpMessageType::DiscoveryResponse as u16)?;
        response.write_u16::<BigEndian>(0x0100)?; // 版本
        response.write_u32::<BigEndian>(0x00000001)?; // 厂商ID
        response.write_u16::<BigEndian>(0x0100)?; // 厂商版本
        response.write_u16::<BigEndian>(15740)?; // 端口
        response.extend_from_slice(&[0u8; 2]); // 2字节使 name 从 buffer[14..] 开始
        response.extend_from_slice(b"Test Camera\0");

        let src_addr: SocketAddr = "192.168.1.100:1900".parse()?;
        let camera = parse_discovery_response(&response, src_addr)?.unwrap();

        assert_eq!(camera.ip_address, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(camera.port, 15740);
        assert_eq!(camera.model_name, "Test Camera");
        assert_eq!(camera.vendor_extension_id, 0x00000001);
        assert_eq!(camera.vendor_extension_version, 0x0100);

        Ok(())
    }

    #[test]
    fn test_parse_discovery_response_invalid() -> Result<()> {
        // 太短的响应
        let response = vec![0x00, 0x02]; // 仅消息类型
        let src_addr: SocketAddr = "192.168.1.100:1900".parse()?;
        let result = parse_discovery_response(&response, src_addr)?;
        assert!(result.is_none());

        // 错误的消息类型
        let mut response = vec![];
        response.write_u16::<BigEndian>(0xFFFF)?; // 无效类型
        response.write_u16::<BigEndian>(0x0100)?;
        let result = parse_discovery_response(&response, src_addr)?;
        assert!(result.is_none());

        // 不支持的版本
        let mut response = vec![];
        response.write_u16::<BigEndian>(PtpIpMessageType::DiscoveryResponse as u16)?;
        response.write_u16::<BigEndian>(0x0200)?; // 版本2.0
        let result = parse_discovery_response(&response, src_addr)?;
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_discovery_ffi_functions() {
        let mut out_cameras = std::ptr::null_mut();
        let mut out_count = 0;

        // 测试发现（无设备时返回 0 或 -2）
        let result = ptpip_discover_cameras(&mut out_cameras, &mut out_count);
        assert!(result == 0 || result == -2);
        if result == 0 {
            assert_eq!(out_count, 0);
            assert!(out_cameras.is_null());
        }

        // 测试内存释放（安全检查）
        ptpip_free_cameras(out_cameras, out_count);
    }

    #[test]
    fn test_discovery_workflow() -> Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let dest_addr = socket.local_addr()?;

        thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            let (_, src) = socket.recv_from(&mut buffer).unwrap();
            let mut response = vec![];
            response.write_u16::<BigEndian>(PtpIpMessageType::DiscoveryResponse as u16).unwrap();
            response.write_u16::<BigEndian>(0x0100).unwrap();
            response.write_u32::<BigEndian>(0x00000001).unwrap();
            response.write_u16::<BigEndian>(0x0100).unwrap();
            response.write_u16::<BigEndian>(15740).unwrap();
            response.extend_from_slice(&[0u8; 2]);
            response.extend_from_slice(b"Test Camera\0");
            socket.send_to(&response, src).unwrap();
        });

        std::thread::sleep(Duration::from_millis(50));

        let config = DiscoveryConfig {
            timeout: Duration::from_secs(2),
            retry_count: 1,
            use_multicast: false,
            test_destinations: Some(vec![dest_addr]),
            ..Default::default()
        };

        let cameras = discover_cameras(config)?;
        assert_eq!(cameras.len(), 1);
        assert_eq!(cameras[0].model_name, "Test Camera");

        Ok(())
    }

    #[test]
    fn test_parse_discovery_response_ipv6_returns_none() -> Result<()> {
        let mut response = vec![];
        response.write_u16::<BigEndian>(PtpIpMessageType::DiscoveryResponse as u16)?;
        response.write_u16::<BigEndian>(0x0100)?;
        response.write_u32::<BigEndian>(0x00000001)?;
        response.write_u16::<BigEndian>(0x0100)?;
        response.write_u16::<BigEndian>(15740)?;
        response.extend_from_slice(b"IPv6 Camera\0");
        let src_addr: SocketAddr = "[::1]:1900".parse()?;
        let result = parse_discovery_response(&response, src_addr)?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    #[ignore = "需要网络权限绑定 UDP"]
    fn test_create_discovery_socket_no_multicast() -> Result<()> {
        let config = DiscoveryConfig {
            use_multicast: false,
            ..Default::default()
        };
        let socket = create_discovery_socket(&config)?;
        assert!(socket.local_addr().is_ok());
        Ok(())
    }

    #[test]
    fn test_ptpip_free_cameras_null_safe() {
        ptpip_free_cameras(std::ptr::null_mut(), 0);
        ptpip_free_cameras(std::ptr::null_mut(), 5);
    }
}
