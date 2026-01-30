use std::net::Ipv4Addr;
use std::time::Duration;
use rand::Rng;
use rand::thread_rng;

/// PTP/IP protocol constants
pub const PTPIP_HEADER_SIZE: usize = 10;
pub const PTPIP_DEFAULT_PORT: u16 = 15740;
pub const PTPIP_MAX_PACKET_SIZE: usize = 16384; // 16KB

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub timeout: u64,                // Timeout in seconds
    pub max_retries: usize,          // Maximum number of retries
    pub retry_delay_ms: u64,         // Retry delay in milliseconds
    pub keep_alive_interval: u64,    // Keep-alive interval in seconds
    pub version: u16,                // 添加版本字段，例如PTP/IP协议版本
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: 30,
            max_retries: 3,
            retry_delay_ms: 1000,
            keep_alive_interval: 10,
            version: 0x0100
        }
    }
}

// 在src/types.rs中添加SessionHandle类型定义
/// 表示PTP/IP会话句柄
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionHandle(pub u32);

impl SessionHandle {
    /// 创建一个新的会话句柄
    pub fn new(value: u32) -> Self {
        Self(value)
    }
    
    /// 获取会话句柄的原始值
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

// 可以根据需要添加更多方法，如默认值、无效值判断等
impl Default for SessionHandle {
    fn default() -> Self {
        Self(0)
    }
}

impl SessionHandle {
    /// 检查会话句柄是否有效
    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }
    
    /// 获取无效的会话句柄
    pub fn invalid() -> Self {
        Self(0)
    }
}

/// Download statistics
#[derive(Debug, Clone, Default)]
pub struct DownloadStats {
    pub total_bytes: u64,        // Total file size in bytes
    pub downloaded_bytes: u64,   // Downloaded bytes
    pub chunks: usize,           // Number of chunks downloaded
    pub retries: usize,          // Number of retries performed
    pub duration_ms: u64,        // Duration in milliseconds
}

/// PTP/IP message types
#[repr(u16)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PtpIpMessageType {
    DiscoveryRequest = 0x0001,
    DiscoveryResponse = 0x0002,
    CommandBlock = 0x0003,
    DataBlock = 0x0004,
    ResponseBlock = 0x0005,
    EventBlock = 0x0006,
}

/// PTP operation codes
#[repr(u16)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PtpOperationCode {
    Ok = 0x2001,
    GetDeviceInfo = 0x1001,
    OpenSession = 0x1002,
    CloseSession = 0x1003,
    GetStorageIDs = 0x1004,
    GetStorageInfo = 0x1005,
    GetObjectHandles = 0x1006,
    GetObjectInfo = 0x1007,
    GetObject = 0x1008,
    GetThumb = 0x1009,
    DeleteObject = 0x1011,
    MoveObject = 0x1012,
    GetDevicePropValue = 0x1014,
    SetDevicePropValue = 0x1015,
    InitiateCapture = 0x100E,
    GetPartialObject = 0x101B,
    GetObjectMetadata = 0x1023,
    SetObjectMetadata = 0x1024,
}

/// PTP event types
#[repr(u16)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EventType {
    ObjectAdded = 0x4001,
    ObjectRemoved = 0x4002,
    StoreAdded = 0x4003,
    StoreRemoved = 0x4004,
    DevicePropChanged = 0x4005,
    RequestObjectTransfer = 0x4006,
}

/// Discovered camera information
#[derive(Debug, Clone)]
pub struct DiscoveredCamera {
    pub ip_address: Ipv4Addr,
    pub port: u16,
    pub model_name: String,
    pub vendor_extension_id: u32,
    pub vendor_extension_version: u16,
}

/// PTP/IP packet structure
#[derive(Debug)]
pub struct PtpIpPacket {
    pub message_type: PtpIpMessageType,
    pub transaction_id: u32,
    pub payload: Vec<u8>,
}

/// Device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub manufacturer: String,
    pub model: String,
    pub device_version: String,
    pub serial_number: String,
    pub supported_operations: Vec<u16>,
}

/// Storage information
#[derive(Debug, Clone)]
pub struct StorageInfo {
    pub storage_id: u32,
    pub storage_type: u16,
    pub filesystem_type: u16,
    pub access_capability: u16,
    pub max_capacity: u64,
    pub free_space_in_bytes: u64,
    pub free_space_in_objects: u32,
    pub storage_description: String,
    pub volume_label: String,
}

/// Object (photo) information
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub handle: u32,
    pub storage_id: u32,
    pub object_format: u16,
    pub protection_status: u8,
    pub object_size: u64,
    pub thumb_size: u32,
    pub filename: String,
    pub capture_date: String,
    pub modification_date: String,
    pub keywords: String,
}

/// Event data
#[derive(Debug)]
pub struct PtpEvent {
    pub event_type: EventType,
    pub transaction_id: u32,
    pub parameters: Vec<u32>,
}

/// C-compatible camera information (for FFI)
#[repr(C)]
#[derive(Debug)]
pub struct CCameraInfo {
    pub ip_address: [u8; 4],
    pub port: u16,
    pub model_name: *mut libc::c_char,
    pub vendor_id: u32,
}

// 或者对于 newer versions of rand (0.8+)，应该使用：
pub fn generate_transaction_id() -> u32 {
    thread_rng().r#gen::<u32>()
}



/// Convert IPv4 address to byte array
pub fn ipv4_to_bytes(ip: Ipv4Addr) -> [u8; 4] {
    let octets = ip.octets();
    [octets[0], octets[1], octets[2], octets[3]]
}

/// Convert opcode to enum
pub fn opcode_to_enum(opcode: u16) -> Option<PtpOperationCode> {
    match opcode {
        0x2001 => Some(PtpOperationCode::Ok),
        0x1001 => Some(PtpOperationCode::GetDeviceInfo),
        0x1002 => Some(PtpOperationCode::OpenSession),
        0x1003 => Some(PtpOperationCode::CloseSession),
        0x1004 => Some(PtpOperationCode::GetStorageIDs),
        0x1005 => Some(PtpOperationCode::GetStorageInfo),
        0x1006 => Some(PtpOperationCode::GetObjectHandles),
        0x1007 => Some(PtpOperationCode::GetObjectInfo),
        0x1008 => Some(PtpOperationCode::GetObject),
        0x1009 => Some(PtpOperationCode::GetThumb),
        0x1011 => Some(PtpOperationCode::DeleteObject),
        0x1012 => Some(PtpOperationCode::MoveObject),
        0x1014 => Some(PtpOperationCode::GetDevicePropValue),
        0x1015 => Some(PtpOperationCode::SetDevicePropValue),
        0x100E => Some(PtpOperationCode::InitiateCapture),
        0x101B => Some(PtpOperationCode::GetPartialObject),
        0x1023 => Some(PtpOperationCode::GetObjectMetadata),
        0x1024 => Some(PtpOperationCode::SetObjectMetadata),
        _ => None,
    }
}

/// Check if opcode is a response code
pub fn is_response_opcode(opcode: u16) -> bool {
    opcode >= 0x2000 && opcode <= 0x2FFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.timeout, 30);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 1000);
        assert_eq!(config.keep_alive_interval, 10);
    }

    #[test]
    fn test_download_stats_default() {
        let stats = DownloadStats::default();
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.downloaded_bytes, 0);
        assert_eq!(stats.chunks, 0);
        assert_eq!(stats.retries, 0);
        assert_eq!(stats.duration_ms, 0);
    }

    #[test]
    fn test_ptp_ip_message_type_repr() {
        assert_eq!(PtpIpMessageType::DiscoveryRequest as u16, 0x0001);
        assert_eq!(PtpIpMessageType::DiscoveryResponse as u16, 0x0002);
        assert_eq!(PtpIpMessageType::CommandBlock as u16, 0x0003);
        assert_eq!(PtpIpMessageType::DataBlock as u16, 0x0004);
        assert_eq!(PtpIpMessageType::ResponseBlock as u16, 0x0005);
        assert_eq!(PtpIpMessageType::EventBlock as u16, 0x0006);
    }

    #[test]
    fn test_ptp_operation_code_repr() {
        assert_eq!(PtpOperationCode::Ok as u16, 0x2001);
        assert_eq!(PtpOperationCode::GetDeviceInfo as u16, 0x1001);
        assert_eq!(PtpOperationCode::OpenSession as u16, 0x1002);
        assert_eq!(PtpOperationCode::CloseSession as u16, 0x1003);
    }

    #[test]
    fn test_event_type_repr() {
        assert_eq!(EventType::ObjectAdded as u16, 0x4001);
        assert_eq!(EventType::ObjectRemoved as u16, 0x4002);
        assert_eq!(EventType::StoreAdded as u16, 0x4003);
    }

    #[test]
    fn test_discovered_camera() {
        let camera = DiscoveredCamera {
            ip_address: Ipv4Addr::new(192, 168, 1, 100),
            port: 15740,
            model_name: "Test Camera".to_string(),
            vendor_extension_id: 0x12345678,
            vendor_extension_version: 0x0100,
        };
        
        assert_eq!(camera.ip_address, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(camera.port, 15740);
        assert_eq!(camera.model_name, "Test Camera");
    }

    #[test]
    fn test_generate_transaction_id() {
        let id1 = generate_transaction_id();
        let id2 = generate_transaction_id();
        // 极低概率会失败，但为了测试目的可以接受
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_ipv4_to_bytes() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        assert_eq!(ipv4_to_bytes(ip), [192, 168, 1, 100]);
    }

    #[test]
    fn test_opcode_to_enum() {
        assert_eq!(opcode_to_enum(0x2001), Some(PtpOperationCode::Ok));
        assert_eq!(opcode_to_enum(0x1001), Some(PtpOperationCode::GetDeviceInfo));
        assert_eq!(opcode_to_enum(0xFFFF), None);
    }

    #[test]
    fn test_is_response_opcode() {
        assert!(is_response_opcode(0x2000));
        assert!(is_response_opcode(0x2FFF));
        assert!(!is_response_opcode(0x1FFF));
        assert!(!is_response_opcode(0x3000));
    }

    #[test]
    fn test_session_handle_new_and_as_u32() {
        let handle = SessionHandle::new(0x12345678);
        assert_eq!(handle.as_u32(), 0x12345678);
    }

    #[test]
    fn test_session_handle_default() {
        let handle = SessionHandle::default();
        assert_eq!(handle.0, 0);
        assert_eq!(handle.as_u32(), 0);
    }

    #[test]
    fn test_session_handle_is_valid() {
        assert!(!SessionHandle::default().is_valid());
        assert!(!SessionHandle::invalid().is_valid());
        assert!(SessionHandle::new(1).is_valid());
        assert!(SessionHandle::new(0xFFFFFFFF).is_valid());
    }

    #[test]
    fn test_session_handle_invalid() {
        let handle = SessionHandle::invalid();
        assert_eq!(handle.as_u32(), 0);
        assert!(!handle.is_valid());
    }

    #[test]
    fn test_session_handle_eq_hash() {
        let h1 = SessionHandle::new(42);
        let h2 = SessionHandle::new(42);
        let h3 = SessionHandle::new(43);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_session_config_version() {
        let config = SessionConfig::default();
        assert_eq!(config.version, 0x0100);
    }

    #[test]
    fn test_opcode_to_enum_all_variants() {
        assert_eq!(opcode_to_enum(0x2001), Some(PtpOperationCode::Ok));
        assert_eq!(opcode_to_enum(0x1002), Some(PtpOperationCode::OpenSession));
        assert_eq!(opcode_to_enum(0x1003), Some(PtpOperationCode::CloseSession));
        assert_eq!(opcode_to_enum(0x1004), Some(PtpOperationCode::GetStorageIDs));
        assert_eq!(opcode_to_enum(0x1005), Some(PtpOperationCode::GetStorageInfo));
        assert_eq!(opcode_to_enum(0x1006), Some(PtpOperationCode::GetObjectHandles));
        assert_eq!(opcode_to_enum(0x1007), Some(PtpOperationCode::GetObjectInfo));
        assert_eq!(opcode_to_enum(0x1008), Some(PtpOperationCode::GetObject));
        assert_eq!(opcode_to_enum(0x1009), Some(PtpOperationCode::GetThumb));
        assert_eq!(opcode_to_enum(0x1011), Some(PtpOperationCode::DeleteObject));
        assert_eq!(opcode_to_enum(0x1012), Some(PtpOperationCode::MoveObject));
        assert_eq!(opcode_to_enum(0x1014), Some(PtpOperationCode::GetDevicePropValue));
        assert_eq!(opcode_to_enum(0x1015), Some(PtpOperationCode::SetDevicePropValue));
        assert_eq!(opcode_to_enum(0x100E), Some(PtpOperationCode::InitiateCapture));
        assert_eq!(opcode_to_enum(0x101B), Some(PtpOperationCode::GetPartialObject));
        assert_eq!(opcode_to_enum(0x1023), Some(PtpOperationCode::GetObjectMetadata));
        assert_eq!(opcode_to_enum(0x1024), Some(PtpOperationCode::SetObjectMetadata));
    }
}

