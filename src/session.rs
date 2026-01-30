use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use byteorder::{BigEndian, WriteBytesExt};
use log::{info, warn, error};

use crate::error::{PtpIpError, Result};
use crate::types::{
    SessionConfig, PtpOperationCode, PtpIpPacket, PtpIpMessageType,
    generate_transaction_id, opcode_to_enum, SessionHandle,
    DeviceInfo, StorageInfo, ObjectInfo
};
use crate::transport::{send_packet, recv_packet, parse_device_info, parse_storage_info};
use crate::commands::{send_command, get_response};

/// PTP/IP 会话结构体，管理与相机的连接状态
#[derive(Debug)]
pub struct Session {
    stream: TcpStream,          // TCP 流
    config: SessionConfig,      // 会话配置
    session_id: u32,            // 会话 ID
    last_activity: Instant,     // 最后活动时间（用于心跳检测）
    transaction_id: u32,        // 事务 ID 生成器
    is_connected: bool,         // 连接状态
}

impl Session {
    /// 建立新会话
    pub fn connect(ip: &str, port: u16, config: SessionConfig) -> Result<Self> {
        info!("尝试连接到相机: {}:{}", ip, port);
        
        // 建立 TCP 连接
        let mut stream = TcpStream::connect((ip, port))?;
        stream.set_read_timeout(Some(Duration::from_secs(config.timeout)))?;
        stream.set_write_timeout(Some(Duration::from_secs(config.timeout)))?;
        
        info!("TCP 连接已建立，正在创建 PTP 会话...");
        
        // 发送 OpenSession 命令
        let transaction_id = generate_transaction_id();
        let session_id = send_open_session(&mut stream, transaction_id, config.version, &config)?;
        
        info!("PTP 会话创建成功，会话 ID: {}", session_id);
        
        Ok(Self {
            stream,
            config,
            session_id,
            last_activity: Instant::now(),
            transaction_id,
            is_connected: true,
        })
    }
    
    /// 获取会话 ID
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    
    /// 检查连接状态
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }
    
    /// 获取设备信息
    pub fn get_device_info(&mut self) -> Result<DeviceInfo> {
        self.check_heartbeat()?;
        
        let transaction_id = generate_transaction_id();
        send_command(
            &mut self.stream,
            PtpOperationCode::GetDeviceInfo as u16,
            transaction_id,
            &[],
            &self.config
        )?;
        
        let response = get_response(&mut self.stream, transaction_id, &self.config)?;
        let device_info = parse_device_info(&response.payload)?;
        
        self.update_activity();
        Ok(device_info)
    }
    
    /// 获取存储设备列表
    pub fn get_storage_ids(&mut self) -> Result<Vec<u32>> {
        self.check_heartbeat()?;
        
        let transaction_id = generate_transaction_id();
        send_command(
            &mut self.stream,
            PtpOperationCode::GetStorageIDs as u16,
            transaction_id,
            &[],
            &self.config
        )?;
        
        let response = get_response(&mut self.stream, transaction_id, &self.config)?;
        self.parse_storage_ids(&response.payload)
    }
    
    /// 获取存储设备信息
    pub fn get_storage_info(&mut self, storage_id: u32) -> Result<StorageInfo> {
        self.check_heartbeat()?;
        
        let transaction_id = generate_transaction_id();
        let mut params = vec![];
        params.write_u32::<BigEndian>(storage_id)?;
        
        send_command(
            &mut self.stream,
            PtpOperationCode::GetStorageInfo as u16,
            transaction_id,
            &params,
            &self.config
        )?;
        
        let response = get_response(&mut self.stream, transaction_id, &self.config)?;
        let storage_info = parse_storage_info(&response.payload)?;
        
        self.update_activity();
        Ok(storage_info)
    }
    
    /// 检查心跳（如果长时间无活动则发送心跳包）
    fn check_heartbeat(&mut self) -> Result<()> {
        if self.is_connected && 
           self.last_activity.elapsed() > Duration::from_secs(self.config.timeout / 2) {
            info!("发送心跳包维持会话");
            self.send_heartbeat()?;
        }
        Ok(())
    }
    
    /// 发送心跳包（使用 GetDeviceInfo 作为心跳命令）
    fn send_heartbeat(&mut self) -> Result<()> {
        let transaction_id = generate_transaction_id();
        send_command(
            &mut self.stream,
            PtpOperationCode::GetDeviceInfo as u16,
            transaction_id,
            &[],
            &self.config
        )?;
        
        // 不需要处理响应内容，只需确认收到响应
        let _ = get_response(&mut self.stream, transaction_id, &self.config)?;
        self.update_activity();
        Ok(())
    }
    
    /// 更新最后活动时间
    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// 解析存储 ID 列表
    fn parse_storage_ids(&self, data: &[u8]) -> Result<Vec<u32>> {
        if data.len() < 2 {
            return Err(PtpIpError::ProtocolError(
                "存储 ID 列表数据长度不足".to_string()
            ));
        }
        
        let count = (data[0] as usize) << 8 | data[1] as usize;
        let mut storage_ids = Vec::with_capacity(count);
        
        for i in 0..count {
            let start = 2 + i * 4;
            if start + 4 > data.len() {
                return Err(PtpIpError::ProtocolError(
                    "存储 ID 数据不完整".to_string()
                ));
            }
            
            let storage_id = ((data[start] as u32) << 24) |
                             ((data[start + 1] as u32) << 16) |
                             ((data[start + 2] as u32) << 8) |
                             (data[start + 3] as u32);
            
            storage_ids.push(storage_id);
        }
        
        Ok(storage_ids)
    }
}

/// 会话结束时关闭连接
impl Drop for Session {
    fn drop(&mut self) {
        if self.is_connected {
            info!("正在关闭会话 ID: {}", self.session_id);
            let _ = send_close_session(&mut self.stream, generate_transaction_id(), self.session_id, &self.config);
            self.is_connected = false;
        }
    }
}

/// 发送 OpenSession 命令并获取会话 ID
fn send_open_session(stream: &mut TcpStream, transaction_id: u32, version: u16, config: &SessionConfig) -> Result<u32> {
    // 构建 OpenSession 命令参数
    let mut params = vec![];
    params.write_u16::<BigEndian>(version)?; // PTP 版本
    params.write_u32::<BigEndian>(0x00000000)?; // 保留字段
    
    // 发送命令
    send_command(
        stream,
        PtpOperationCode::OpenSession as u16,
        transaction_id,
        &params,
        config
    )?;
    
    // 接收响应
    let response = get_response(stream, transaction_id, config)?;
    
    // 解析会话 ID
    if response.payload.len() < 4 {
        return Err(PtpIpError::ProtocolError(
            "OpenSession 响应数据不足".to_string()
        ));
    }
    
    let session_id = ((response.payload[0] as u32) << 24) |
                     ((response.payload[1] as u32) << 16) |
                     ((response.payload[2] as u32) << 8) |
                     (response.payload[3] as u32);
    
    Ok(session_id)
}

/// 发送 CloseSession 命令
fn send_close_session(stream: &mut TcpStream, transaction_id: u32, session_id: u32, config: &SessionConfig) -> Result<()> {
    // 构建 CloseSession 命令参数
    let mut params = vec![];
    params.write_u32::<BigEndian>(session_id)?; // 会话 ID
    
    // 发送命令
    send_command(
        stream,
        PtpOperationCode::CloseSession as u16,
        transaction_id,
        &params,
        config
    )?;
    
    // 等待响应
    let _ = get_response(stream, transaction_id, config)?;
    Ok(())
}

// --- FFI 接口 ---

/// 创建新会话（供 Swift 调用）
#[unsafe(no_mangle)]
pub extern "C" fn ptpip_create_session(
    ip: *const libc::c_char,
    port: u16,
    timeout: u32,
) -> *mut SessionHandle {
    let ip_str = unsafe {
        if ip.is_null() {
            error!("IP 地址为空");
            return std::ptr::null_mut();
        }
        std::ffi::CStr::from_ptr(ip).to_str()
    };
    
    let ip_str = match ip_str {
        Ok(s) => s,
        Err(e) => {
            error!("无效的 IP 地址格式: {}", e);
            return std::ptr::null_mut();
        }
    };
    
    let config = SessionConfig {
        timeout: timeout.into(),
        ..SessionConfig::default()
    };
    
    match Session::connect(ip_str, port, config) {
        Ok(session) => {
            let arc_session = Arc::new(Mutex::new(session));
            Arc::into_raw(arc_session) as *mut SessionHandle
        }
        Err(e) => {
            error!("创建会话失败: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// 关闭会话（供 Swift 调用）
#[unsafe(no_mangle)]
pub extern "C" fn ptpip_close_session(session_ptr: *mut SessionHandle) {
    if session_ptr.is_null() {
        return;
    }
    
    unsafe {
        let _ = Arc::from_raw(session_ptr as *mut Mutex<Session>);
    }
}

/// 检查会话连接状态（供 Swift 调用）
#[unsafe(no_mangle)]
pub extern "C" fn ptpip_is_connected(session_ptr: *mut SessionHandle) -> bool {
    if session_ptr.is_null() {
        return false;
    }
    
    let arc_session = unsafe { Arc::from_raw(session_ptr as *mut Mutex<Session>) };
    let is_connected = arc_session.lock().unwrap().is_connected();
    std::mem::forget(arc_session);
    is_connected
}

/// 获取会话 ID（供 Swift 调用）
#[unsafe(no_mangle)]
pub extern "C" fn ptpip_get_session_id(session_ptr: *mut SessionHandle) -> u32 {
    if session_ptr.is_null() {
        return 0;
    }
    
    let arc_session = unsafe { Arc::from_raw(session_ptr as *mut Mutex<Session>) };
    let session_id = arc_session.lock().unwrap().session_id();
    std::mem::forget(arc_session);
    session_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::time::Duration;

    #[test]
    fn test_ptpip_create_session_null_ip() {
        let result = ptpip_create_session(std::ptr::null(), 15740, 30);
        assert!(result.is_null());
    }

    #[test]
    fn test_ptpip_close_session_null() {
        ptpip_close_session(std::ptr::null_mut());
    }

    #[test]
    fn test_ptpip_is_connected_null() {
        assert!(!ptpip_is_connected(std::ptr::null_mut()));
    }

    #[test]
    fn test_ptpip_get_session_id_null() {
        assert_eq!(ptpip_get_session_id(std::ptr::null_mut()), 0);
    }

    #[test]
    fn test_ptpip_create_session_invalid_ip() {
        let ip = CString::new("999.999.999.999").unwrap();
        let result = ptpip_create_session(ip.as_ptr(), 15740, 5);
        assert!(result.is_null());
    }

    #[test]
    #[ignore = "需要网络权限创建 TCP 连接"]
    fn test_parse_storage_ids_success() {
        let session = create_test_session();
        let data = [0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
        let result = session.parse_storage_ids(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x00000001, 0x00000002]);
    }

    #[test]
    #[ignore = "需要网络权限创建 TCP 连接"]
    fn test_parse_storage_ids_insufficient_data() {
        let session = create_test_session();
        let data = [0x00];
        let result = session.parse_storage_ids(&data);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    #[ignore = "需要网络权限创建 TCP 连接"]
    fn test_parse_storage_ids_incomplete() {
        let session = create_test_session();
        let data = [0x00, 0x02, 0x00, 0x00]; // count=2 but only 0 bytes of storage ids
        let result = session.parse_storage_ids(&data);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    fn create_test_session() -> Session {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut server, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf);
            let session_id: u32 = 0x12345678;
            let mut resp = vec![0x00u8, 0x05, 0x00, 0x00];
            resp.extend_from_slice(&0u32.to_be_bytes());
            resp.extend_from_slice(&4u32.to_be_bytes());
            resp.extend_from_slice(&session_id.to_be_bytes());
            let _ = server.write_all(&resp);
        });
        std::thread::sleep(Duration::from_millis(50));
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        Session {
            stream: client,
            config: SessionConfig::default(),
            session_id: 0x12345678,
            last_activity: Instant::now(),
            transaction_id: 0,
            is_connected: true,
        }
    }
}
