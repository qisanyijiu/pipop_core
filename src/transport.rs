use std::io::{self, Read, Write, Cursor};
use std::net::TcpStream;
use std::time::Duration;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::{info, debug, warn, trace};

use crate::error::{PtpIpError, Result};
use crate::types::{
    PtpIpPacket, PtpIpMessageType, PTPIP_HEADER_SIZE,
    PtpOperationCode, opcode_to_enum, is_response_opcode, SessionConfig
};
use crate::utils::{read_u16_be, read_u32_be, bytes_to_hex};

/// PTP/IP packet header structure
#[derive(Debug)]
struct PtpIpHeader {
    message_type: u16,      // Message type (2 bytes)
    reserved: u16,          // Reserved field (2 bytes)
    transaction_id: u32,    // Transaction ID (4 bytes)
    payload_length: u32,    // Payload length (4 bytes, only for data blocks)
}

/// Size of header after message type: reserved(2) + transaction_id(4) = 6 bytes
const HEADER_AFTER_TYPE_SIZE: usize = 6;
/// Full header when type not yet read: type(2) + reserved(2) + transaction_id(4) = 8 bytes
const FULL_HEADER_SIZE: usize = 8;

impl PtpIpHeader {
    /// Read header from stream (message_type may already have been read)
    fn from_stream<R: std::io::Read>(stream: &mut R, message_type: Option<u16>) -> Result<Self> {
        let read_size = if message_type.is_some() {
            HEADER_AFTER_TYPE_SIZE
        } else {
            FULL_HEADER_SIZE
        };
        let mut header_bytes = vec![0u8; read_size];
        stream.read_exact(&mut header_bytes)?;
        
        let mut reader = Cursor::new(&header_bytes);
        let message_type = message_type.unwrap_or_else(|| reader.read_u16::<BigEndian>().unwrap());
        let reserved = reader.read_u16::<BigEndian>()?;
        let transaction_id = reader.read_u32::<BigEndian>()?;
        
        // Data blocks have an additional 4-byte length field
        let payload_length = if message_type == PtpIpMessageType::DataBlock as u16 {
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes)?;
            ((len_bytes[0] as u32) << 24)
                | ((len_bytes[1] as u32) << 16)
                | ((len_bytes[2] as u32) << 8)
                | (len_bytes[3] as u32)
        } else {
            0
        };
        
        Ok(Self {
            message_type,
            reserved,
            transaction_id,
            payload_length,
        })
    }
    
    /// Convert to byte stream
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(PTPIP_HEADER_SIZE);
        bytes.write_u16::<BigEndian>(self.message_type)?;
        bytes.write_u16::<BigEndian>(self.reserved)?;
        bytes.write_u32::<BigEndian>(self.transaction_id)?;
        
        // Data blocks need the length field
        if self.message_type == PtpIpMessageType::DataBlock as u16 {
            bytes.write_u32::<BigEndian>(self.payload_length)?;
        }
        
        Ok(bytes)
    }
}

/// Configure TCP stream parameters
pub fn configure_stream(stream: &TcpStream, config: &SessionConfig) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(config.timeout)))?;
    stream.set_write_timeout(Some(Duration::from_secs(config.timeout)))?;
    stream.set_nodelay(true)?; // Disable Nagle's algorithm to reduce latency
    Ok(())
}

/// Send PTP/IP packet with retry mechanism
pub fn send_packet_with_retry<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    packet: &PtpIpPacket,
    config: &SessionConfig
) -> Result<()> {
    let mut retries = 0;
    
    loop {
        match send_packet(stream, packet) {
            Ok(_) => return Ok(()),
            Err(e) => {
                retries += 1;
                if retries > config.max_retries {
                    return Err(PtpIpError::Other(format!(
                        "Failed to send packet after {} retries: {}", config.max_retries, e
                    )));
                }
                
                warn!("Send failed, retrying (attempt {}): {}", retries, e);
                std::thread::sleep(Duration::from_millis(config.retry_delay_ms));
            }
        }
    }
}

/// Send PTP/IP packet
pub fn send_packet<S: std::io::Write>(stream: &mut S, packet: &PtpIpPacket) -> Result<()> {
    // Build header
    let header = PtpIpHeader {
        message_type: packet.message_type as u16,
        reserved: 0,
        transaction_id: packet.transaction_id,
        payload_length: packet.payload.len() as u32,
    };
    
    // Send header
    let header_bytes = header.to_bytes()?;
    trace!(
        "Sending packet: type={:?}, transaction_id={}, length={}, header={}",
        packet.message_type, 
        packet.transaction_id, 
        packet.payload.len(),
        bytes_to_hex(&header_bytes)
    );
    trace!(" payload: {}", bytes_to_hex(&packet.payload));
    
    stream.write_all(&header_bytes)?;
    
    // Send payload
    if !packet.payload.is_empty() {
        stream.write_all(&packet.payload)?;
    }
    
    stream.flush()?;
    Ok(())
}

/// Receive PTP/IP packet with timeout and type filtering
pub fn recv_packet_filtered<S: std::io::Read>(
    stream: &mut S,
    expected_type: Option<PtpIpMessageType>,
    config: &SessionConfig
) -> Result<PtpIpPacket> {
    let start_time = std::time::Instant::now();
    
    loop {
        // Check for timeout
        if start_time.elapsed() > Duration::from_secs(config.timeout) {
            return Err(PtpIpError::Timeout);
        }
        
        let packet = recv_packet(stream)?;
        
        // Check if type filtering is needed
        if let Some(expected) = expected_type {
            if packet.message_type != expected {
                debug!(
                    "Ignoring packet with mismatched type: received={:?}, expected={:?}",
                    packet.message_type, expected
                );
                continue;
            }
        }
        
        return Ok(packet);
    }
}

/// Receive PTP/IP packet
pub fn recv_packet<S: std::io::Read>(stream: &mut S) -> Result<PtpIpPacket> {
    // First read header to get message type
    let mut type_bytes = [0u8; 2];
    stream.read_exact(&mut type_bytes)?;
    let message_type = ((type_bytes[0] as u16) << 8) | (type_bytes[1] as u16);
    
    // Read complete header
    let header = PtpIpHeader::from_stream(stream, Some(message_type))?;
    
    // Determine message type
    let message_type = match header.message_type {
        0x0003 => PtpIpMessageType::CommandBlock,
        0x0004 => PtpIpMessageType::DataBlock,
        0x0005 => PtpIpMessageType::ResponseBlock,
        0x0006 => PtpIpMessageType::EventBlock,
        _ => return Err(PtpIpError::ProtocolError(format!(
            "Unknown message type: 0x{:04X}", header.message_type
        ))),
    };
    
    // Determine payload length
    let payload_length = if message_type == PtpIpMessageType::DataBlock {
        header.payload_length as usize
    } else if message_type == PtpIpMessageType::ResponseBlock {
        // Parse length from response (first 4 bytes)
        if header.payload_length == 0 {
            let mut len_bytes = [0u8; 4];
            if stream.read_exact(&mut len_bytes).is_ok() {
            let total_len = ((len_bytes[0] as u32) << 24) |
                           ((len_bytes[1] as u32) << 16) |
                           ((len_bytes[2] as u32) << 8) |
                           (len_bytes[3] as u32);
            if total_len >= 4 {
            let payload_len = (total_len - 4) as usize;
            let mut payload = vec![0u8; payload_len];
            if payload_len > 0 {
                stream.read_exact(&mut payload)?;
            }
            
            trace!(
                "Received response packet: type={:?}, transaction_id={}, length={}",
                message_type, header.transaction_id, payload_len
            );
            trace!(" payload: {}", bytes_to_hex(&payload));
            
            return Ok(PtpIpPacket {
                message_type,
                transaction_id: header.transaction_id,
                payload,
            });
            }
            }
        }
        0
    } else {
        0
    };
    
    // Read payload data
    let mut payload = vec![0u8; payload_length];
    if payload_length > 0 {
        stream.read_exact(&mut payload)?;
    }
    
    trace!(
        "Received packet: type={:?}, transaction_id={}, length={}",
        message_type, header.transaction_id, payload_length
    );
    trace!(" payload: {}", bytes_to_hex(&payload));
    
    Ok(PtpIpPacket {
        message_type,
        transaction_id: header.transaction_id,
        payload,
    })
}

/// Parse device info response
pub fn parse_device_info(data: &[u8]) -> Result<crate::types::DeviceInfo> {
    if data.len() < 24 {
        return Err(PtpIpError::ProtocolError(
            "Insufficient data length for device info".to_string()
        ));
    }
    
    let mut cursor = Cursor::new(data);
    
    // Skip first 8 bytes (PTP response header)
    cursor.set_position(8);
    
    // Read string offsets and lengths
    let manufacturer_offset = read_u32_be(&mut cursor)? as usize;
    let manufacturer_len = read_u32_be(&mut cursor)? as usize;
    let model_offset = read_u32_be(&mut cursor)? as usize;
    let model_len = read_u32_be(&mut cursor)? as usize;
    let version_offset = read_u32_be(&mut cursor)? as usize;
    let version_len = read_u32_be(&mut cursor)? as usize;
    let serial_offset = read_u32_be(&mut cursor)? as usize;
    let serial_len = read_u32_be(&mut cursor)? as usize;
    
    // Read supported operations list
    let ops_count = read_u16_be(&mut cursor)? as usize;
    let mut supported_operations = Vec::with_capacity(ops_count);
    for _ in 0..ops_count {
        supported_operations.push(read_u16_be(&mut cursor)?);
    }
    
    // Extract strings
    let manufacturer = extract_string(data, manufacturer_offset, manufacturer_len)?;
    let model = extract_string(data, model_offset, model_len)?;
    let device_version = extract_string(data, version_offset, version_len)?;
    let serial_number = extract_string(data, serial_offset, serial_len)?;
    
    Ok(crate::types::DeviceInfo {
        manufacturer,
        model,
        device_version,
        serial_number,
        supported_operations,
    })
}

/// Parse storage info response
pub fn parse_storage_info(data: &[u8]) -> Result<crate::types::StorageInfo> {
    if data.len() < 40 {
        return Err(PtpIpError::ProtocolError(
            "Insufficient data length for storage info".to_string()
        ));
    }
    
    let mut cursor = Cursor::new(data);
    
    // Skip first 8 bytes (PTP response header)
    cursor.set_position(8);
    
    // Read basic storage info
    let storage_id = read_u32_be(&mut cursor)?;
    let storage_type = read_u16_be(&mut cursor)?;
    let filesystem_type = read_u16_be(&mut cursor)?;
    let access_capability = read_u16_be(&mut cursor)?;
    
    // Read capacity info (8 bytes)
    let max_capacity = read_u64_be(&mut cursor)?;
    let free_space_in_bytes = read_u64_be(&mut cursor)?;
    let free_space_in_objects = read_u32_be(&mut cursor)?;
    
    // Read string offsets and lengths
    let desc_offset = read_u32_be(&mut cursor)? as usize;
    let desc_len = read_u32_be(&mut cursor)? as usize;
    let label_offset = read_u32_be(&mut cursor)? as usize;
    let label_len = read_u32_be(&mut cursor)? as usize;
    
    // Extract strings
    let storage_description = extract_string(data, desc_offset, desc_len)?;
    let volume_label = extract_string(data, label_offset, label_len)?;
    
    Ok(crate::types::StorageInfo {
        storage_id,
        storage_type,
        filesystem_type,
        access_capability,
        max_capacity,
        free_space_in_bytes,
        free_space_in_objects,
        storage_description,
        volume_label,
    })
}

/// Extract string from data
fn extract_string(data: &[u8], offset: usize, length: usize) -> Result<String> {
    if offset + length > data.len() {
        return Err(PtpIpError::ProtocolError(format!(
            "String extraction out of bounds: offset={}, length={}, data length={}",
            offset, length, data.len()
        )));
    }
    
    let slice = &data[offset..offset + length];
    // Remove trailing null characters
    let slice = slice.split(|&b| b == 0).next().unwrap_or(slice);
    
    String::from_utf8(slice.to_vec())
        .map_err(|e| PtpIpError::StringEncoding(e))
}

/// Read 64-bit unsigned integer (big-endian)
fn read_u64_be<R: Read>(reader: &mut R) -> Result<u64> {
    Ok(reader.read_u64::<BigEndian>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    use crate::types::{PtpIpMessageType, PtpOperationCode, SessionConfig};

    // 模拟TcpStream用于测试
    struct MockStream {
        read_buffer: Cursor<Vec<u8>>,
        write_buffer: Vec<u8>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        nodelay: bool,
    }

    impl MockStream {
        fn new(read_data: &[u8]) -> Self {
            Self {
                read_buffer: Cursor::new(read_data.to_vec()),
                write_buffer: Vec::new(),
                read_timeout: None,
                write_timeout: None,
                nodelay: false,
            }
        }

        fn written_data(&self) -> &[u8] {
            &self.write_buffer
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_buffer.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_buffer.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_ptp_ip_header_from_stream() -> Result<()> {
        // 测试普通消息头
        let data = b"\x00\x03\x00\x00\x12\x34\x56\x78"; // CommandBlock类型
        let mut stream = Cursor::new(data);
        let header = PtpIpHeader::from_stream(&mut stream, None)?;
        
        assert_eq!(header.message_type, 0x0003);
        assert_eq!(header.reserved, 0x0000);
        assert_eq!(header.transaction_id, 0x12345678);
        assert_eq!(header.payload_length, 0);

        // 测试数据块消息头
        let data = b"\x00\x04\x00\x00\x87\x65\x43\x21\x00\x00\x00\x0A"; // DataBlock类型， payload长度10
        let mut stream = Cursor::new(data);
        let header = PtpIpHeader::from_stream(&mut stream, None)?;
        
        assert_eq!(header.message_type, 0x0004);
        assert_eq!(header.transaction_id, 0x87654321);
        assert_eq!(header.payload_length, 0x0000000A);
        
        Ok(())
    }

    #[test]
    fn test_ptp_ip_header_to_bytes() -> Result<()> {
        // 测试普通消息头
        let header = PtpIpHeader {
            message_type: 0x0005,
            reserved: 0x0000,
            transaction_id: 0x11223344,
            payload_length: 0,
        };
        
        let bytes = header.to_bytes()?;
        assert_eq!(bytes, b"\x00\x05\x00\x00\x11\x22\x33\x44");

        // 测试数据块消息头
        let header = PtpIpHeader {
            message_type: 0x0004,
            reserved: 0x0000,
            transaction_id: 0x44332211,
            payload_length: 0x00000005,
        };
        
        let bytes = header.to_bytes()?;
        assert_eq!(bytes, b"\x00\x04\x00\x00\x44\x33\x22\x11\x00\x00\x00\x05");
        
        Ok(())
    }

    #[test]
    fn test_configure_stream() -> Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let stream = TcpStream::connect(("127.0.0.1", port))?;
        let _ = listener.accept()?;
        let config = SessionConfig::default();
        configure_stream(&stream, &config)?;
        assert_eq!(stream.read_timeout()?, Some(Duration::from_secs(30)));
        assert_eq!(stream.write_timeout()?, Some(Duration::from_secs(30)));
        assert!(stream.nodelay()?);
        Ok(())
    }

    #[test]
    fn test_send_packet() -> Result<()> {
        let mut mock_stream = MockStream::new(&[]);
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::CommandBlock,
            transaction_id: 0x12345678,
            payload: vec![0x01, 0x02, 0x03],
        };
        
        send_packet(&mut mock_stream, &packet)?;
        
        // 预期的头 +  payload
        let expected = b"\x00\x03\x00\x00\x12\x34\x56\x78\x01\x02\x03";
        assert_eq!(mock_stream.written_data(), expected);
        
        Ok(())
    }

    #[test]
    fn test_recv_packet() -> Result<()> {
        // 测试响应包: 头8 + 长度4 + 主体4 (payload 仅主体)
        let data = b"\x00\x05\x00\x00\x12\x34\x56\x78\x00\x00\x00\x08\x00\x00\x00\x00";
        let mut mock_stream = MockStream::new(data);
        
        let packet = recv_packet(&mut mock_stream)?;
        
        assert_eq!(packet.message_type, PtpIpMessageType::ResponseBlock);
        assert_eq!(packet.transaction_id, 0x12345678);
        assert_eq!(packet.payload, b"\x00\x00\x00\x00"); // 主体不含长度前缀
        
        // 测试数据块
        let data = b"\x00\x04\x00\x00\x87\x65\x43\x21\x00\x00\x00\x05\x01\x02\x03\x04\x05";
        let mut mock_stream = MockStream::new(data);
        
        let packet = recv_packet(&mut mock_stream)?;
        
        assert_eq!(packet.message_type, PtpIpMessageType::DataBlock);
        assert_eq!(packet.transaction_id, 0x87654321);
        assert_eq!(packet.payload, b"\x01\x02\x03\x04\x05");
        
        Ok(())
    }

    #[test]
    fn test_parse_device_info() -> Result<()> {
        // parse_device_info: skip 8, then 8*4=32 offset/len, then ops_count(2)+2 ops(2+2)=6 -> 8+32+6=46
        let manuf_off = 46usize;
        let manuf_len = 11usize;
        let model_off = 57usize;
        let model_len = 5usize;
        let version_off = 62usize;
        let version_len = 5usize;
        let serial_off = 67usize;
        let serial_len = 12usize;
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&(manuf_off as u32).to_be_bytes());
        data.extend_from_slice(&(manuf_len as u32).to_be_bytes());
        data.extend_from_slice(&(model_off as u32).to_be_bytes());
        data.extend_from_slice(&(model_len as u32).to_be_bytes());
        data.extend_from_slice(&(version_off as u32).to_be_bytes());
        data.extend_from_slice(&(version_len as u32).to_be_bytes());
        data.extend_from_slice(&(serial_off as u32).to_be_bytes());
        data.extend_from_slice(&(serial_len as u32).to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&0x1001u16.to_be_bytes());
        data.extend_from_slice(&0x1002u16.to_be_bytes());
        while data.len() < manuf_off {
            data.push(0);
        }
        data.extend_from_slice(b"Manufacturer");
        while data.len() < model_off {
            data.push(0);
        }
        data.extend_from_slice(b"Model");
        while data.len() < version_off {
            data.push(0);
        }
        data.extend_from_slice(b"1.0.0");
        while data.len() < serial_off {
            data.push(0);
        }
        data.extend_from_slice(b"SN1234567890");

        let device_info = parse_device_info(&data)?;

        assert_eq!(device_info.supported_operations.len(), 2);
        assert!(device_info.supported_operations.contains(&0x1001));
        assert!(device_info.supported_operations.contains(&0x1002));
        assert!(!device_info.manufacturer.is_empty());
        assert!(!device_info.model.is_empty());

        Ok(())
    }

    #[test]
    fn test_parse_storage_info() -> Result<()> {
        // parse_storage_info: skip 8, then storage_id(4)+storage_type(2)+filesystem_type(2)+access(2)+max_cap(8)+free_bytes(8)+free_objects(4)=30, then desc_off(4)+desc_len(4)+label_off(4)+label_len(4)=16, so strings at 8+30+16=54
        let desc_off = 54usize;
        let desc_len = 16usize;
        let label_off = 70usize;
        let label_len = 7usize;
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(&65536u64.to_be_bytes());
        data.extend_from_slice(&32768u64.to_be_bytes());
        data.extend_from_slice(&100u32.to_be_bytes());
        data.extend_from_slice(&(desc_off as u32).to_be_bytes());
        data.extend_from_slice(&(desc_len as u32).to_be_bytes());
        data.extend_from_slice(&(label_off as u32).to_be_bytes());
        data.extend_from_slice(&(label_len as u32).to_be_bytes());
        while data.len() < desc_off {
            data.push(0);
        }
        data.extend_from_slice(b"Internal Storage");
        while data.len() < label_off {
            data.push(0);
        }
        data.extend_from_slice(b"SD Card");

        let storage_info = parse_storage_info(&data)?;

        assert_eq!(storage_info.storage_id, 1);
        assert_eq!(storage_info.storage_type, 1);
        assert_eq!(storage_info.filesystem_type, 2);
        assert_eq!(storage_info.access_capability, 3);
        assert_eq!(storage_info.max_capacity, 65536);
        assert_eq!(storage_info.free_space_in_bytes, 32768);
        assert_eq!(storage_info.free_space_in_objects, 100);
        assert_eq!(storage_info.storage_description, "Internal Storage");
        assert_eq!(storage_info.volume_label, "SD Card");

        Ok(())
    }

    #[test]
    fn test_extract_string() -> Result<()> {
        let data = b"Hello\0World\0Test";
        
        let s1 = extract_string(data, 0, 5)?;
        assert_eq!(s1, "Hello");
        
        let s2 = extract_string(data, 6, 5)?;
        assert_eq!(s2, "World");
        
        let s3 = extract_string(data, 12, 4)?;
        assert_eq!(s3, "Test");
        
        // 测试超出范围
        let result = extract_string(data, 20, 5);
        assert!(result.is_err());
        
        Ok(())
    }

    #[test]
    fn test_parse_device_info_insufficient_data() {
        let data = [0u8; 20];
        let result = parse_device_info(&data);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_storage_info_insufficient_data() {
        let data = [0u8; 30];
        let result = parse_storage_info(&data);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_recv_packet_unknown_message_type() {
        let data = b"\x00\x01\x00\x00\x12\x34\x56\x78"; // 0x0001 = DiscoveryRequest, not supported
        let mut stream = MockStream::new(data);
        let result = recv_packet(&mut stream);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_ptp_ip_header_from_stream_with_message_type() -> Result<()> {
        let data = b"\x00\x00\x12\x34\x56\x78"; // 6 bytes when message_type already read
        let mut stream = Cursor::new(data);
        let header = PtpIpHeader::from_stream(&mut stream, Some(0x0003))?;
        assert_eq!(header.message_type, 0x0003);
        assert_eq!(header.reserved, 0x0000);
        assert_eq!(header.transaction_id, 0x12345678);
        assert_eq!(header.payload_length, 0);
        Ok(())
    }

    #[test]
    fn test_send_packet_empty_payload() -> Result<()> {
        let mut mock_stream = MockStream::new(&[]);
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::CommandBlock,
            transaction_id: 0x12345678,
            payload: vec![],
        };
        send_packet(&mut mock_stream, &packet)?;
        let written = mock_stream.written_data();
        assert_eq!(written, b"\x00\x03\x00\x00\x12\x34\x56\x78");
        Ok(())
    }

    #[test]
    fn test_send_packet_with_retry_success_on_first_try() -> Result<()> {
        let mut mock_stream = MockStream::new(&[]);
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::CommandBlock,
            transaction_id: 0x12345678,
            payload: vec![0x01, 0x02],
        };
        let config = SessionConfig::default();
        send_packet_with_retry(&mut mock_stream, &packet, &config)?;
        assert!(!mock_stream.written_data().is_empty());
        Ok(())
    }

    #[test]
    fn test_recv_packet_filtered_type_mismatch() -> Result<()> {
        let mut data = vec![];
        data.extend_from_slice(b"\x00\x03\x00\x00\x12\x34\x56\x78"); // CommandBlock
        data.extend_from_slice(b"\x00\x05\x00\x00\x12\x34\x56\x78\x00\x00\x00\x08\x00\x00\x00\x00"); // ResponseBlock
        let mut stream = MockStream::new(&data);
        let config = SessionConfig::default();
        let packet = recv_packet_filtered(&mut stream, Some(PtpIpMessageType::ResponseBlock), &config)?;
        assert_eq!(packet.message_type, PtpIpMessageType::ResponseBlock);
        Ok(())
    }
}
