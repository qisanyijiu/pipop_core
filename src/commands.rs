use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::{info, debug, warn, error, trace};

use crate::error::{PtpIpError, Result};
use crate::types::{
    PtpIpPacket, PtpIpMessageType, PtpOperationCode,
    ObjectInfo, generate_transaction_id, SessionConfig,
    DownloadStats, EventType, PtpEvent
};
use crate::transport::{send_packet_with_retry, recv_packet_filtered, configure_stream};
use crate::utils::{read_u16_be, read_u32_be, read_u64_be, bytes_to_hex};

/// Download progress callback type definition
/// Parameters: current bytes downloaded / total bytes / is complete / statistics
pub type DownloadProgressCallback = Box<dyn Fn(usize, usize, bool, &DownloadStats) + Send + 'static>;

/// Chunk download configuration
#[derive(Debug, Clone)]
pub struct ChunkDownloadConfig {
    pub chunk_size: usize,          // Chunk size (default 1MB)
    pub progress_interval: f32,     // Progress callback interval (percentage, default 5%)
    pub min_chunk_size: usize,      // Minimum chunk size (for final chunk)
}

impl Default for ChunkDownloadConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024,    // 1MB
            progress_interval: 5.0,     // Trigger every 5%
            min_chunk_size: 1024 * 64,  // 64KB
        }
    }
}

// ------------------------------
// High-level API - Camera Client
// ------------------------------

/// Camera client (high-level API encapsulating all operations)
pub struct CameraClient {
    stream: TcpStream,
    session_id: u32,
    config: SessionConfig,
    event_receiver: Option<std::sync::mpsc::Receiver<PtpEvent>>,
}

impl CameraClient {
    /// Connect to a camera
    pub fn connect(
        ip: &str,
        port: u16,
        config: SessionConfig
    ) -> Result<Self> {
        info!("Connecting to camera: {}:{}", ip, port);
        let mut stream = TcpStream::connect((ip, port))?;
        configure_stream(&stream, &config)?;
        
        // Open session
        let session_id = generate_transaction_id();
        let transaction_id = generate_transaction_id();
        let mut params = vec![];
        params.write_u32::<BigEndian>(session_id)?;
        
        send_command(
            &mut stream,
            PtpOperationCode::OpenSession as u16,
            transaction_id,
            &params,
            &config
        )?;
        
        let _ = get_response(&mut stream, transaction_id, &config)?;
        info!("Session opened, ID: {}", session_id);
        
        // Start event listener
        let (event_sender, event_receiver) = std::sync::mpsc::channel();
        let mut event_stream = stream.try_clone()?;
        let event_config = config.clone();
        
        std::thread::spawn(move || {
            let mut event_stream = event_stream;
            loop {
                match recv_packet_filtered(
                    &mut event_stream,
                    Some(PtpIpMessageType::EventBlock),
                    &event_config
                ) {
                    Ok(packet) => {
                        if let Ok(event) = parse_event_packet(&packet) {
                            trace!("Received event: {:?}", event);
                            if event_sender.send(event).is_err() {
                                error!("Event receiver closed, stopping event listener");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Event reception error: {}", e);
                        if let PtpIpError::Timeout = e {
                            continue; // Timeout is normal, keep listening
                        }
                        break;
                    }
                }
            }
        });
        
        Ok(Self {
            stream,
            session_id,
            config,
            event_receiver: Some(event_receiver),
        })
    }
    
    /// Get device information
    pub fn get_device_info(&mut self) -> Result<crate::types::DeviceInfo> {
        let transaction_id = generate_transaction_id();
        send_command(
            &mut self.stream,
            PtpOperationCode::GetDeviceInfo as u16,
            transaction_id,
            &[],
            &self.config
        )?;
        
        let response = get_response(&mut self.stream, transaction_id, &self.config)?;
        crate::transport::parse_device_info(&response.payload)
    }
    
    /// Get storage list
    pub fn get_storage_ids(&mut self) -> Result<Vec<u32>> {
        let transaction_id = generate_transaction_id();
        send_command(
            &mut self.stream,
            PtpOperationCode::GetStorageIDs as u16,
            transaction_id,
            &[],
            &self.config
        )?;
        
        let response = get_response(&mut self.stream, transaction_id, &self.config)?;
        parse_storage_ids(&response.payload)
    }
    
    /// Get storage information
    pub fn get_storage_info(&mut self, storage_id: u32) -> Result<crate::types::StorageInfo> {
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
        crate::transport::parse_storage_info(&response.payload)
    }
    
    /// Get object handle list
    pub fn get_object_handles(
        &mut self,
        storage_id: u32,
        object_format: u16,
        max_count: u32
    ) -> Result<Vec<u32>> {
        let transaction_id = generate_transaction_id();
        let mut params = vec![];
        
        params.write_u32::<BigEndian>(storage_id)?;
        params.write_u16::<BigEndian>(object_format)?;
        params.write_u16::<BigEndian>(0x0000)?; // Reserved
        params.write_u32::<BigEndian>(0)?; // Start index
        params.write_u32::<BigEndian>(max_count)?;
        
        send_command(
            &mut self.stream,
            PtpOperationCode::GetObjectHandles as u16,
            transaction_id,
            &params,
            &self.config
        )?;
        
        let response = get_response(&mut self.stream, transaction_id, &self.config)?;
        parse_object_handles(&response.payload)
    }
    
    /// Get object information
    pub fn get_object_info(&mut self, object_handle: u32) -> Result<ObjectInfo> {
        let transaction_id = generate_transaction_id();
        let mut params = vec![];
        params.write_u32::<BigEndian>(object_handle)?;
        
        send_command(
            &mut self.stream,
            PtpOperationCode::GetObjectInfo as u16,
            transaction_id,
            &params,
            &self.config
        )?;
        
        let response = get_response(&mut self.stream, transaction_id, &self.config)?;
        parse_object_info(&response.payload, object_handle)
    }
    
    /// Remote capture
    pub fn initiate_capture(
        &mut self,
        storage_id: u32,
        format: u16
    ) -> Result<u32> {
        info!("Triggering remote capture, storage ID: {}, format: 0x{:04X}", storage_id, format);
        
        let transaction_id = generate_transaction_id();
        let mut params = vec![];
        
        params.write_u32::<BigEndian>(storage_id)?;
        params.write_u16::<BigEndian>(format)?;
        params.write_u16::<BigEndian>(0x0000)?; // Reserved
        
        send_command(
            &mut self.stream,
            PtpOperationCode::InitiateCapture as u16,
            transaction_id,
            &params,
            &self.config
        )?;
        
        let response = get_response(&mut self.stream, transaction_id, &self.config)?;
        
        if response.payload.len() < 12 {
            return Err(PtpIpError::ProtocolError(
                "Insufficient data length for capture response".to_string()
            ));
        }
        
        let mut cursor = Cursor::new(&response.payload);
        cursor.set_position(8);
        let object_handle = read_u32_be(&mut cursor)?;
        
        info!("Capture successful, new photo handle: {}", object_handle);
        Ok(object_handle)
    }
    
    /// Download photo (with resume and progress callback)
    pub fn download_photo(
        &mut self,
        object_handle: u32,
        save_path: &Path,
        download_config: ChunkDownloadConfig,
        progress_callback: DownloadProgressCallback
    ) -> Result<DownloadStats> {
        let start_time = Instant::now();
        let mut stats = DownloadStats::default();
        
        // Get object information
        let object_info = self.get_object_info(object_handle)?;
        stats.total_bytes = object_info.object_size;
        
        // Perform chunked download
        download_object_with_resume(
            &mut self.stream,
            object_handle,
            save_path,
            &self.config,
            download_config,
            &mut stats,
            progress_callback
        )?;
        
        // Calculate download time
        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        info!(
            "Download completed: {} ({} bytes), duration: {}ms, retries: {}",
            save_path.display(),
            stats.total_bytes,
            stats.duration_ms,
            stats.retries
        );
        
        Ok(stats)
    }
    
    /// Delete photo
    pub fn delete_object(&mut self, object_handle: u32) -> Result<()> {
        info!("Deleting photo, handle: {}", object_handle);
        
        let transaction_id = generate_transaction_id();
        let mut params = vec![];
        params.write_u32::<BigEndian>(object_handle)?;
        
        send_command(
            &mut self.stream,
            PtpOperationCode::DeleteObject as u16,
            transaction_id,
            &params,
            &self.config
        )?;
        
        let _ = get_response(&mut self.stream, transaction_id, &self.config)?;
        info!("Photo deleted successfully");
        Ok(())
    }
    
    /// Get event receiver
    pub fn event_receiver(&mut self) -> Option<&std::sync::mpsc::Receiver<PtpEvent>> {
        self.event_receiver.as_ref()
    }
    
    /// Close session
    pub fn close(&mut self) -> Result<()> {
        info!("Closing session, ID: {}", self.session_id);
        let transaction_id = generate_transaction_id();
        let mut params = vec![];
        params.write_u32::<BigEndian>(self.session_id)?;
        
        send_command(
            &mut self.stream,
            PtpOperationCode::CloseSession as u16,
            transaction_id,
            &params,
            &self.config
        )?;
        
        let _ = get_response(&mut self.stream, transaction_id, &self.config)?;
        Ok(())
    }
}

// ------------------------------
// Chunked Download Implementation (with resume and progress)
// ------------------------------

/// Large file download with resume capability and progress callback
fn download_object_with_resume(
    stream: &mut TcpStream,
    object_handle: u32,
    save_path: &Path,
    session_config: &SessionConfig,
    download_config: ChunkDownloadConfig,
    stats: &mut DownloadStats,
    progress_callback: DownloadProgressCallback
) -> Result<()> {
    // Check file status
    let (mut current_offset, mut file) = check_resume_state(save_path, stats.total_bytes as usize)?;
    stats.downloaded_bytes = current_offset as u64;

    // Calculate progress checkpoints
    let progress_checkpoints: Vec<usize> = (1..=20)
        .map(|i| ((i as f32 * download_config.progress_interval / 100.0) * stats.total_bytes as f32) as usize)
        .collect();

    let mut last_reported_progress = 0;
    let total_size = stats.total_bytes as usize;

    // Main chunk download loop
    while current_offset < total_size {
        // Calculate current chunk size
        let remaining = total_size - current_offset;
        let chunk_size = std::cmp::min(
            if remaining < download_config.min_chunk_size {
                remaining
            } else {
                download_config.chunk_size
            },
            remaining
        );

        // Download current chunk (with retry)
        let data = download_with_retry(
            stream,
            object_handle,
            current_offset as u64,
            chunk_size as u32,
            session_config,
            stats
        )?;

        // Verify data integrity
        if data.len() != chunk_size {
            save_resume_state(save_path, current_offset)?;
            return Err(PtpIpError::ProtocolError(format!(
                "Incomplete chunk data: expected {} bytes, received {} bytes",
                chunk_size, data.len()
            )));
        }

        // Write to file
        file.write_all(&data)?;
        current_offset += chunk_size;
        stats.downloaded_bytes = current_offset as u64;
        stats.chunks += 1;

        debug!(
            "Download progress: {}/{} bytes ({:.1}%)",
            current_offset, total_size,
            (current_offset as f32 / total_size as f32) * 100.0
        );

        // Trigger progress callback
        if let Some(next_checkpoint) = progress_checkpoints
            .iter()
            .find(|&&p| p > last_reported_progress && current_offset >= p)
        {
            progress_callback(current_offset, total_size, false, stats);
            last_reported_progress = *next_checkpoint;
        }

        // Save resume point
        save_resume_state(save_path, current_offset)?;
    }

    // Complete download
    file.flush()?;
    drop(file);

    // Rename temporary file
    let temp_path = get_temp_path(save_path);
    fs::rename(&temp_path, save_path)?;
    
    // Delete resume file
    let resume_path = get_resume_path(save_path);
    let _ = fs::remove_file(resume_path);

    // Final callback
    progress_callback(total_size, total_size, true, stats);
    Ok(())
}

/// Chunk download with retry mechanism
fn download_with_retry(
    stream: &mut TcpStream,
    object_handle: u32,
    offset: u64,
    length: u32,
    config: &SessionConfig,
    stats: &mut DownloadStats
) -> Result<Vec<u8>> {
    let mut retries = 0;
    
    loop {
        match get_partial_object(stream, object_handle, offset, length, config) {
            Ok(data) => return Ok(data),
            Err(e) => {
                retries += 1;
                stats.retries += 1;
                
                if retries > config.max_retries {
                    error!(
                        "Chunk download failed after {} retries: offset={}, length={}, error: {}",
                        config.max_retries, offset, length, e
                    );
                    return Err(e);
                }
                
                warn!(
                    "Chunk download failed, retrying (attempt {}): {}",
                    retries, e
                );
                std::thread::sleep(Duration::from_millis(config.retry_delay_ms));
            }
        }
    }
}

/// Chunk download implementation
fn get_partial_object(
    stream: &mut TcpStream,
    object_handle: u32,
    offset: u64,
    length: u32,
    config: &SessionConfig
) -> Result<Vec<u8>> {
    trace!(
        "Downloading chunk: handle={}, offset={} bytes, length={} bytes",
        object_handle, offset, length
    );
    
    let transaction_id = generate_transaction_id();
    let mut params = vec![];
    
    // Build parameters
    params.write_u32::<BigEndian>(object_handle)?;
    params.write_u64::<BigEndian>(offset)?;
    params.write_u32::<BigEndian>(length)?;
    
    // Send command
    send_command(
        stream,
        PtpOperationCode::GetPartialObject as u16,
        transaction_id,
        &params,
        config
    )?;
    
    // Receive data block
    receive_data_block(stream, transaction_id, config)
}

// ------------------------------
// Resume Helper Functions
// ------------------------------

/// Check resume state
fn check_resume_state(save_path: &Path, total_size: usize) -> Result<(usize, File)> {
    let temp_path = get_temp_path(save_path);
    let resume_path = get_resume_path(save_path);

    // Target file exists and is complete
    if save_path.exists() {
        let metadata = fs::metadata(save_path)?;
        if metadata.len() as usize == total_size {
            return Ok((total_size, File::open(&save_path)?));
        }
    }

    // Check for resume point
    if resume_path.exists() && temp_path.exists() {
        let resume_data = fs::read_to_string(&resume_path)?;
        let current_offset: usize = resume_data.trim().parse()
            .map_err(|_| PtpIpError::InvalidResumeData)?;

        let temp_metadata = fs::metadata(&temp_path)?;
        if temp_metadata.len() as usize != current_offset {
            warn!(
                "Resume record mismatch with temporary file, restarting download: record={} bytes, actual={} bytes",
                current_offset, temp_metadata.len()
            );
            fs::remove_file(&resume_path)?;
            fs::remove_file(&temp_path)?;
            return Ok((0, File::create(&temp_path)?));
        }

        if current_offset >= total_size {
            fs::rename(&temp_path, save_path)?;
            fs::remove_file(&resume_path)?;
            return Ok((total_size, File::open(save_path)?));
        }

        info!("Resuming download from: {} bytes", current_offset);
        return Ok((current_offset, File::options()
            .append(true)
            .open(&temp_path)?));
    }

    // Start from beginning
    if temp_path.exists() {
        fs::remove_file(&temp_path)?;
    }
    Ok((0, File::create(&temp_path)?))
}

/// Save resume state
fn save_resume_state(save_path: &Path, offset: usize) -> Result<()> {
    let resume_path = get_resume_path(save_path);
    fs::write(&resume_path, offset.to_string())?;
    Ok(())
}

/// Get temporary file path
fn get_temp_path(save_path: &Path) -> PathBuf {
    let mut temp_path = save_path.to_path_buf();
    let file_name = temp_path.file_name()
        .map(|n| format!(".{}.download", n.to_string_lossy()))
        .unwrap_or_else(|| ".download.tmp".to_string());
    temp_path.set_file_name(file_name);
    temp_path
}

/// Get resume file path
fn get_resume_path(save_path: &Path) -> PathBuf {
    let mut resume_path = save_path.to_path_buf();
    let file_name = resume_path.file_name()
        .map(|n| format!(".{}.resume", n.to_string_lossy()))
        .unwrap_or_else(|| ".resume".to_string());
    resume_path.set_file_name(file_name);
    resume_path
}

// ------------------------------
// Command Sending and Response Handling
// ------------------------------

/// Send PTP command
pub fn send_command<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    opcode: u16,
    transaction_id: u32,
    parameters: &[u8],
    config: &SessionConfig
) -> Result<()> {
    // Parse parameters
    let mut params = Vec::new();
    let mut cursor = Cursor::new(parameters);
    while cursor.position() < parameters.len() as u64 {
        params.push(read_u32_be(&mut cursor)?);
    }
    
    // Create command
    let command = PtpCommand::new(opcode, &params);
    let command_bytes = command.to_bytes()?;
    
    debug!(
        "Sending command: opcode=0x{:04X}, transaction_id={}, parameter count={}",
        opcode, transaction_id, params.len()
    );
    trace!("Command data: {}", bytes_to_hex(&command_bytes));
    
    // Send packet
    let packet = PtpIpPacket {
        message_type: PtpIpMessageType::CommandBlock,
        transaction_id,
        payload: command_bytes,
    };
    
    send_packet_with_retry(stream, &packet, config)?;
    Ok(())
}

/// Get command response
pub fn get_response<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    expected_transaction_id: u32,
    config: &SessionConfig
) -> Result<PtpIpPacket> {
    loop {
        let packet = recv_packet_filtered(
            stream,
            Some(PtpIpMessageType::ResponseBlock),
            config
        )?;
        
        if packet.transaction_id != expected_transaction_id {
            warn!(
                "Transaction ID mismatch: received={}, expected={}",
                packet.transaction_id, expected_transaction_id
            );
            continue;
        }
        
        check_response_error(&packet)?;
        return Ok(packet);
    }
}

/// Check response for errors
fn check_response_error(packet: &PtpIpPacket) -> Result<()> {
    if packet.payload.len() < 8 {
        return Err(PtpIpError::ProtocolError(
            "Insufficient response packet length".to_string()
        ));
    }
    
    let mut cursor = Cursor::new(&packet.payload);
    cursor.set_position(2); // skip version(2), then read response_code(2)
    let response_code = read_u16_be(&mut cursor)?;
    
    if response_code != PtpOperationCode::Ok as u16 {
        let error_msg = match response_code {
            0x2002 => "General error".to_string(),
            0x2003 => "Session not open".to_string(),
            0x2004 => "Invalid transaction ID".to_string(),
            0x2005 => "Unsupported operation".to_string(),
            0x2006 => "Unsupported parameter".to_string(),
            0x2007 => "Incomplete transfer".to_string(),
            0x2008 => "Invalid storage ID".to_string(),
            0x2009 => "Invalid object handle".to_string(),
            _ => format!("Unknown error (0x{:04X})", response_code),
        };
        
        return Err(PtpIpError::DeviceError {
            code: response_code as u32,
            message: error_msg,
        });
    }
    
    Ok(())
}

// ------------------------------
// Data Parsing Functions
// ------------------------------

/// Parse storage ID list
fn parse_storage_ids(data: &[u8]) -> Result<Vec<u32>> {
    if data.len() < 10 {
        return Err(PtpIpError::ProtocolError(
            "Insufficient data for storage ID list".to_string()
        ));
    }
    
    let mut cursor = Cursor::new(data);
    cursor.set_position(8); // Skip header
    
    let count = read_u32_be(&mut cursor)? as usize;
    let mut storage_ids = Vec::with_capacity(count);
    
    for _ in 0..count {
        storage_ids.push(read_u32_be(&mut cursor)?);
    }
    
    Ok(storage_ids)
}

/// Parse object handles
fn parse_object_handles(data: &[u8]) -> Result<Vec<u32>> {
    if data.len() < 10 {
        return Err(PtpIpError::ProtocolError(
            "Insufficient data length for object handles".to_string()
        ));
    }
    
    let mut cursor = Cursor::new(data);
    cursor.set_position(8); // Skip header
    
    let count = read_u32_be(&mut cursor)? as usize;
    let mut handles = Vec::with_capacity(count);
    
    for _ in 0..count {
        handles.push(read_u32_be(&mut cursor)?);
    }
    
    info!("Parsed {} object handles", handles.len());
    Ok(handles)
}

/// Parse object information
fn parse_object_info(data: &[u8], object_handle: u32) -> Result<ObjectInfo> {
    if data.len() < 64 {
        return Err(PtpIpError::ProtocolError(
            "Insufficient data length for object info".to_string()
        ));
    }
    
    let mut cursor = Cursor::new(data);
    cursor.set_position(8); // Skip header
    
    // Read basic information
    let storage_id = read_u32_be(&mut cursor)?;
    let object_format = read_u16_be(&mut cursor)?;
    let protection_status = read_u8_be(&mut cursor)?;
    cursor.set_position(cursor.position() + 1); // Skip reserved
    
    let object_size = read_u64_be(&mut cursor)?;
    let thumb_size = read_u32_be(&mut cursor)?;
    
    // Read string offsets and lengths
    let filename_offset = read_u32_be(&mut cursor)? as usize;
    let filename_len = read_u32_be(&mut cursor)? as usize;
    let capture_date_offset = read_u32_be(&mut cursor)? as usize;
    let capture_date_len = read_u32_be(&mut cursor)? as usize;
    let modification_date_offset = read_u32_be(&mut cursor)? as usize;
    let modification_date_len = read_u32_be(&mut cursor)? as usize;
    let keywords_offset = read_u32_be(&mut cursor)? as usize;
    let keywords_len = read_u32_be(&mut cursor)? as usize;
    
    // Extract strings
    let filename = extract_string(data, filename_offset, filename_len)?;
    let capture_date = extract_string(data, capture_date_offset, capture_date_len)?;
    let modification_date = extract_string(data, modification_date_offset, modification_date_len)?;
    let keywords = extract_string(data, keywords_offset, keywords_len)?;
    
    Ok(ObjectInfo {
        handle: object_handle,
        storage_id,
        object_format,
        protection_status,
        object_size,
        thumb_size,
        filename,
        capture_date,
        modification_date,
        keywords,
    })
}

/// Parse event packet
fn parse_event_packet(packet: &PtpIpPacket) -> Result<PtpEvent> {
    if packet.payload.len() < 6 {
        return Err(PtpIpError::ProtocolError(
            "Insufficient data length for event packet".to_string()
        ));
    }
    
    let mut cursor = Cursor::new(&packet.payload);
    let event_code = read_u16_be(&mut cursor)?;
    let param_count = read_u16_be(&mut cursor)? as usize;
    
    // Parse parameters
    let mut parameters = Vec::with_capacity(param_count);
    for _ in 0..param_count {
        parameters.push(read_u32_be(&mut cursor)?);
    }
    
    // Convert to event type
    let event_type = match event_code {
        0x4001 => EventType::ObjectAdded,
        0x4002 => EventType::ObjectRemoved,
        0x4003 => EventType::StoreAdded,
        0x4004 => EventType::StoreRemoved,
        0x4005 => EventType::DevicePropChanged,
        0x4006 => EventType::RequestObjectTransfer,
        _ => return Err(PtpIpError::ProtocolError(format!(
            "Unknown event type: 0x{:04X}", event_code
        ))),
    };
    
    Ok(PtpEvent {
        event_type,
        transaction_id: packet.transaction_id,
        parameters,
    })
}

// ------------------------------
// Helper Functions
// ------------------------------

/// Receive data block
fn receive_data_block(
    stream: &mut TcpStream,
    expected_transaction_id: u32,
    config: &SessionConfig
) -> Result<Vec<u8>> {
    let mut total_data = Vec::new();
    
    loop {
        let packet = recv_packet_filtered(
            stream,
            Some(PtpIpMessageType::DataBlock),
            config
        )?;
        
        if packet.transaction_id != expected_transaction_id {
            warn!(
                "Transaction ID mismatch: received={}, expected={}",
                packet.transaction_id, expected_transaction_id
            );
            continue;
        }
        
        // Empty packet indicates end
        if packet.payload.is_empty() {
            break;
        }
        
        total_data.extend_from_slice(&packet.payload);
        trace!(
            "Received data block: cumulative size={} bytes",
            total_data.len()
        );
    }
    
    info!("Data block reception complete, total size={} bytes", total_data.len());
    Ok(total_data)
}

/// Extract string
fn extract_string(data: &[u8], offset: usize, length: usize) -> Result<String> {
    if offset + length > data.len() {
        return Err(PtpIpError::ProtocolError(format!(
            "String extraction out of bounds: offset={}, length={}, data length={}",
            offset, length, data.len()
        )));
    }
    
    let slice = &data[offset..offset + length];
    let slice = slice.split(|&b| b == 0).next().unwrap_or(slice);
    
    String::from_utf8(slice.to_vec())
        .map_err(|e| PtpIpError::StringEncoding(e))
}

/// Read 8-bit unsigned integer
fn read_u8_be<R: io::Read>(reader: &mut R) -> Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

/// PTP command structure
#[derive(Debug)]
struct PtpCommand {
    opcode: u16,          // Operation code
    parameter_count: u16, // Number of parameters
    parameters: Vec<u32>, // Parameter list
}

impl PtpCommand {
    /// Create new command
    fn new(opcode: u16, parameters: &[u32]) -> Self {
        Self {
            opcode,
            parameter_count: parameters.len() as u16,
            parameters: parameters.to_vec(),
        }
    }
    
    /// Convert to byte stream
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // PTP command header (8 bytes)
        bytes.write_u16::<BigEndian>(0x0000)?; // Version
        bytes.write_u16::<BigEndian>(self.opcode)?; // Operation code
        bytes.write_u32::<BigEndian>(self.parameter_count as u32)?; // Parameter count
        
        // Write parameters
        for &param in &self.parameters {
            bytes.write_u32::<BigEndian>(param)?;
        }
        
        Ok(bytes)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read, Write};
    use std::time::Duration;
    use tempfile::tempdir;
    use crate::types::{PtpIpMessageType, PtpOperationCode, SessionConfig, EventType};
    use crate::error::PtpIpError;
    use crate::utils::chunk_vector;

    // 模拟TcpStream用于测试
    struct MockStream {
        read_buffer: Cursor<Vec<u8>>,
        write_buffer: Vec<u8>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    }

    impl MockStream {
        fn new(read_data: &[u8]) -> Self {
            Self {
                read_buffer: Cursor::new(read_data.to_vec()),
                write_buffer: Vec::new(),
                read_timeout: None,
                write_timeout: None,
            }
        }

        fn written_data(&self) -> &[u8] {
            &self.write_buffer
        }

        fn set_read_data(&mut self, data: &[u8]) {
            self.read_buffer = Cursor::new(data.to_vec());
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
    fn test_chunk_download_config_default() {
        let config = ChunkDownloadConfig::default();
        assert_eq!(config.chunk_size, 1024 * 1024);
        assert_eq!(config.progress_interval, 5.0);
        assert_eq!(config.min_chunk_size, 1024 * 64);
    }

    #[test]
    fn test_send_command() -> Result<()> {
        let mut mock_stream = MockStream::new(&[]);
        let config = SessionConfig::default();
        let transaction_id = 0x12345678;
        let opcode = PtpOperationCode::GetDeviceInfo as u16;
        let params = vec![0x01, 0x02, 0x03, 0x04]; // 4字节参数
        
        send_command(&mut mock_stream, opcode, transaction_id, &params, &config)?;
        
        // 预期的包结构: 头 + 命令数据
        // 命令数据: 版本(2字节) + 操作码(2字节) + 参数计数(4字节) + 参数(4字节)
        let expected = [
            0x00, 0x03, // 消息类型: CommandBlock
            0x00, 0x00, // 保留
            0x12, 0x34, 0x56, 0x78, // 事务ID
            0x00, 0x00, // 版本
            0x10, 0x01, // 操作码: GetDeviceInfo
            0x00, 0x00, 0x00, 0x01, // 参数计数
            0x01, 0x02, 0x03, 0x04  // 参数
        ];
        
        assert_eq!(mock_stream.written_data(), &expected);
        
        Ok(())
    }

    #[test]
    fn test_get_response() -> Result<()> {
        // 准备响应数据: 头8字节 + 长度4字节 + 主体8字节(version 2 + code Ok 2 + param 4)
        let response_data = [
            0x00, 0x05, // 消息类型: ResponseBlock
            0x00, 0x00, // 保留
            0x12, 0x34, 0x56, 0x78, // 事务ID
            0x00, 0x00, 0x00, 0x0C, // 长度 (4 + 8 主体)
            0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, // 主体: version, Ok, params
        ];
        
        let mut mock_stream = MockStream::new(&response_data);
        let config = SessionConfig::default();
        
        let response = get_response(&mut mock_stream, 0x12345678, &config)?;
        
        assert_eq!(response.message_type, PtpIpMessageType::ResponseBlock);
        assert_eq!(response.transaction_id, 0x12345678);
        assert_eq!(response.payload, &response_data[12..]); // 主体 = 无长度前缀
        Ok(())
    }

    #[test]
    fn test_get_response_wrong_tid_then_ok() -> Result<()> {
        // 第一个包: 错误 transaction_id 0x11111111
        let packet1: Vec<u8> = [
            0x00, 0x05, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11, // type + reserved + tid
            0x00, 0x00, 0x00, 0x08, // length 8
            0x00, 0x00, 0x00, 0x00, // payload 4 bytes (8-4)
        ].into();
        // 第二个包: 正确 transaction_id 0x12345678
        let packet2: Vec<u8> = [
            0x00, 0x05, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
            0x00, 0x00, 0x00, 0x0C,
            0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, // Ok response
        ].into();
        let mut read_data = packet1;
        read_data.extend_from_slice(&packet2);
        let mut mock_stream = MockStream::new(&read_data);
        let config = SessionConfig::default();
        let response = get_response(&mut mock_stream, 0x12345678, &config)?;
        assert_eq!(response.transaction_id, 0x12345678);
        assert_eq!(response.payload, &[0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00]);
        Ok(())
    }

    #[test]
    fn test_check_response_error() -> Result<()> {
        // 正常响应: 前2字节版本，接着2字节响应码(Ok=0x2001)
        let mut payload = vec![0x00, 0x00, 0x20, 0x01]; // version(2) + response_code Ok(2)
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 至少8字节
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::ResponseBlock,
            transaction_id: 0x12345678,
            payload: payload.clone()
        };
        
        assert!(check_response_error(&packet).is_ok());

        // 错误响应：版本(2) + 响应码 0x2002(2) + 至少4字节
        let err_payload = vec![0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x00];
        let err_packet = PtpIpPacket {
            message_type: PtpIpMessageType::ResponseBlock,
            transaction_id: 0x12345678,
            payload: err_payload,
        };
        let result = check_response_error(&err_packet);
        assert!(matches!(result, Err(PtpIpError::DeviceError { .. })));
        
        Ok(())
    }

    #[test]
    fn test_parse_storage_ids() -> Result<()> {
        let data = [
            0x00, 0x00, 0x00, 0x00, // 前4字节
            0x20, 0x01, 0x00, 0x00, // 响应码: Ok
            0x00, 0x00, 0x00, 0x02, // 计数
            0x00, 0x00, 0x00, 0x01, // 存储ID 1
            0x00, 0x00, 0x00, 0x02  // 存储ID 2
        ];
        
        let storage_ids = parse_storage_ids(&data)?;
        assert_eq!(storage_ids, vec![1, 2]);
        
        Ok(())
    }

    #[test]
    fn test_parse_object_handles() -> Result<()> {
        let data = [
            0x00, 0x00, 0x00, 0x00, // 前4字节
            0x20, 0x01, 0x00, 0x00, // 响应码: Ok
            0x00, 0x00, 0x00, 0x03, // 计数
            0x00, 0x00, 0x00, 0x0A, // 对象句柄1
            0x00, 0x00, 0x00, 0x0B, // 对象句柄2
            0x00, 0x00, 0x00, 0x0C  // 对象句柄3
        ];
        
        let handles = parse_object_handles(&data)?;
        assert_eq!(handles, vec![10, 11, 12]);
        
        Ok(())
    }

    #[test]
    fn test_parse_object_info() -> Result<()> {
        // parse_object_info: position 8 后为 storage_id(4)+object_format(2)+protection(1)+reserved(1)+object_size(8)+thumb_size(4)=20, 再 8*4=32 字节 offset/len，共 8+20+32=60 字节后为字符串
        let filename_offset = 60usize;
        let filename_len = 12usize; // "IMAGE001.jpg\0"
        let capture_date_offset = 72usize;
        let capture_date_len = 19usize;
        let modification_date_offset = 91usize;
        let modification_date_len = 19usize;
        let keywords_offset = 110usize;
        let keywords_len = 8usize;
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        data.push(0);
        data.push(0);
        data.extend_from_slice(&256u64.to_be_bytes());
        data.extend_from_slice(&64u32.to_be_bytes());
        data.extend_from_slice(&(filename_offset as u32).to_be_bytes());
        data.extend_from_slice(&(filename_len as u32).to_be_bytes());
        data.extend_from_slice(&(capture_date_offset as u32).to_be_bytes());
        data.extend_from_slice(&(capture_date_len as u32).to_be_bytes());
        data.extend_from_slice(&(modification_date_offset as u32).to_be_bytes());
        data.extend_from_slice(&(modification_date_len as u32).to_be_bytes());
        data.extend_from_slice(&(keywords_offset as u32).to_be_bytes());
        data.extend_from_slice(&(keywords_len as u32).to_be_bytes());
        assert_eq!(data.len(), 60);
        data.extend_from_slice(b"IMAGE001.jpg\0");
        data.extend_from_slice(b"2023-01-01 12:00:00");
        data.extend_from_slice(b"2023-01-01 12:30:00");
        data.extend_from_slice(b"vacation"); // 8 bytes, no null needed for extract_string

        let object_info = parse_object_info(&data, 0x12345678)?;

        assert_eq!(object_info.handle, 0x12345678);
        assert_eq!(object_info.storage_id, 1);
        assert_eq!(object_info.object_format, 2);
        assert_eq!(object_info.protection_status, 0);
        assert_eq!(object_info.object_size, 256);
        assert_eq!(object_info.thumb_size, 64);
        assert!(!object_info.filename.is_empty());
        assert!(!object_info.keywords.is_empty());

        Ok(())
    }

    #[test]
    fn test_parse_event_packet() -> Result<()> {
        // 构建事件包数据
        let data = [
            0x40, 0x01, // 事件类型: ObjectAdded
            0x00, 0x01, // 参数计数
            0x00, 0x00, 0x00, 0x0A, // 参数1: 对象句柄
        ];
        
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::EventBlock,
            transaction_id: 0x87654321,
            payload: data.to_vec()
        };
        
        let event = parse_event_packet(&packet)?;
        
        assert_eq!(event.event_type, EventType::ObjectAdded);
        assert_eq!(event.transaction_id, 0x87654321);
        assert_eq!(event.parameters, vec![10]);
        
        Ok(())
    }

    #[test]
    fn test_check_resume_state() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.jpg");
        
        // 测试新文件
        let (offset, _) = check_resume_state(&file_path, 1024)?;
        assert_eq!(offset, 0);
        
        // 创建临时文件和恢复文件
        let temp_path = get_temp_path(&file_path);
        let resume_path = get_resume_path(&file_path);
        
        fs::write(&temp_path, vec![0; 512])?;
        fs::write(&resume_path, "512")?;
        
        // 测试恢复状态
        let (offset, _) = check_resume_state(&file_path, 1024)?;
        assert_eq!(offset, 512);
        
        // 测试文件已完成
        fs::write(&temp_path, vec![0; 1024])?;
        fs::write(&resume_path, "1024")?;
        
        let (offset, _) = check_resume_state(&file_path, 1024)?;
        assert_eq!(offset, 1024);
        assert!(file_path.exists());
        assert!(!temp_path.exists());
        assert!(!resume_path.exists());
        
        Ok(())
    }

    #[test]
    fn test_chunk_vector() {
        let data = vec![1, 2, 3, 4, 5, 6, 7];
        let chunks = chunk_vector(&data, 3);
        assert_eq!(chunks, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7]]);
    }

    #[test]
    fn test_ptp_command_to_bytes() -> Result<()> {
        let command = PtpCommand::new(0x1001, &[0x00000001, 0x00000002]);
        let bytes = command.to_bytes()?;
        
        // 预期: 版本(2字节) + 操作码(2字节) + 参数计数(4字节) + 参数1(4字节) + 参数2(4字节)
        let expected = [
            0x00, 0x00, // 版本
            0x10, 0x01, // 操作码
            0x00, 0x00, 0x00, 0x02, // 参数计数
            0x00, 0x00, 0x00, 0x01, // 参数1
            0x00, 0x00, 0x00, 0x02  // 参数2
        ];
        
        assert_eq!(bytes, expected);
        
        Ok(())
    }

    #[test]
    fn test_send_command_empty_params() -> Result<()> {
        let mut mock_stream = MockStream::new(&[]);
        let config = SessionConfig::default();
        send_command(&mut mock_stream, PtpOperationCode::GetDeviceInfo as u16, 0x12345678, &[], &config)?;
        let written = mock_stream.written_data();
        assert!(written.len() >= 16);
        assert_eq!(&written[0..2], &[0x00, 0x03]); // CommandBlock
        assert_eq!(&written[12..16], &[0x00, 0x00, 0x00, 0x00]); // param count 0
        Ok(())
    }

    #[test]
    fn test_send_command_params_not_multiple_of_four() {
        let mut mock_stream = MockStream::new(&[]);
        let config = SessionConfig::default();
        // 3 bytes: read_u32_be will fail (need 4 bytes)
        let result = send_command(
            &mut mock_stream,
            PtpOperationCode::GetDeviceInfo as u16,
            0x12345678,
            &[0x01, 0x02, 0x03],
            &config,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_check_response_error_insufficient_payload() {
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::ResponseBlock,
            transaction_id: 0,
            payload: vec![0x00, 0x00, 0x00],
        };
        let result = check_response_error(&packet);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_check_response_error_device_errors() {
        // response_code is read at payload bytes 2-3 (after version 2 bytes)
        for (code, _desc) in [
            (0x2002u16, "General error"),
            (0x2003, "Session not open"),
            (0x2004, "Invalid transaction ID"),
            (0x2005, "Unsupported operation"),
            (0x2006, "Unsupported parameter"),
            (0x2007, "Incomplete transfer"),
            (0x2008, "Invalid storage ID"),
            (0x2009, "Invalid object handle"),
        ] {
            let mut payload = vec![0x00, 0x00]; // version
            payload.extend_from_slice(&code.to_be_bytes()); // response_code at 2-3
            payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // at least 8 bytes total
            let packet = PtpIpPacket {
                message_type: PtpIpMessageType::ResponseBlock,
                transaction_id: 0,
                payload,
            };
            let result = check_response_error(&packet);
            assert!(matches!(result, Err(PtpIpError::DeviceError { .. })));
        }
    }

    #[test]
    fn test_check_response_error_unknown_code() {
        // 前2字节版本，接着2字节响应码(0x2099)，总长至少8
        let mut payload = vec![0x00, 0x00, 0x20, 0x99];
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::ResponseBlock,
            transaction_id: 0,
            payload,
        };
        let result = check_response_error(&packet);
        if let Err(PtpIpError::DeviceError { code, .. }) = result {
            assert_eq!(code, 0x2099);
        } else {
            panic!("expected DeviceError with code 0x2099");
        }
    }

    #[test]
    fn test_parse_storage_ids_insufficient_data() {
        let data = [0u8; 8];
        let result = parse_storage_ids(&data);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_storage_ids_insufficient_after_count() {
        // 10 bytes pass initial check; count=1 at 8..12; only 1 byte left, read_u32_be fails
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&1u32.to_be_bytes()); // count = 1
        data.push(0);
        let result = parse_storage_ids(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_object_handles_insufficient_data() {
        let data = [0u8; 8];
        let result = parse_object_handles(&data);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_object_handles_insufficient_after_count() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&1u32.to_be_bytes()); // count = 1
        data.push(0);
        let result = parse_object_handles(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_object_info_insufficient_data() {
        let data = [0u8; 60];
        let result = parse_object_info(&data, 1);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_object_info_extract_string_out_of_bounds() {
        // 64 bytes fixed header; set filename_offset=1000 so extract_string fails
        let mut data = vec![0u8; 64];
        // at 8: storage_id(4)+object_format(2)+protection(1)+reserved(1)=8, position 16
        // object_size(8)+thumb_size(4)=12, position 28
        // 8 u32 offset/len start at 28: filename_offset at 28
        data[28..32].copy_from_slice(&1000u32.to_be_bytes()); // filename_offset = 1000
        data[32..36].copy_from_slice(&10u32.to_be_bytes());    // filename_len = 10
        let result = parse_object_info(&data, 1);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_event_packet_insufficient_data() {
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::EventBlock,
            transaction_id: 0,
            payload: vec![0x40, 0x01],
        };
        let result = parse_event_packet(&packet);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_event_packet_unknown_event_type() {
        let mut data = vec![0x40, 0xFF, 0x00, 0x00]; // unknown event 0x40FF
        data.extend_from_slice(&0u32.to_be_bytes());
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::EventBlock,
            transaction_id: 0,
            payload: data,
        };
        let result = parse_event_packet(&packet);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_event_packet_insufficient_params() {
        // event_code(2) + param_count=1(2) = 4 bytes, then need 4 bytes for param; only 2 bytes
        let data = [0x40, 0x01, 0x00, 0x01, 0x00, 0x00];
        let packet = PtpIpPacket {
            message_type: PtpIpMessageType::EventBlock,
            transaction_id: 0,
            payload: data.to_vec(),
        };
        let result = parse_event_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_event_packet_all_event_types() -> Result<()> {
        for (code, event_type) in [
            (0x4001u16, EventType::ObjectAdded),
            (0x4002, EventType::ObjectRemoved),
            (0x4003, EventType::StoreAdded),
            (0x4004, EventType::StoreRemoved),
            (0x4005, EventType::DevicePropChanged),
            (0x4006, EventType::RequestObjectTransfer),
        ] {
            let mut data = vec![];
            data.extend_from_slice(&code.to_be_bytes());
            data.extend_from_slice(&0u16.to_be_bytes()); // param count 0
            data.extend_from_slice(&[0u8; 2]); // 至少6字节payload
            let packet = PtpIpPacket {
                message_type: PtpIpMessageType::EventBlock,
                transaction_id: 1,
                payload: data,
            };
            let event = parse_event_packet(&packet)?;
            assert_eq!(event.event_type, event_type);
            assert_eq!(event.transaction_id, 1);
        }
        Ok(())
    }

    #[test]
    fn test_extract_string_out_of_bounds() {
        let data = b"hello";
        let result = extract_string(data, 0, 10);
        assert!(matches!(result, Err(PtpIpError::ProtocolError(_))));
    }

    #[test]
    fn test_extract_string_invalid_utf8() {
        let data = vec![0xFF, 0xFE, 0xFD];
        let result = extract_string(&data, 0, 3);
        assert!(matches!(result, Err(PtpIpError::StringEncoding(_))));
    }

    #[test]
    fn test_extract_string_success_with_null() -> Result<()> {
        let data = b"hello\0world";
        let s = extract_string(data, 0, 11)?;
        assert_eq!(s, "hello");
        Ok(())
    }

    #[test]
    fn test_read_u8_be() -> Result<()> {
        let data = [0xAB];
        let mut cursor = Cursor::new(&data);
        assert_eq!(read_u8_be(&mut cursor)?, 0xAB);
        Ok(())
    }

    #[test]
    fn test_read_u8_be_eof() {
        let mut cursor = Cursor::new(vec![]);
        let result = read_u8_be(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_temp_path() {
        let path = std::path::Path::new("/tmp/photo.jpg");
        let temp = get_temp_path(path);
        assert_eq!(temp.file_name().unwrap().to_str().unwrap(), ".photo.jpg.download");
    }

    #[test]
    fn test_get_temp_path_no_filename() {
        // Path ending with / may have file_name() = "tmp" on some systems
        let path = std::path::Path::new(".");
        let temp = get_temp_path(path);
        let name = temp.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
        assert_eq!(name, ".download.tmp");
    }

    #[test]
    fn test_get_resume_path() {
        let path = std::path::Path::new("/tmp/photo.jpg");
        let resume = get_resume_path(path);
        assert_eq!(resume.file_name().unwrap().to_str().unwrap(), ".photo.jpg.resume");
    }

    #[test]
    fn test_get_resume_path_no_filename() {
        let path = std::path::Path::new("/tmp/");
        let resume = get_resume_path(path);
        assert!(resume.to_string_lossy().ends_with(".resume"));
    }

    #[test]
    fn test_save_resume_state() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.jpg");
        save_resume_state(&file_path, 1024)?;
        let content = fs::read_to_string(get_resume_path(&file_path))?;
        assert_eq!(content, "1024");
        Ok(())
    }

    #[test]
    fn test_check_resume_state_invalid_resume_data() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.jpg");
        let temp_path = get_temp_path(&file_path);
        let resume_path = get_resume_path(&file_path);
        fs::write(&temp_path, vec![0; 100]).unwrap();
        fs::write(&resume_path, "not_a_number").unwrap();
        let result = check_resume_state(&file_path, 1024);
        assert!(matches!(result, Err(PtpIpError::InvalidResumeData)));
    }

    #[test]
    fn test_check_resume_state_temp_size_mismatch() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.jpg");
        let temp_path = get_temp_path(&file_path);
        let resume_path = get_resume_path(&file_path);
        fs::write(&temp_path, vec![0; 200])?; // temp has 200 bytes
        fs::write(&resume_path, "512")?;       // resume says 512
        let (offset, _) = check_resume_state(&file_path, 1024)?;
        assert_eq!(offset, 0);
        Ok(())
    }

    #[test]
    fn test_check_resume_state_target_exists_complete() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("complete.jpg");
        fs::write(&file_path, vec![0u8; 100])?;
        let (offset, _) = check_resume_state(&file_path, 100)?;
        assert_eq!(offset, 100);
        Ok(())
    }

    #[test]
    fn test_check_resume_state_temp_only() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.jpg");
        let temp_path = get_temp_path(&file_path);
        fs::write(&temp_path, vec![0; 100])?;
        // No resume file; only temp exists -> remove temp and start from 0
        let (offset, _) = check_resume_state(&file_path, 1024)?;
        assert_eq!(offset, 0);
        Ok(())
    }
}
