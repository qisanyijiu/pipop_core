use std::io::{self, Read};
use std::os::raw::c_char;
use std::ffi::{CString, CStr};
use std::time::{SystemTime, UNIX_EPOCH};

/// 读取16位无符号整数（大端序）
pub fn read_u16_be<R: Read>(reader: &mut R) -> Result<u16, io::Error> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(((buf[0] as u16) << 8) | (buf[1] as u16))
}

/// 读取32位无符号整数（大端序）
pub fn read_u32_be<R: Read>(reader: &mut R) -> Result<u32, io::Error> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(((buf[0] as u32) << 24) |
       ((buf[1] as u32) << 16) |
       ((buf[2] as u32) << 8) |
       (buf[3] as u32))
}

/// 读取64位无符号整数（大端序）
pub fn read_u64_be<R: Read>(reader: &mut R) -> Result<u64, io::Error> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(((buf[0] as u64) << 56) |
       ((buf[1] as u64) << 48) |
       ((buf[2] as u64) << 40) |
       ((buf[3] as u64) << 32) |
       ((buf[4] as u64) << 24) |
       ((buf[5] as u64) << 16) |
       ((buf[6] as u64) << 8) |
       (buf[7] as u64))
}

/// 将16位无符号整数转换为大端序字节数组
pub fn write_u16_be(value: u16) -> [u8; 2] {
    [(value >> 8) as u8, value as u8]
}

/// 将32位无符号整数转换为大端序字节数组
pub fn write_u32_be(value: u32) -> [u8; 4] {
    [
        (value >> 24) as u8,
        (value >> 16) as u8,
        (value >> 8) as u8,
        value as u8,
    ]
}

/// 将64位无符号整数转换为大端序字节数组
pub fn write_u64_be(value: u64) -> [u8; 8] {
    [
        (value >> 56) as u8,
        (value >> 48) as u8,
        (value >> 40) as u8,
        (value >> 32) as u8,
        (value >> 24) as u8,
        (value >> 16) as u8,
        (value >> 8) as u8,
        value as u8,
    ]
}

/// 调试日志宏（带模块名和时间戳）
#[macro_export]
macro_rules! debug_log {
    ($module:expr, $($arg:tt)*) => {
        let timestamp = $crate::utils::get_timestamp();
        log::debug!("[{}][{}] {}", timestamp, $module, format_args!($($arg)*));
    };
}

/// 信息日志宏（带模块名和时间戳）
#[macro_export]
macro_rules! info_log {
    ($module:expr, $($arg:tt)*) => {
        let timestamp = $crate::utils::get_timestamp();
        log::info!("[{}][{}] {}", timestamp, $module, format_args!($($arg)*));
    };
}

/// 警告日志宏（带模块名和时间戳）
#[macro_export]
macro_rules! warn_log {
    ($module:expr, $($arg:tt)*) => {
        let timestamp = $crate::utils::get_timestamp();
        log::warn!("[{}][{}] {}", timestamp, $module, format_args!($($arg)*));
    };
}

/// 错误日志宏（带模块名和时间戳）
#[macro_export]
macro_rules! error_log {
    ($module:expr, $($arg:tt)*) => {
        let timestamp = $crate::utils::get_timestamp();
        log::error!("[{}][{}] {}", timestamp, $module, format_args!($($arg)*));
    };
}

/// 获取当前时间戳（毫秒）
pub fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 计算数据的简单校验和
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for &byte in data {
        sum = (sum + byte as u32) % 0x10000;
    }
    sum as u16
}

/// 将字节数组格式化为十六进制字符串（带分隔符）
pub fn bytes_to_hex(data: &[u8]) -> String {
    if data.len() > 128 {
        // 对于长字节数组，显示开头和结尾
        let prefix = &data[0..32];
        let suffix = &data[data.len()-32..];
        format!(
            "{} ... [{} bytes omitted] ... {}",
            prefix.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
            data.len() - 64,
            suffix.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
        )
    } else {
        data.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// 安全地将C字符串转换为Rust字符串
pub unsafe fn c_str_to_rust(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() {
        return None;
    }
    unsafe {
        CStr::from_ptr(c_str)
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }
}

/// 将Rust字符串转换为C字符串（需要手动释放）
pub fn rust_str_to_c(rust_str: &str) -> *mut c_char {
    CString::new(rust_str)
        .map(|c_str| c_str.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// 计算两个时间戳之间的持续时间（毫秒）
pub fn duration_ms(start: u64, end: u64) -> u64 {
    if end > start {
        end - start
    } else {
        0
    }
}

/// 将大向量分割为指定大小的块
pub fn chunk_vector<T: Clone>(data: &[T], chunk_size: usize) -> Vec<Vec<T>> {
    data.chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    // 导入所有父模块的函数和类型
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    #[test]
    fn test_read_u16_be() -> io::Result<()> {
        let data = [0x12, 0x34];
        let mut cursor = Cursor::new(&data);
        assert_eq!(read_u16_be(&mut cursor)?, 0x1234);
        Ok(())
    }

    #[test]
    fn test_read_u32_be() -> io::Result<()> {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut cursor = Cursor::new(&data);
        assert_eq!(read_u32_be(&mut cursor)?, 0x12345678);
        Ok(())
    }

    #[test]
    fn test_read_u64_be() -> io::Result<()> {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut cursor = Cursor::new(&data);
        assert_eq!(read_u64_be(&mut cursor)?, 0x123456789ABCDEF0);
        Ok(())
    }

    #[test]
    fn test_write_u16_be() {
        assert_eq!(write_u16_be(0x1234), [0x12, 0x34]);
    }

    #[test]
    fn test_write_u32_be() {
        assert_eq!(write_u32_be(0x12345678), [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_write_u64_be() {
        assert_eq!(
            write_u64_be(0x123456789ABCDEF0),
            [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
        );
    }

    #[test]
    fn test_get_timestamp() {
        let ts1 = get_timestamp();
        std::thread::sleep(Duration::from_millis(10));
        let ts2 = get_timestamp();
        assert!(ts2 > ts1);
    }

    #[test]
    fn test_checksum() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(checksum(&data), 0x000A); // 1+2+3+4=10
        
        let data = [0xFF, 0xFF];
        assert_eq!(checksum(&data), 0x01FE); // 255+255=510
    }

    #[test]
    fn test_bytes_to_hex() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(bytes_to_hex(&data), "01 02 03 04 05");
        
        // 测试长字节数组
        let mut long_data = vec![0u8; 200];
        for i in 0..200 {
            long_data[i] = i as u8;
        }
        let hex = bytes_to_hex(&long_data);
        assert!(hex.contains("... [136 bytes omitted] ..."));
    }

    #[test]
    fn test_c_str_conversions() {
        // 测试Rust到C字符串转换
        let rust_str = "test string";
        let c_str = rust_str_to_c(rust_str);
        assert!(!c_str.is_null());
        
        // 测试C到Rust字符串转换
        let converted_rust_str = unsafe { c_str_to_rust(c_str) }.unwrap();
        assert_eq!(converted_rust_str, rust_str);
        
        // 释放C字符串
        unsafe {
            let _ = CString::from_raw(c_str);
        }
        
        // 测试空指针
        let null_str: *const c_char = std::ptr::null();
        assert!(unsafe { c_str_to_rust(null_str) }.is_none());
    }

    #[test]
    fn test_duration_ms() {
        assert_eq!(duration_ms(100, 200), 100);
        assert_eq!(duration_ms(200, 100), 0);
        assert_eq!(duration_ms(500, 500), 0);
    }

    #[test]
    fn test_chunk_vector() {
        let data = vec![1, 2, 3, 4, 5, 6, 7];
        let chunks = chunk_vector(&data, 3);
        assert_eq!(chunks, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7]]);
        
        // 测试空向量
        let data: Vec<i32> = vec![];
        let chunks = chunk_vector(&data, 3);
        assert!(chunks.is_empty());
        
        // 测试 chunk_size 大于数据长度
        let data = vec![1, 2, 3];
        let chunks = chunk_vector(&data, 5);
        assert_eq!(chunks, vec![vec![1, 2, 3]]);
    }

    #[test]
    fn test_read_u16_be_eof() {
        let data = [0x12]; // only 1 byte
        let mut cursor = Cursor::new(&data);
        let result = read_u16_be(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u32_be_eof() {
        let data = [0x12, 0x34]; // only 2 bytes
        let mut cursor = Cursor::new(&data);
        let result = read_u32_be(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u64_be_eof() {
        let data = [0x12, 0x34, 0x56]; // only 3 bytes
        let mut cursor = Cursor::new(&data);
        let result = read_u64_be(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_rust_str_to_c_empty() {
        let c_str = rust_str_to_c("");
        assert!(!c_str.is_null());
        let s = unsafe { c_str_to_rust(c_str) }.unwrap();
        assert_eq!(s, "");
        unsafe { let _ = CString::from_raw(c_str); }
    }

    #[test]
    fn test_rust_str_to_c_with_null_returns_null() {
        // CString::new fails for strings containing null byte, returns null_mut
        let c_str = rust_str_to_c("hello\x00world");
        assert!(c_str.is_null());
    }
}
