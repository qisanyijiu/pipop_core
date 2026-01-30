// src/lib.rs
pub mod discovery;
pub mod session;
pub mod commands;
pub mod types;
pub mod error;
pub mod transport;
mod utils;  // 私有模块，仅内部使用

// 导出常用类型和错误
pub use error::PtpIpError;
pub use crate::error::Result;