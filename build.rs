use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // 生成协议常量定义文件
    generate_protocol_constants();
    
    // 告诉 Cargo 重新运行构建脚本的条件
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PTPIP_DEBUG");
}

/// 生成 PTP/IP 协议相关的常量定义
fn generate_protocol_constants() {
    // 获取输出目录
    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR 环境变量未设置");
    let dest_path = Path::new(&out_dir).join("protocol_constants.rs");
    
    // 生成协议常量代码
    let constants = r#"
        // 自动生成的 PTP/IP 协议常量
        // 由 build.rs 生成，不要手动修改
        
        /// PTP/IP 协议版本
        pub const PTPIP_VERSION: u16 = 0x0100;
        
        /// 标准 PTP 操作码范围
        pub const PTP_OPCODE_MIN: u16 = 0x1000;
        pub const PTP_OPCODE_MAX: u16 = 0x1FFF;
        
        /// PTP 响应码范围
        pub const PTP_RESPONSE_MIN: u16 = 0x2000;
        pub const PTP_RESPONSE_MAX: u16 = 0x2FFF;
        
        /// PTP 事件码范围
        pub const PTP_EVENT_MIN: u16 = 0x4000;
        pub const PTP_EVENT_MAX: u16 = 0x4FFF;
    "#;
    
    // 写入生成的代码到文件
    fs::write(&dest_path, constants).expect("无法写入协议常量文件");
    
    // 告诉 Cargo 这个文件是由构建脚本生成的
    println!("cargo:rustc-env=PROTOCOL_CONSTANTS_FILE={}", dest_path.display());
}
    