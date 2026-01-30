# ptpip_core / PTP/IP 核心库

[English](#english) | [中文](#中文)

---

<a name="english"></a>

## English

### Overview

**ptpip_core** is a Rust implementation of the PTP/IP (Picture Transfer Protocol over IP) protocol core. It provides device discovery, session management, and camera control (get device info, list storage/objects, download photos, remote capture, etc.). The crate can be built as a static library for use in iOS/macOS apps via C/Swift FFI.

PTP/IP is used by many cameras (e.g. Nikon, Sony) for tethered shooting and file transfer over the network.

### Features

- **Discovery**: UDP-based discovery of PTP/IP devices on the local network (broadcast/multicast).
- **Session**: TCP session lifecycle (connect, keep-alive, disconnect).
- **Commands**: High-level `CameraClient` API:
  - Get device info, storage IDs, storage info
  - Get object handles, object info
  - Download objects (with chunked transfer, resume, progress callback)
  - Delete objects, initiate capture
- **Transport**: Low-level PTP/IP packet send/receive, retry, and parsing (device info, storage info, object info, events).
- **FFI**: C-compatible API for discovery and session (e.g. `ptpip_discover_cameras`, `ptpip_create_session`) for use from Swift/Objective-C.

### Requirements

- Rust 1.70+ (edition 2024; if your toolchain is older, you may need to set `edition = "2021"` in `Cargo.toml`).
- For iOS/macOS: build as staticlib and link from Xcode; use `cbindgen` to generate C headers if needed.

### Build

```bash
# Library and tests
cargo build
cargo test --lib
```

Static library (for linking into an app):

```bash
cargo build --release
# Output: target/release/libptpip_core.a
```

### Usage (Rust)

```rust
use ptpip_core::discovery::{discover_cameras, DiscoveryConfig};
use ptpip_core::commands::CameraClient;
use ptpip_core::types::SessionConfig;
use std::time::Duration;

// Discover cameras
let config = DiscoveryConfig {
    timeout: Duration::from_secs(5),
    retry_count: 3,
    ..Default::default()
};
let cameras = discover_cameras(config)?;

// Connect and use
if let Some(camera) = cameras.first() {
    let session_config = SessionConfig::default();
    let mut client = CameraClient::connect(
        &camera.ip_address.to_string(),
        camera.port,
        session_config,
    )?;
    let device_info = client.get_device_info()?;
    // ... get_storage_ids, get_object_handles, download_photo, etc.
    client.close()?;
}
```

### Project structure

```
src/
  lib.rs       # Crate root and re-exports
  discovery.rs # UDP discovery, FFI for discover
  session.rs   # Session lifecycle, FFI for session
  commands.rs  # CameraClient, PTP commands, chunked download
  transport.rs# TCP transport, packet I/O, parse device/storage/object
  types.rs     # Configs, message types, structs (DiscoveredCamera, etc.)
  error.rs     # PtpIpError and Result
  utils.rs     # Byte order, checksum, C string helpers
tests/
  integration.rs # Integration tests (optional, require camera)
```

### License

See repository license (e.g. MIT/Apache-2.0). If none is specified, assume the project’s default.

---

<a name="中文"></a>

## 中文

### 概述

**ptpip_core** 是 PTP/IP（基于 IP 的图片传输协议）协议的 Rust 核心实现。提供设备发现、会话管理以及相机控制（获取设备信息、存储/对象列表、下载照片、远程拍摄等）。本库可编译为静态库，供 iOS/macOS 通过 C/Swift FFI 调用。

PTP/IP 被多款相机（如尼康、索尼）用于有线/网络连接拍摄与文件传输。

### 功能

- **发现**：基于 UDP 的局域网 PTP/IP 设备发现（广播/组播）。
- **会话**：TCP 会话生命周期（连接、保活、断开）。
- **命令**：高层 `CameraClient` API：
  - 获取设备信息、存储 ID、存储信息
  - 获取对象句柄、对象信息
  - 下载对象（分块、断点续传、进度回调）
  - 删除对象、发起拍摄
- **传输**：底层 PTP/IP 报文收发、重试与解析（设备信息、存储信息、对象信息、事件）。
- **FFI**：C 兼容接口（如 `ptpip_discover_cameras`、`ptpip_create_session`），供 Swift/Objective-C 调用。

### 环境要求

- Rust 1.70+（edition 2024；若工具链较旧，可在 `Cargo.toml` 中改为 `edition = "2021"`）。
- iOS/macOS：以 staticlib 形式编译并在 Xcode 中链接；如需 C 头文件可使用 `cbindgen` 生成。

### 构建

```bash
# 库与单元测试
cargo build
cargo test --lib
```

静态库（供应用链接）：

```bash
cargo build --release
# 产物：target/release/libptpip_core.a
```

### 使用示例（Rust）

```rust
use ptpip_core::discovery::{discover_cameras, DiscoveryConfig};
use ptpip_core::commands::CameraClient;
use ptpip_core::types::SessionConfig;
use std::time::Duration;

// 发现设备
let config = DiscoveryConfig {
    timeout: Duration::from_secs(5),
    retry_count: 3,
    ..Default::default()
};
let cameras = discover_cameras(config)?;

// 连接并使用
if let Some(camera) = cameras.first() {
    let session_config = SessionConfig::default();
    let mut client = CameraClient::connect(
        &camera.ip_address.to_string(),
        camera.port,
        session_config,
    )?;
    let device_info = client.get_device_info()?;
    // ... get_storage_ids, get_object_handles, download_photo 等
    client.close()?;
}
```

### 目录结构

```
src/
  lib.rs       # 库入口与导出
  discovery.rs # UDP 发现、发现相关 FFI
  session.rs   # 会话生命周期、会话相关 FFI
  commands.rs  # CameraClient、PTP 命令、分块下载
  transport.rs # TCP 传输、报文收发与解析
  types.rs     # 配置与类型定义（DiscoveredCamera 等）
  error.rs     # PtpIpError 与 Result
  utils.rs     # 字节序、校验和、C 字符串等工具
tests/
  integration.rs # 集成测试（可选，需真实相机）
```

### 许可证

以仓库中声明的许可证为准（如 MIT/Apache-2.0）；未声明时请按项目默认约定理解。
