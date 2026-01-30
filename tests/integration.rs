use std::time::Duration;
use std::path::PathBuf;
use std::env;
// 解决方案1: 使用完整的crate路径（推荐）
use ptpip_core::commands::{CameraClient, ChunkDownloadConfig, DownloadProgressCallback};
use ptpip_core::error::Result;
use ptpip_core::types::SessionConfig;
use ptpip_core::discovery::{discover_cameras, DiscoveryConfig};
use ptpip_core::utils::get_timestamp;


// 测试标记：默认忽略实际设备测试（需要物理相机）
// 运行时使用 `cargo test -- --ignored` 执行设备测试

/// 测试设备发现功能
#[test]
#[ignore = "需要实际相机设备"]
fn test_device_discovery() -> Result<()> {
    println!("[{}] 开始设备发现测试", get_timestamp());
    
    let config = DiscoveryConfig {
        timeout: Duration::from_secs(10),
        retry_count: 2,
        ..Default::default()
    };
    
    let cameras = discover_cameras(config)?;
    
    assert!(!cameras.is_empty(), "未发现任何 PTP/IP 设备");
    println!("[{}] 发现 {} 台设备", get_timestamp(), cameras.len());
    
    for (i, camera) in cameras.iter().enumerate() {
        println!(
            "[{}] 设备 {}: {} ({}) 端口: {}",
            get_timestamp(),
            i + 1,
            camera.model_name,
            camera.ip_address,
            camera.port
        );
    }
    
    Ok(())
}

/// 完整功能测试套件（需要至少发现一台相机）
#[test]
#[ignore = "需要实际相机设备"]
fn test_full_workflow() -> Result<()> {
    println!("[{}] 开始完整工作流程测试", get_timestamp());
    
    // 1. 发现设备
    let discovery_config = DiscoveryConfig {
        timeout: Duration::from_secs(10),
        retry_count: 2,
        ..Default::default()
    };
    
    let cameras = discover_cameras(discovery_config)?;
    assert!(!cameras.is_empty(), "未发现任何设备，无法进行后续测试");
    let target_camera = &cameras[0];
    println!(
        "[{}] 选择测试设备: {} ({})",
        get_timestamp(),
        target_camera.model_name,
        target_camera.ip_address
    );
    
    // 2. 连接设备
    let session_config = SessionConfig {
        timeout: 60,
        max_retries: 3,
        ..Default::default()
    };
    
    let mut client = CameraClient::connect(
        &target_camera.ip_address.to_string(),
        target_camera.port,
        session_config.clone()
    )?;
    println!("[{}] 成功连接到设备", get_timestamp());
    
    // 3. 获取设备信息
    let device_info = client.get_device_info()?;
    println!(
        "[{}] 设备信息: 制造商={}, 型号={}, 版本={}",
        get_timestamp(),
        device_info.manufacturer,
        device_info.model,
        device_info.device_version
    );
    
    // 4. 获取存储列表
    let storage_ids = client.get_storage_ids()?;
    assert!(!storage_ids.is_empty(), "设备没有可用存储");
    println!(
        "[{}] 发现 {} 个存储设备",
        get_timestamp(),
        storage_ids.len()
    );
    
    let target_storage_id = storage_ids[0];
    
    // 5. 获取存储信息
    let storage_info = client.get_storage_info(target_storage_id)?;
    println!(
        "[{}] 存储信息: {} (容量: {} MB, 可用: {} MB)",
        get_timestamp(),
        storage_info.storage_description,
        storage_info.max_capacity / 1024 / 1024,
        storage_info.free_space_in_bytes / 1024 / 1024
    );
    
    // 6. 获取对象列表（照片）
    let object_handles = client.get_object_handles(target_storage_id, 0x0000, 10)?; // 0x0000 表示所有格式
    println!(
        "[{}] 发现 {} 个对象（照片）",
        get_timestamp(),
        object_handles.len()
    );
    
    // 如果有照片，获取第一张照片的信息
    if !object_handles.is_empty() {
        let first_object_handle = object_handles[0];
        let object_info = client.get_object_info(first_object_handle)?;
        println!(
            "[{}] 照片信息: 文件名={}, 大小={} KB, 拍摄日期={}",
            get_timestamp(),
            object_info.filename,
            object_info.object_size / 1024,
            object_info.capture_date
        );
        
        // 7. 测试下载（如果环境变量指定了下载目录）
        if let Ok(download_dir) = env::var("PTPIP_DOWNLOAD_DIR") {
            let download_path = PathBuf::from(download_dir).join(&object_info.filename);
            println!(
                "[{}] 测试下载照片到: {:?}",
                get_timestamp(),
                download_path
            );
            
            // 进度回调
            let progress_callback: DownloadProgressCallback = Box::new(|current, total, complete, stats| {
                if complete {
                    println!(
                        "[{}] 下载完成: 总大小={} bytes, 耗时={}ms, 重试次数={}",
                        get_timestamp(),
                        total,
                        stats.duration_ms,
                        stats.retries
                    );
                } else {
                    let percent = (current as f32 / total as f32) * 100.0;
                    println!(
                        "[{}] 下载进度: {}/{} bytes ({:.1}%)",
                        get_timestamp(),
                        current,
                        total,
                        percent
                    );
                }
            });
            
            // 下载配置
            let download_config = ChunkDownloadConfig {
                chunk_size: 2 * 1024 * 1024, // 2MB 块
                progress_interval: 10.0,     // 每10%触发一次回调
                ..Default::default()
            };
            
            // 执行下载
            let download_stats = client.download_photo(
                first_object_handle,
                &download_path,
                download_config,
                progress_callback
            )?;
            
            assert_eq!(
                download_stats.downloaded_bytes,
                object_info.object_size,
                "下载的文件大小与预期不符"
            );
        } else {
            println!("[{}] 未设置 PTPIP_DOWNLOAD_DIR 环境变量，跳过下载测试", get_timestamp());
        }
    } else {
        println!("[{}] 设备上没有照片，跳过照片信息和下载测试", get_timestamp());
    }
    
    // 8. 测试远程拍摄（如果有足够空间）
    if storage_info.free_space_in_bytes > 100 * 1024 * 1024 { // 至少100MB可用空间
        println!("[{}] 测试远程拍摄功能", get_timestamp());
        
        let new_photo_handle = client.initiate_capture(target_storage_id, 0x0000)?; // 0x0000 表示默认格式
        assert_ne!(new_photo_handle, 0, "远程拍摄失败，返回无效句柄");
        println!(
            "[{}] 远程拍摄成功，新照片句柄: {}",
            get_timestamp(),
            new_photo_handle
        );
        
        // 验证新照片存在
        let new_object_info = client.get_object_info(new_photo_handle)?;
        println!(
            "[{}] 新拍摄照片信息: 文件名={}, 大小={} KB",
            get_timestamp(),
            new_object_info.filename,
            new_object_info.object_size / 1024
        );
    } else {
        println!("[{}] 存储空间不足，跳过远程拍摄测试", get_timestamp());
    }
    
    // 9. 关闭连接
    client.close()?;
    println!("[{}] 成功关闭连接，所有测试完成", get_timestamp());
    
    Ok(())
}

/// 测试错误处理流程
#[test]
#[ignore = "需要实际相机设备"]
fn test_error_handling() -> Result<()> {
    println!("[{}] 开始错误处理测试", get_timestamp());
    
    // 测试连接不存在的设备
    let invalid_ip = "192.168.1.254"; // 假设这个IP没有设备
    let session_config = SessionConfig {
        timeout: 5,
        max_retries: 1,
        ..Default::default()
    };
    
    let result = CameraClient::connect(invalid_ip, 15740, session_config);
    assert!(result.is_err(), "连接无效IP应该失败");
    println!(
        "[{}] 无效IP连接测试通过: {:?}",
        get_timestamp(),
        result.err().unwrap()
    );
    
    // 测试其他错误场景
    let discovery_config = DiscoveryConfig {
        timeout: Duration::from_secs(2),
        retry_count: 1,
        ..Default::default()
    };
    
    // 先尝试发现设备
    let cameras = discover_cameras(discovery_config)?;
    if !cameras.is_empty() {
        let target_camera = &cameras[0];
        let mut client = CameraClient::connect(
            &target_camera.ip_address.to_string(),
            target_camera.port,
            SessionConfig::default()
        )?;
        
        // 测试获取不存在的对象
        let invalid_handle = 0xFFFFFFFE;
        let result = client.get_object_info(invalid_handle);
        assert!(result.is_err(), "获取无效对象应该失败");
        println!(
            "[{}] 无效对象句柄测试通过: {:?}",
            get_timestamp(),
            result.err().unwrap()
        );
        
        client.close()?;
    }
    
    println!("[{}] 错误处理测试完成", get_timestamp());
    Ok(())
}
