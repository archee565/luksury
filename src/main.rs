use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockDevice {
    name: String,
//    maj_min: String,
    rm: bool,
    size: String,
    ro: bool,
    #[serde(rename = "type")]
    device_type: String,
    mountpoint: Option<String>,
    children: Option<Vec<BlockDevice>>,
}

/// Finds the root device name by examining the parent of the root partition
pub fn find_root_device() -> Result<String, Box<dyn std::error::Error>> {
    // Execute lsblk command with JSON output
    let output = Command::new("lsblk")
        .arg("-J")
        .arg("-o")
        .arg("NAME,MAJ:MIN,RM,SIZE,RO,TYPE,MOUNTPOINT")
        .output()?;

    if !output.status.success() {
        return Err("Failed to execute lsblk command".into());
    }

    // Parse JSON output
    let lsblk_output = serde_json::from_slice::<LsblkOutput>(&output.stdout)?;

    if let Some(res) = find_parent_device(&lsblk_output.blockdevices, "")
    {
        println!("disk: {}   part: {:?}",res,extract_partition_number(res.as_str()));
    }

    // Find the root partition and its parent
    if let Some((root_partition, parent_device)) = find_root_partition_and_parent(&lsblk_output.blockdevices) {
        println!("Root partition: {}", root_partition);
        println!("Parent device: {}", parent_device);
        Ok(parent_device)
    } else {
        Err("Could not find root partition or its parent".into())
    }
}


/// Extracts partition number from device name
fn extract_partition_number(device_name: &str) -> Option<u32> {
    // Common patterns for partition naming:
    // - sda1, sdb2 -> partition 1, 2
    // - nvme0n1p3, nvme1n2p1 -> partition 3, 1
    // - vda1, vdb2 -> partition 1, 2
    // - mmcblk0p1, mmcblk1p2 -> partition 1, 2
    // - loop0p1, loop1p2 -> partition 1, 2
    
    let patterns = [
        // NVMe pattern: nvme0n1p3 -> 3
        (r"^nvme\d+n\d+p(\d+)$", 1),
        // MMC pattern: mmcblk0p1 -> 1
        (r"^mmcblk\d+p(\d+)$", 1),
        // Loop pattern: loop0p1 -> 1
        (r"^loop\d+p(\d+)$", 1),
        // Standard pattern: sda1, vda2, xvda1 -> 1, 2, 1
        (r"^[a-z]+(\d+)$", 1),
    ];
    
    for (pattern, capture_group) in patterns.iter() {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(device_name) {
                if let Some(matched) = caps.get(*capture_group) {
                    if let Ok(num) = matched.as_str().parse::<u32>() {
                        return Some(num);
                    }
                }
            }
        }
    }
    
    None
}

fn find_parent_device(devices : &[BlockDevice], parent : &str) -> Option<String>
{
    for device in devices
    {
        if let Some(mp) = &device.mountpoint 
        {
            if mp == "/"
            {
                return Some(parent.to_string());
            }
        }
        if let Some(children) = &device.children
        {
            if let Some(goodparent) = find_parent_device(children,&device.name)
            {
                if goodparent!="" { return Some(goodparent); }
            }
        }
    }
    None
}

/// Recursively searches for the root partition and returns (partition_name, parent_device_name)
fn find_root_partition_and_parent(devices: &[BlockDevice]) -> Option<(String, String)> {
    for device in devices {
        // Check if this device is mounted as root
        if let Some(mountpoint) = &device.mountpoint {
            if mountpoint == "/" {
                // This is the root partition, now find its parent
                return Some((device.name.clone(), device.name.clone()));
            }
        }

        // Recursively check children
        if let Some(children) = &device.children {
            if let Some((root_partition, _)) = find_root_partition_and_parent(children) {
                // Found root partition in children, this device is the parent
                return Some((root_partition, device.name.clone()));
            }
        }
    }
    None
}

#[derive(Debug)]
pub struct RootDeviceInfo {
    pub root_partition: String,
    pub parent_device: String,
    pub device_type: String,
    pub is_removable: bool,
    pub is_read_only: bool,
    pub size: String,
}

/// Finds detailed information about the root device and its parent
fn find_root_device_info(devices: &[BlockDevice]) -> Option<RootDeviceInfo> {
    for device in devices {
        // Check if this device is mounted as root
        if let Some(mountpoint) = &device.mountpoint {
            if mountpoint == "/" {
                return Some(RootDeviceInfo {
                    root_partition: device.name.clone(),
                    parent_device: device.name.clone(), // For root devices without parent
                    device_type: device.device_type.clone(),
                    is_removable: device.rm,
                    is_read_only: device.ro,
                    size: device.size.clone(),
                });
            }
        }

        // Check children for root mountpoint
        if let Some(children) = &device.children {
            for child in children {
                if let Some(mountpoint) = &child.mountpoint {
                    if mountpoint == "/" {
                        return Some(RootDeviceInfo {
                            root_partition: child.name.clone(),
                            parent_device: device.name.clone(),
                            device_type: device.device_type.clone(),
                            is_removable: device.rm,
                            is_read_only: device.ro,
                            size: device.size.clone(),
                        });
                    }
                }
            }
        }
    }
    None
}

// Example usage
fn main() -> Result<(), Box<dyn std::error::Error>> {
    match find_root_device() {
        Ok(device) => println!("Root device: {}", device),
        Err(e) => eprintln!("Error: {}", e),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_root_device() {
        // This test will only work on systems where lsblk is available
        // and we're running in an environment with root mounted
        if std::process::Command::new("lsblk")
            .arg("--version")
            .output()
            .is_ok()
        {
            let result = find_root_device();
            assert!(result.is_ok(), "Should be able to find root device");
            
            let device = result.unwrap();
            assert!(!device.is_empty(), "Root device name should not be empty");
            
            println!("Found root device: {}", device);
        } else {
            println!("lsblk not available, skipping test");
        }
    }
}