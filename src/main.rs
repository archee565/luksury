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
pub fn find_root_device() -> Result<(String,u32),Box<dyn std::error::Error>> {
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

    if let Some(encrtypted_device) = find_parent_device(&lsblk_output.blockdevices, "")
    {
        if let Some(part) = extract_partition_number(encrtypted_device.as_str())
        {
            return Ok((encrtypted_device,part));
        }
    }
    Err("Can't find root device".into())
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

#[derive(Debug)]
pub struct RootDeviceInfo {
    pub root_partition: String,
    pub parent_device: String,
    pub device_type: String,
    pub is_removable: bool,
    pub is_read_only: bool,
    pub size: String,
}

// Example usage
fn main() -> Result<(), Box<dyn std::error::Error>> {
    match find_root_device() {
        Ok((device,part)) => println!("Root device: {} part: {}", device,part),
        Err(e) => eprintln!("Error: {}", e),
    }

    Ok(())
}
