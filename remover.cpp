#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cassert>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <memory>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <unistd.h>
#include <json/json.h>  // Requires jsoncpp library
namespace fs = std::filesystem;

#include <openssl/sha.h>  
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>

//#include "luksury.h"

extern std::string root_device_name;
extern std::string root_device_uuid;
extern std::string root_partition_name;
extern const char *root_key_file;
extern const char *dracut_path ;
extern const char *data_dir;

std::uintmax_t getFileSize(const std::string& filepath);
std::string exec(const std::string&command);
bool getTPMHandleAddress(bool only_from_file);
std::vector<TPM2_HANDLE> get_tpm_persistent_handles();
bool evict_persistent( TPM2_HANDLE persistent_handle);
bool find_root_partition_data();

struct PERSISTENT_HANDLE {
    char text[16];
    TPM2_HANDLE handle;
} ;

extern PERSISTENT_HANDLE persistent_handle;





bool restoreCrypttab() {
    std::string deviceName = root_partition_name;
    const std::string& crypttabPath = "/etc/crypttab";
    std::ifstream inFile(crypttabPath);
    if (!inFile.is_open()) {
        std::cerr << "Error: Cannot open " << crypttabPath << std::endl;
        return false;
    }

    std::vector<std::string> lines;
    std::string line;
    bool deviceFound = false;

    // Read and process each line
    while (std::getline(inFile, line)) {
        // Skip empty lines and comments
        std::string trimmed = line;
        trimmed.erase(0, trimmed.find_first_not_of(" \t"));
        
        if (trimmed.empty() || trimmed[0] == '#') {
            lines.push_back(line);
            continue;
        }

        // Parse the line into columns
        std::istringstream iss(line);
        std::string name, source, keyfile, options;
        iss >> name >> source >> keyfile >> options;

        // Check if this is the target device with /root.key
        if (name == deviceName && keyfile == "/root.key") {
            deviceFound = true;
            
            // Reconstruct the line with "none" as keyfile (password prompt)
            std::ostringstream oss;
            oss << name << " " << source << " none";
            
            // Preserve options if they exist
            if (!options.empty()) {
                oss << " " << options;
            }
            
            lines.push_back(oss.str());
            std::cout << "Restored entry for device: " << deviceName << " (will prompt for password)" << std::endl;
        } else {
            lines.push_back(line);
        }
    }
    inFile.close();

    if (!deviceFound) {
        std::cout << "Note: Device '" << deviceName << "' does not use /root.key in " << crypttabPath << std::endl;
        return true; // Not an error, just nothing to restore
    }

    // Write back to the file
    std::ofstream outFile(crypttabPath);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot write to " << crypttabPath << std::endl;
        return false;
    }

    for (const auto& l : lines) {
        outFile << l << "\n";
    }
    outFile.close();
    chmod(crypttabPath.c_str(), 0644);

    std::cout << "Successfully restored " << crypttabPath << std::endl;
    return true;
}

bool remove_luks_key() {
    if (getFileSize(root_key_file)==0) {
        std::cout << "Note: Root keyfile not found. Skipping LUKS key removal." << std::endl;
        return true;
    }
    std::cout << "Removing auto-unlock key from LUKS header..." << std::endl;

    // Try to remove the key using the keyfile
    std::string command = "cryptsetup luksRemoveKey /dev/" + root_device_name + 
             " " + root_key_file + " --key-file " + root_key_file + " --verbose";
    auto result = exec(command.c_str());
    
    if (result.find("Command successful.") != std::string::npos) {
        std::cout << "Successfully removed auto-unlock key from LUKS header" << std::endl;
        return true;
    } else {
        std::cout << "Warning: Could not remove LUKS key. It may have been removed already." << std::endl;
        std::cout << result << std::endl;
        return true; // Continue with other cleanup
    }
}

bool uninstall_hooks() {
    bool success = true;
    
    // Remove dracut module directory
    if (fs::exists(dracut_path)) {
        try {
            fs::remove_all(dracut_path);
            std::cout << "Removed initRAMFS hook directory: " << dracut_path << std::endl;
        } catch (const fs::filesystem_error& e) {
            std::cerr << "Warning: Failed to remove " << dracut_path << ": " << e.what() << std::endl;
            success = false;
        }
    } else {
        std::cout << "Note: initRAMFS hook directory not found (already removed?)" << std::endl;
    }

    // Remove dracut config
    std::string dracut_config = "/usr/lib/dracut/dracut.conf.d/80-luksury.conf";
    if (fs::exists(dracut_config)) {
        if (std::remove(dracut_config.c_str()) == 0) {
            std::cout << "Removed dracut config: " << dracut_config << std::endl;
        } else {
            std::cerr << "Warning: Failed to remove " << dracut_config << std::endl;
            success = false;
        }
    }

    return success;
}

bool uninstall_auto_update() {
    std::string update_hook = "/etc/initramfs/post-update.d/zzz-luksury";
    
    if (fs::exists(update_hook)) {
        if (std::remove(update_hook.c_str()) == 0) {
            std::cout << "Removed auto-update hook: " << update_hook << std::endl;
            return true;
        } else {
            std::cerr << "Warning: Failed to remove " << update_hook << std::endl;
            return false;
        }
    } else {
        std::cout << "Note: Auto-update hook not found (already removed?)" << std::endl;
        return true;
    }
}

bool cleanup_tpm_data() {
    bool success = true;

    // Get the persistent handle if it exists
    if (!getTPMHandleAddress(true)) {
        std::cout << "Note: No TPM persistent handle found (already removed?)" << std::endl;
    } else {
        // Check if the handle is in use
        std::vector<TPM2_HANDLE> handles = get_tpm_persistent_handles();
        if (std::find(handles.begin(), handles.end(), persistent_handle.handle) != handles.end()) {
            std::cout << "Removing sealed key from TPM NVRAM (handle " << persistent_handle.text << ")..." << std::endl;
            if (evict_persistent(persistent_handle.handle)) {
                std::cout << "Successfully removed TPM sealed key" << std::endl;
            } else {
                std::cerr << "Warning: Failed to evict TPM handle " << persistent_handle.text << std::endl;
                success = false;
            }
        } else {
            std::cout << "Note: TPM handle not active (already removed?)" << std::endl;
        }
    }

    return success;
}

bool cleanup_data_directory() {
    bool success = true;

    // Remove root keyfile
    if (fs::exists(root_key_file)) {
        // Securely overwrite before deletion
        std::ofstream file(root_key_file, std::ios::binary);
        if (file.is_open()) {
            std::vector<unsigned char> zeros(32, 0);
            file.write(reinterpret_cast<char*>(zeros.data()), zeros.size());
            file.close();
        }
        
        if (std::remove(root_key_file) == 0) {
            std::cout << "Removed root keyfile: " << root_key_file << std::endl;
        } else {
            std::cerr << "Warning: Failed to remove " << root_key_file << std::endl;
            success = false;
        }
    }

    // Remove persistent handle file
    std::string handle_file = std::string(data_dir) + "/persistent_handle.bin";
    if (fs::exists(handle_file)) {
        if (std::remove(handle_file.c_str()) == 0) {
            std::cout << "Removed persistent handle file" << std::endl;
        } else {
            std::cerr << "Warning: Failed to remove persistent handle file" << std::endl;
            success = false;
        }
    }

    // Try to remove data directory if empty
    if (fs::exists(data_dir) && fs::is_empty(data_dir)) {
        if (rmdir(data_dir) == 0) {
            std::cout << "Removed data directory: " << data_dir << std::endl;
        } else {
            std::cerr << "Warning: Failed to remove " << data_dir << std::endl;
            success = false;
        }
    } else if (fs::exists(data_dir)) {
        std::cout << "Note: Data directory not empty, not removing: " << data_dir << std::endl;
    }

    return success;
}

bool remove_luksury() {
    std::cout << "=== Removing Luksury Auto-Unlock  ===" << std::endl;
    std::cout << std::endl;

    // Find root partition data
    if (!find_root_partition_data()) {
        std::cerr << "Warning: Could not find root partition data. Continuing with removal..." << std::endl;
    }

    bool all_success = true;

    // Step 1: Restore crypttab
    std::cout << "\n[1/6] Restoring /etc/crypttab..." << std::endl;
    if (!restoreCrypttab()) {
        std::cerr << "Failed to restore crypttab" << std::endl;
        all_success = false;
    }

    // Step 2: Remove LUKS key
    std::cout << "\n[2/6] Removing LUKS key..." << std::endl;
    if (!remove_luks_key()) {
        std::cerr << "Failed to remove LUKS key" << std::endl;
        all_success = false;
    }

    // Step 3: Remove TPM data
    std::cout << "\n[3/6] Cleaning up TPM data..." << std::endl;
    if (!cleanup_tpm_data()) {
        std::cerr << "Failed to cleanup TPM data" << std::endl;
        all_success = false;
    }

    // Step 4: Uninstall hooks
    std::cout << "\n[4/6] Removing initRAMFS hooks..." << std::endl;
    if (!uninstall_hooks()) {
        std::cerr << "Failed to uninstall hooks" << std::endl;
        all_success = false;
    }

    // Step 5: Uninstall auto-update
    std::cout << "\n[5/6] Removing auto-update hook..." << std::endl;
    if (!uninstall_auto_update()) {
        std::cerr << "Failed to uninstall auto-update" << std::endl;
        all_success = false;
    }

    // Step 6: Clean up data directory
    std::cout << "\n[6/6] Cleaning up data directory..." << std::endl;
    if (!cleanup_data_directory()) {
        std::cerr << "Failed to cleanup data directory" << std::endl;
        all_success = false;
    }

    std::cout << "\n=== Removal Process Complete ===" << std::endl;
    
    if (all_success) {
        if (fs::exists("/usr/sbin/update-initramfs")) {
//            std::cout << "  sudo update-initramfs -u" << std::endl;
            int res = system("/usr/sbin/update-initramfs -u");
        }
        std::cout << "\nLuksury has been successfully removed from your system." << std::endl;
        std::cout << "\nAfter the next boot, you will need to enter your password to unlock the root partition." << std::endl;
    } else {
        std::cout << "\nRemoval completed with warnings. Please check the messages above." << std::endl;
        std::cout << "You may need to manually verify that all components were removed." << std::endl;
    }

    return all_success;
}