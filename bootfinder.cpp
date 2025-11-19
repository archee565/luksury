#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <regex>

namespace fs = std::filesystem;

struct BootEntry {
    std::string kernel;
    std::string initrd;
    std::string title;
};

// Trim whitespace from string
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

// Convert wildcard pattern to regex
std::string wildcardToRegex(const std::string& pattern) {
    std::string result;
    for (char c : pattern) {
        switch (c) {
            case '*': result += ".*"; break;
            case '?': result += "."; break;
            case '.': result += "\\."; break;
            case '\\': result += "\\\\"; break;
            default: result += c;
        }
    }
    return result;
}

// Find files matching wildcard pattern
std::vector<std::string> findMatchingFiles(const std::string& basePath, 
                                           const std::string& pattern) {
    std::vector<std::string> matches;
    
    fs::path base(basePath);
    fs::path patternPath(pattern);
    
    // Combine base path with pattern's directory part
    fs::path searchDir = base / patternPath.parent_path();
    std::string filename = patternPath.filename().string();
    
    if (!fs::exists(searchDir) || !fs::is_directory(searchDir)) {
        return matches;
    }
    
    // Convert wildcard to regex
    std::regex fileRegex(wildcardToRegex(filename));
    
    for (const auto& entry : fs::directory_iterator(searchDir)) {
        if (entry.is_regular_file()) {
            std::string name = entry.path().filename().string();
            if (std::regex_match(name, fileRegex)) {
                matches.push_back(entry.path().string());
            }
        }
    }
    
    // Sort to get consistent results (typically newest/highest version)
    std::sort(matches.rbegin(), matches.rend());
    
    return matches;
}

// Parse a boot entry file
BootEntry parseBootEntry(const std::string& entryPath, const std::string& espPath) {
    BootEntry entry;
    std::ifstream file(entryPath);
    std::string line;
    
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find_first_of(" \t");
        if (pos == std::string::npos) continue;
        
        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));
        
        if (key == "title") {
            entry.title = value;
        } else if (key == "linux") {
            // Remove leading slash if present
            if (!value.empty() && value[0] == '/') {
                value = value.substr(1);
            }
            
            // Check for wildcards
            if (value.find('*') != std::string::npos || 
                value.find('?') != std::string::npos) {
                auto matches = findMatchingFiles(espPath, value);
                if (!matches.empty()) {
                    entry.kernel = matches[0];
                }
            } else {
                entry.kernel = espPath + "/" + value;
            }
        } else if (key == "initrd") {
            // Remove leading slash if present
            if (!value.empty() && value[0] == '/') {
                value = value.substr(1);
            }
            
            // Check for wildcards
            if (value.find('*') != std::string::npos || 
                value.find('?') != std::string::npos) {
                auto matches = findMatchingFiles(espPath, value);
                if (!matches.empty()) {
                    entry.initrd = matches[0];
                }
            } else {
                entry.initrd = espPath + "/" + value;
            }
        }
    }
    
    return entry;
}

// Find the ESP (EFI System Partition) path
std::string findESPPath() {
    // Common ESP mount points to check
    std::vector<std::string> possiblePaths = {
        "/boot/efi",
        "/boot",
        "/efi",
        "/esp"
    };
    
    for (const auto& path : possiblePaths) {
        std::string loaderPath = path + "/loader/loader.conf";
        if (fs::exists(loaderPath)) {
            return path;
        }
    }
    
    // Try to read from /proc/mounts to find ESP
    std::ifstream mounts("/proc/mounts");
    std::string line;
    
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string device, mountPoint, fsType;
        
        if (iss >> device >> mountPoint >> fsType) {
            // Check if it's a vfat filesystem (typical for ESP)
            if (fsType == "vfat") {
                std::string loaderPath = mountPoint + "/loader/loader.conf";
                if (fs::exists(loaderPath)) {
                    return mountPoint;
                }
            }
        }
    }
    
    return "";
}

// Main function to find default boot paths
BootEntry findDefaultBootPaths(const std::string& espPath = "") {
    BootEntry result;
    
    // Auto-detect ESP path if not provided
    std::string actualESPPath = espPath;
    if (actualESPPath.empty()) {
        actualESPPath = findESPPath();
        if (actualESPPath.empty()) {
            std::cerr << "Cannot find EFI System Partition" << std::endl;
            return result;
        }
    }
    
    std::string loaderConfPath = actualESPPath + "/loader/loader.conf";
    std::string defaultEntry;
    
    // Parse loader.conf to find default entry
    std::ifstream loaderConf(loaderConfPath);
    if (!loaderConf.is_open()) {
        std::cerr << "Cannot open " << loaderConfPath << std::endl;
        return result;
    }
    
    std::string line;
    while (std::getline(loaderConf, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find_first_of(" \t");
        if (pos == std::string::npos) continue;
        
        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));
        
        if (key == "default") {
            defaultEntry = value;
            break;
        }
    }
    loaderConf.close();
    
    if (defaultEntry.empty()) {
        std::cerr << "No default entry found in loader.conf" << std::endl;
        return result;
    }
    
    // Helper lambda to check string suffix
    auto endsWith = [](const std::string& str, const std::string& suffix) {
        if (suffix.length() > str.length()) return false;
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    };
    
    // Handle wildcard in default entry
    std::string entriesPath = actualESPPath + "/loader/entries";
    std::vector<std::string> entryFiles;
    
    if (defaultEntry.find('*') != std::string::npos || 
        defaultEntry.find('?') != std::string::npos) {
        
        if (!endsWith(defaultEntry, ".conf")) {
            defaultEntry += ".conf";
        }
        
        entryFiles = findMatchingFiles(entriesPath, defaultEntry);
    } else {
        // Add .conf extension if not present
        if (!endsWith(defaultEntry, ".conf")) {
            defaultEntry += ".conf";
        }
        std::string fullPath = entriesPath + "/" + defaultEntry;
        if (fs::exists(fullPath)) {
            entryFiles.push_back(fullPath);
        }
    }
    
    if (entryFiles.empty()) {
        std::cerr << "Default entry file not found" << std::endl;
        return result;
    }
    
    // Parse the entry file (use first match if wildcard)
    result = parseBootEntry(entryFiles[0], actualESPPath);
    
    return result;
}

// Example usage
int main() {
    // Auto-detect ESP path (or specify custom path)
    std::string espPath = ""; // Empty string triggers auto-detection
    
    BootEntry bootEntry = findDefaultBootPaths(espPath);
    
    if (!bootEntry.kernel.empty()) {
        std::cout << "Title:  " << bootEntry.title << std::endl;
        std::cout << "Kernel: " << bootEntry.kernel << std::endl;
        std::cout << "Initrd: " << bootEntry.initrd << std::endl;
    } else {
        std::cout << "Failed to find default boot entry" << std::endl;
        return 1;
    }
    
    return 0;
}