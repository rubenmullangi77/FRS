#include "sanitization/drive_detector.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

namespace forensivault {
namespace sanitization {

DriveProperties DriveDetector::detectImage(
    const std::string& imagePath,
    DriveMediaType simulatedType) {

    DriveProperties props;
    props.target_path = imagePath;
    props.media_type = simulatedType;
    props.interface_type = DriveInterface::VIRTUAL_IMAGE;
    props.is_physical_device = false;
    props.is_safe_to_sanitize = true;

    std::error_code ec;
    if (!fs::exists(imagePath, ec) || !fs::is_regular_file(imagePath, ec)) {
        props.is_safe_to_sanitize = false;
        props.hardware_limitations.push_back("File does not exist or is not a regular file.");
        return props;
    }

    uint64_t fileSize = fs::file_size(imagePath, ec);
    if (ec) {
        props.is_safe_to_sanitize = false;
        props.hardware_limitations.push_back("Could not read file size: " + ec.message());
        return props;
    }

    props.total_bytes = fileSize;
    props.sector_size = 512;
    props.total_sectors = fileSize / props.sector_size;
    props.device_identifier = "RAW_IMAGE://" + fs::absolute(imagePath).string();
    props.model_name = "ForensiVault Virtual Image Target (" + fs::path(imagePath).filename().string() + ")";
    props.serial_number = "FV-VIRT-" + std::to_string(fileSize);

    // Read Sector 0 to check partition signature
    std::ifstream ifs(imagePath, std::ios::binary);
    if (ifs) {
        std::vector<uint8_t> sec0(512);
        ifs.read(reinterpret_cast<char*>(sec0.data()), 512);
        if (ifs.gcount() >= 512) {
            bool has55AA = (sec0[510] == 0x55 && sec0[511] == 0xAA);
            if (has55AA) {
                props.capabilities.push_back("Partition Table / Boot Sector Signature Verified (0x55AA)");
            }
        }
    }

    props.capabilities.push_back("Logical Sector Read/Write Overwrite Supported");
    props.capabilities.push_back("Full-Image Cryptographic Pre/Post Hash Verification Supported");
    props.capabilities.push_back("Sector-by-Sector Shannon Entropy Verification Supported");

    if (simulatedType == DriveMediaType::SSD_NAND) {
        props.hardware_limitations.push_back(
            "Simulated SSD target: Real physical SSDs have overprovisioned spare NAND blocks inaccessible via logical sector overwriting.");
        props.supports_trim = true;
    } else if (simulatedType == DriveMediaType::USB_DRIVE || simulatedType == DriveMediaType::MEMORY_CARD_SD) {
        props.hardware_limitations.push_back(
            "Simulated Flash target: Flash memory controllers use Wear-Leveling algorithms that map logical blocks dynamically.");
    }

    return props;
}

std::vector<DriveProperties> DriveDetector::detectPhysicalDevices() {
    std::vector<DriveProperties> devices;

    DriveProperties sysDrive;
#if defined(_WIN32)
    sysDrive.device_identifier = "\\\\.\\PhysicalDrive0";
#elif defined(__linux__)
    sysDrive.device_identifier = "/dev/nvme0n1";
#else
    sysDrive.device_identifier = "/dev/disk0";
#endif
    sysDrive.model_name = "Physical System NVMe / SATA Storage Device";
    sysDrive.serial_number = "PROTECTED-SYS-001";
    sysDrive.media_type = DriveMediaType::SSD_NAND;
    sysDrive.interface_type = DriveInterface::NVME;
    sysDrive.is_physical_device = true;
    sysDrive.is_safe_to_sanitize = false; // STRICTLY PROHIBITED IN PROTOTYPE
    sysDrive.supports_trim = true;
    sysDrive.supports_nvme_format = true;
    sysDrive.supports_sanitize_crypto = true;
    sysDrive.capabilities.push_back("Hardware NVMe Sanitize Specification (Crypto Erase / Block Erase)");
    sysDrive.capabilities.push_back("TRIM / Deallocate supported");
    sysDrive.hardware_limitations.push_back(
        "PROTOTYPE SAFETY INTERLOCK: Physical device sanitization is disabled in this build. Use disk-image targets (.img/.dd).");
    sysDrive.hardware_limitations.push_back(
        "Overwriting logical LBA sectors does not guarantee physical NAND cell clearing due to Flash Translation Layer (FTL) wear leveling.");

    devices.push_back(sysDrive);
    return devices;
}

} // namespace sanitization
} // namespace forensivault
