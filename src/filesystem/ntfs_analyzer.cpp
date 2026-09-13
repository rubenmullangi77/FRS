#include "filesystem/ntfs_analyzer.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>

namespace forensivault {
namespace filesystem {

namespace {
inline uint16_t readLE16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t readLE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t readLE64(const uint8_t* p) {
    return static_cast<uint64_t>(readLE32(p)) |
           (static_cast<uint64_t>(readLE32(p + 4)) << 32);
}
} // namespace

NTFSAnalyzer::NTFSAnalyzer() = default;

bool NTFSAnalyzer::probe(core::DiskImageReader& reader, uint64_t partitionStartSector) {
    partition_start_sector_ = partitionStartSector;
    current_reader_ = &reader;

    const uint64_t offset = partitionStartSector * 512;
    if (offset + 512 > reader.size()) {
        return false;
    }

    std::vector<uint8_t> bootSector(512);
    if (!reader.read(offset, bootSector.data(), 512)) {
        return false;
    }

    // Check boot signature 0x55AA at offset 510
    if (bootSector[510] != 0x55 || bootSector[511] != 0xAA) {
        return false;
    }

    // Check OEM ID: "NTFS    "
    char oemId[9] = {0};
    std::memcpy(oemId, &bootSector[3], 8);
    if (std::strcmp(oemId, "NTFS    ") != 0) {
        return false;
    }

    uint16_t bytesPerSec = readLE16(&bootSector[11]);
    uint8_t secPerClus = bootSector[13];
    uint64_t totalSectors = readLE64(&bootSector[40]);
    uint64_t mftLcn = readLE64(&bootSector[48]);
    int8_t mftClustersPerRecord = static_cast<int8_t>(bootSector[64]);

    if (bytesPerSec != 512 && bytesPerSec != 1024 && bytesPerSec != 2048 && bytesPerSec != 4096) {
        return false;
    }
    if (secPerClus == 0) {
        return false;
    }

    uint32_t recordSize = 1024;
    if (mftClustersPerRecord < 0) {
        recordSize = 1U << (-mftClustersPerRecord);
    } else if (mftClustersPerRecord > 0) {
        recordSize = static_cast<uint32_t>(mftClustersPerRecord) * secPerClus * bytesPerSec;
    }

    volume_info_.fs_type = FsType::NTFS;
    volume_info_.bytes_per_sector = bytesPerSec;
    volume_info_.sectors_per_cluster = secPerClus;
    volume_info_.cluster_size = static_cast<uint64_t>(bytesPerSec) * secPerClus;
    volume_info_.total_sectors = totalSectors;
    volume_info_.partition_offset_bytes = offset;
    volume_info_.allocation_table_offset = offset + (mftLcn * volume_info_.cluster_size);
    volume_info_.volume_label = "NTFS_Volume";
    volume_info_.serial_number = static_cast<uint32_t>(readLE64(&bootSector[72]));
    volume_info_.valid = true;

    mft_start_lcn_ = mftLcn;
    mft_record_size_ = recordSize;
    mft_byte_offset_ = volume_info_.allocation_table_offset;

    return true;
}

FsVolumeInfo NTFSAnalyzer::getVolumeInfo() const {
    return volume_info_;
}

std::string NTFSAnalyzer::parseUtf16LE(const uint8_t* bytes, size_t numChars) const {
    std::string out;
    for (size_t i = 0; i < numChars; ++i) {
        uint16_t c = readLE16(bytes + (i * 2));
        if (c == 0) break;
        if (c < 128) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('?');
        }
    }
    return out;
}

std::string NTFSAnalyzer::formatFileTime(uint64_t filetime) const {
    if (filetime == 0) return "N/A";
    // Convert Windows FILETIME (100-ns intervals since Jan 1, 1601) to UNIX time
    const uint64_t epochDiff = 116444736000000000ULL;
    if (filetime < epochDiff) return "N/A";
    time_t unixTime = static_cast<time_t>((filetime - epochDiff) / 10000000ULL);
    
    std::tm tmBuf{};
#if defined(_WIN32)
    gmtime_s(&tmBuf, &unixTime);
#else
    gmtime_r(&unixTime, &tmBuf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tmBuf, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::vector<ClusterRun> NTFSAnalyzer::parseRunlist(const uint8_t* runlistData, size_t maxLen) const {
    std::vector<ClusterRun> runs;
    size_t idx = 0;
    int64_t prevLcn = 0;

    while (idx < maxLen && runlistData[idx] != 0) {
        uint8_t header = runlistData[idx++];
        uint8_t lenFieldSize = header & 0x0F;
        uint8_t offsetFieldSize = (header >> 4) & 0x0F;

        if (lenFieldSize == 0 || idx + lenFieldSize + offsetFieldSize > maxLen) {
            break;
        }

        uint64_t runLength = 0;
        for (uint8_t i = 0; i < lenFieldSize; ++i) {
            runLength |= (static_cast<uint64_t>(runlistData[idx++]) << (i * 8));
        }

        int64_t runOffsetDiff = 0;
        for (uint8_t i = 0; i < offsetFieldSize; ++i) {
            runOffsetDiff |= (static_cast<int64_t>(runlistData[idx++]) << (i * 8));
        }
        // Sign-extend if negative
        if (offsetFieldSize > 0 && (runlistData[idx - 1] & 0x80)) {
            for (uint8_t i = offsetFieldSize; i < 8; ++i) {
                runOffsetDiff |= (static_cast<int64_t>(0xFF) << (i * 8));
            }
        }

        int64_t currentLcn = prevLcn + runOffsetDiff;
        prevLcn = currentLcn;

        if (currentLcn >= 0) {
            runs.push_back({static_cast<uint64_t>(currentLcn), runLength});
        }
    }

    return runs;
}

bool NTFSAnalyzer::parseMftRecord(const uint8_t* recordData, size_t recordSize, FsFileRecord& outRecord, bool& isAllocated) {
    if (recordSize < 48) return false;

    // Signature check: "FILE"
    if (recordData[0] != 'F' || recordData[1] != 'I' || recordData[2] != 'L' || recordData[3] != 'E') {
        return false;
    }

    uint16_t attrsOffset = readLE16(&recordData[20]);
    uint16_t flags = readLE16(&recordData[22]);

    isAllocated = (flags & 0x01) != 0;
    bool isDirectory = (flags & 0x02) != 0;

    outRecord.is_directory = isDirectory;
    outRecord.attributes = flags;

    // Walk attributes
    uint32_t currOffset = attrsOffset;
    std::string foundName;
    uint64_t foundSize = 0;
    std::vector<ClusterRun> foundRuns;
    uint64_t residentDataOffset = 0;
    uint64_t residentDataSize = 0;

    while (currOffset + 8 <= recordSize) {
        uint32_t attrType = readLE32(&recordData[currOffset]);
        if (attrType == 0xFFFFFFFF || attrType == 0) {
            break; // End of attributes
        }

        uint32_t attrLen = readLE32(&recordData[currOffset + 4]);
        if (attrLen == 0 || currOffset + attrLen > recordSize) {
            break;
        }

        uint8_t nonResident = recordData[currOffset + 8];

        if (attrType == 0x30) {
            // $FILE_NAME attribute (always resident)
            if (nonResident == 0 && currOffset + 24 <= recordSize) {
                uint16_t contentOffset = readLE16(&recordData[currOffset + 20]);
                uint32_t contentLen = readLE32(&recordData[currOffset + 16]);

                if (currOffset + contentOffset + contentLen <= recordSize && contentLen >= 66) {
                    const uint8_t* fnData = &recordData[currOffset + contentOffset];
                    uint64_t cTime = readLE64(&fnData[8]);
                    uint64_t mTime = readLE64(&fnData[16]);
                    outRecord.created_time = formatFileTime(cTime);
                    outRecord.modified_time = formatFileTime(mTime);

                    uint8_t nameLen = fnData[64];
                    uint8_t nameNamespace = fnData[65]; // 0=POSIX, 1=Win32, 2=DOS, 3=Win32 & DOS

                    // Prefer Win32 or POSIX names over DOS 8.3
                    if (foundName.empty() || nameNamespace != 2) {
                        if (static_cast<uint32_t>(66 + nameLen * 2) <= contentLen) {
                            foundName = parseUtf16LE(&fnData[66], nameLen);
                        }
                    }
                    if (foundSize == 0) {
                        foundSize = readLE64(&fnData[48]);
                    }
                }
            }
        } else if (attrType == 0x80) {
            // $DATA attribute
            if (nonResident == 0) {
                // Resident data
                if (currOffset + 24 <= recordSize) {
                    uint16_t contentOffset = readLE16(&recordData[currOffset + 20]);
                    uint32_t contentLen = readLE32(&recordData[currOffset + 16]);
                    if (currOffset + contentOffset + contentLen <= recordSize) {
                        residentDataOffset = currOffset + contentOffset;
                        residentDataSize = contentLen;
                        foundSize = contentLen;
                    }
                }
            } else {
                // Non-resident data
                if (currOffset + 48 <= recordSize) {
                    uint16_t runlistOffset = readLE16(&recordData[currOffset + 32]);
                    uint64_t realSize = readLE64(&recordData[currOffset + 48]);
                    foundSize = realSize;

                    if (currOffset + runlistOffset < recordSize) {
                        size_t maxRunLen = recordSize - (currOffset + runlistOffset);
                        foundRuns = parseRunlist(&recordData[currOffset + runlistOffset], maxRunLen);
                    }
                }
            }
        }

        currOffset += attrLen;
    }

    // If no $FILE_NAME found, or empty system entry like $MFT, skip if not relevant
    if (foundName.empty()) {
        return false;
    }

    outRecord.filename = foundName;
    outRecord.file_size = foundSize;
    outRecord.full_path = "/" + foundName;
    outRecord.cluster_runs = foundRuns;

    size_t dotPos = foundName.rfind('.');
    if (dotPos != std::string::npos) {
        outRecord.extension = foundName.substr(dotPos + 1);
    }

    outRecord.fragment_count = static_cast<uint32_t>(foundRuns.size());

    if (!foundRuns.empty()) {
        outRecord.starting_cluster = foundRuns.front().start_cluster;
        outRecord.byte_offset = volume_info_.partition_offset_bytes + (outRecord.starting_cluster * volume_info_.cluster_size);
        
        // Validate runs: check if runs exceed total volume sectors/clusters
        bool runsValid = true;
        uint64_t totalClusterSpan = 0;
        for (const auto& run : foundRuns) {
            totalClusterSpan += run.cluster_count;
            if (volume_info_.total_sectors > 0 && volume_info_.sectors_per_cluster > 0) {
                uint64_t maxCluster = volume_info_.total_sectors / volume_info_.sectors_per_cluster;
                if (run.start_cluster >= maxCluster || (run.start_cluster + run.cluster_count) > maxCluster + 1024) {
                    runsValid = false;
                    break;
                }
            }
        }
        if (!runsValid) {
            outRecord.is_recoverable = false;
            outRecord.unrecoverable_reason = "Required file data or allocation information is unavailable (cluster runs point beyond volume boundary).";
            outRecord.allocation_status = AllocationStatus::NOT_RECOVERABLE;
        } else {
            outRecord.is_recoverable = true;
            outRecord.allocation_status = isAllocated ? AllocationStatus::ALLOCATED : AllocationStatus::DELETED_CANDIDATE;
        }
    } else if (residentDataSize > 0) {
        // Resident data offset
        outRecord.starting_cluster = 0;
        outRecord.byte_offset = residentDataOffset; // Relative to record in this context
        outRecord.is_recoverable = true;
        outRecord.fragment_count = 1;
        outRecord.allocation_status = isAllocated ? AllocationStatus::ALLOCATED : AllocationStatus::DELETED_CANDIDATE;
    } else if (foundSize > 0) {
        // Non-zero file but missing runs and resident data
        outRecord.is_recoverable = false;
        outRecord.unrecoverable_reason = "Required file data or allocation information is unavailable (data runs destroyed or zeroed).";
        outRecord.allocation_status = AllocationStatus::NOT_RECOVERABLE;
    } else {
        outRecord.is_recoverable = true;
        outRecord.allocation_status = isAllocated ? AllocationStatus::ALLOCATED : AllocationStatus::DELETED_CANDIDATE;
    }

    outRecord.recovery_method = isAllocated ? RecoveryMethod::FILESYSTEM_METADATA_ACTIVE : RecoveryMethod::FILESYSTEM_METADATA_DELETED;

    return true;
}

std::vector<FsFileRecord> NTFSAnalyzer::scanMftRecords(core::DiskImageReader& reader, bool lookForDeleted) {
    std::vector<FsFileRecord> results;
    if (!volume_info_.valid || mft_record_size_ == 0) return results;

    std::vector<uint8_t> recordBuf(mft_record_size_);
    uint64_t currentOffset = mft_byte_offset_;
    const uint64_t maxScanRecords = 5000; // Cap to avoid scanning infinite damaged runs

    for (uint64_t i = 0; i < maxScanRecords && currentOffset + mft_record_size_ <= reader.size(); ++i) {
        if (!reader.read(currentOffset, recordBuf.data(), mft_record_size_)) {
            break;
        }

        FsFileRecord rec;
        bool isAllocated = false;
        if (parseMftRecord(recordBuf.data(), mft_record_size_, rec, isAllocated)) {
            rec.mft_record_number = i;
            if (lookForDeleted == (!isAllocated)) {
                // If resident file, mark offset as absolute image offset
                if (rec.cluster_runs.empty() && rec.byte_offset > 0) {
                    rec.byte_offset = currentOffset + rec.byte_offset;
                }
                results.push_back(rec);
            }
        }

        currentOffset += mft_record_size_;
    }

    return results;
}

std::vector<FsFileRecord> NTFSAnalyzer::listDirectory(const std::string& /*path*/) {
    if (!current_reader_ || !volume_info_.valid) return {};
    return scanMftRecords(*current_reader_, false);
}

std::vector<FsFileRecord> NTFSAnalyzer::findDeletedFiles() {
    if (!current_reader_ || !volume_info_.valid) return {};
    return scanMftRecords(*current_reader_, true);
}

std::vector<uint8_t> NTFSAnalyzer::extractFile(const FsFileRecord& record, core::DiskImageReader& reader) {
    std::vector<uint8_t> data;
    if (record.file_size == 0) {
        return data;
    }

    data.resize(record.file_size);

    if (!record.cluster_runs.empty()) {
        // Non-resident data extraction via cluster runs
        uint64_t bytesRemaining = record.file_size;
        uint64_t bytesReadTotal = 0;

        for (const auto& run : record.cluster_runs) {
            if (bytesRemaining == 0) break;
            uint64_t runBytes = run.cluster_count * volume_info_.cluster_size;
            uint64_t toRead = std::min(bytesRemaining, runBytes);
            uint64_t offset = volume_info_.partition_offset_bytes + (run.start_cluster * volume_info_.cluster_size);

            if (offset + toRead > reader.size()) {
                if (offset < reader.size()) {
                    toRead = reader.size() - offset;
                } else {
                    break;
                }
            }

            if (!reader.read(offset, data.data() + bytesReadTotal, toRead)) {
                break;
            }

            bytesReadTotal += toRead;
            bytesRemaining -= toRead;
        }
        data.resize(bytesReadTotal);
    } else if (record.byte_offset > 0) {
        // Resident data
        uint64_t toRead = std::min(record.file_size, reader.size() - record.byte_offset);
        if (reader.read(record.byte_offset, data.data(), toRead)) {
            data.resize(toRead);
        } else {
            data.clear();
        }
    }

    return data;
}

} // namespace filesystem
} // namespace forensivault
