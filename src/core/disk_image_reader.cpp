#include "core/disk_image_reader.hpp"
#include <system_error>
#include <limits>
#include <iostream>

namespace forensivault::core {

DiskImageReader::DiskImageReader() = default;

DiskImageReader::DiskImageReader(const std::string& filepath, uint32_t sectorSize) {
    open(filepath, sectorSize);
}

DiskImageReader::~DiskImageReader() {
    close();
}

DiskImageReader::DiskImageReader(DiskImageReader&& other) noexcept {
    std::lock_guard<std::mutex> lock(other.ioMutex_);
    filepath_ = std::move(other.filepath_);
    sectorSize_ = other.sectorSize_;
    fileSize_ = other.fileSize_;
    totalSectors_ = other.totalSectors_;
    stream_ = std::move(other.stream_);
    lastError_ = std::move(other.lastError_);

    other.fileSize_ = 0;
    other.totalSectors_ = 0;
}

DiskImageReader& DiskImageReader::operator=(DiskImageReader&& other) noexcept {
    if (this != &other) {
        std::scoped_lock lock(ioMutex_, other.ioMutex_);
        close();
        filepath_ = std::move(other.filepath_);
        sectorSize_ = other.sectorSize_;
        fileSize_ = other.fileSize_;
        totalSectors_ = other.totalSectors_;
        stream_ = std::move(other.stream_);
        lastError_ = std::move(other.lastError_);

        other.fileSize_ = 0;
        other.totalSectors_ = 0;
    }
    return *this;
}

bool DiskImageReader::open(const std::string& filepath, uint32_t sectorSize) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    close();
    clearError();

    if (filepath.empty()) {
        setError("Cannot open disk image: empty filepath provided");
        return false;
    }

    if (sectorSize == 0) {
        setError("Invalid sector size: sector size must be greater than zero");
        return false;
    }

    filepath_ = filepath;
    sectorSize_ = sectorSize;

    // Open strictly read-only binary stream
    stream_ = std::make_unique<std::ifstream>(filepath_, std::ios::binary | std::ios::in);
    if (!stream_ || !stream_->is_open()) {
        setError("Failed to open image file '" + filepath_ + "' in binary read-only mode");
        stream_.reset();
        return false;
    }

    // Determine file size
    stream_->seekg(0, std::ios::end);
    std::streamoff endPos = stream_->tellg();
    if (endPos < 0) {
        setError("Failed to query size of image file: " + filepath_);
        stream_->close();
        stream_.reset();
        return false;
    }

    fileSize_ = static_cast<uint64_t>(endPos);
    totalSectors_ = (fileSize_ + sectorSize_ - 1) / sectorSize_;

    // Reset seek position to start
    stream_->seekg(0, std::ios::beg);
    if (!stream_->good()) {
        setError("Failed to rewind image file stream after size query");
        stream_->close();
        stream_.reset();
        return false;
    }

    return true;
}

void DiskImageReader::close() {
    if (stream_ && stream_->is_open()) {
        stream_->close();
    }
    stream_.reset();
    fileSize_ = 0;
    totalSectors_ = 0;
    filepath_.clear();
}

bool DiskImageReader::isOpen() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return stream_ && stream_->is_open();
}

uint64_t DiskImageReader::size() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return fileSize_;
}

uint32_t DiskImageReader::sectorSize() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return sectorSize_;
}

uint64_t DiskImageReader::totalSectors() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return totalSectors_;
}

const std::string& DiskImageReader::filepath() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return filepath_;
}

bool DiskImageReader::seek(uint64_t offset) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    clearError();

    if (!stream_ || !stream_->is_open()) {
        setError("Seek failed: no disk image opened");
        return false;
    }

    if (offset > fileSize_) {
        setError("Seek offset out of bounds: requested offset " + std::to_string(offset) +
                 ", total size " + std::to_string(fileSize_));
        return false;
    }

    if (stream_->eof() || stream_->fail()) {
        stream_->clear();
    }

    stream_->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream_->good()) {
        setError("Stream seek operation failed at offset " + std::to_string(offset));
        return false;
    }

    return true;
}

uint64_t DiskImageReader::tell() {
    std::lock_guard<std::mutex> lock(ioMutex_);
    if (!stream_ || !stream_->is_open()) {
        return 0;
    }
    std::streamoff pos = stream_->tellg();
    return (pos < 0) ? 0 : static_cast<uint64_t>(pos);
}

bool DiskImageReader::read(uint64_t offset, uint8_t* buffer, size_t size) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    clearError();

    if (!stream_ || !stream_->is_open()) {
        setError("Read failed: no disk image opened");
        return false;
    }

    if (!buffer && size > 0) {
        setError("Read failed: destination buffer is null");
        return false;
    }

    if (size == 0) {
        return true;
    }

    // Bounds check and overflow check
    if (offset > fileSize_ || (fileSize_ - offset) < size) {
        setError("Read bounds error: offset " + std::to_string(offset) + " + length " +
                 std::to_string(size) + " exceeds image size " + std::to_string(fileSize_));
        return false;
    }

    if (stream_->eof() || stream_->fail()) {
        stream_->clear();
    }

    stream_->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream_->good()) {
        setError("Seek prior to read failed at offset " + std::to_string(offset));
        return false;
    }

    stream_->read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(size));
    std::streamsize bytesRead = stream_->gcount();

    if (bytesRead != static_cast<std::streamsize>(size)) {
        setError("Short read encountered: requested " + std::to_string(size) +
                 " bytes, but only read " + std::to_string(bytesRead) + " bytes");
        return false;
    }

    return true;
}

std::vector<uint8_t> DiskImageReader::readBytes(uint64_t offset, size_t size) {
    std::vector<uint8_t> buffer(size);
    if (read(offset, buffer.data(), size)) {
        return buffer;
    }
    return {};
}

std::vector<uint8_t> DiskImageReader::readSector(uint64_t sectorNumber) {
    std::vector<uint8_t> buffer(sectorSize_);
    if (readSector(sectorNumber, buffer.data())) {
        return buffer;
    }
    return {};
}

bool DiskImageReader::readSector(uint64_t sectorNumber, uint8_t* outBuffer) {
    return readSectors(sectorNumber, 1, outBuffer);
}

bool DiskImageReader::readSectors(uint64_t startSector, uint64_t count, uint8_t* outBuffer) {
    if (count == 0) {
        return true;
    }

    uint64_t byteOffset = startSector * sectorSize_;
    uint64_t totalBytes = count * sectorSize_;

    return read(byteOffset, outBuffer, static_cast<size_t>(totalBytes));
}

const std::string& DiskImageReader::lastError() const {
    std::lock_guard<std::mutex> lock(ioMutex_);
    return lastError_;
}

void DiskImageReader::setError(const std::string& errorMsg) const {
    lastError_ = errorMsg;
}

void DiskImageReader::clearError() const {
    lastError_.clear();
}

} // namespace forensivault::core
