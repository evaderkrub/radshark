// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// file_source.cpp -- a pcap / pcapng file, delivered whole on the first poll.
#include "sources.h"
#include "pcap_reader.h"

namespace radshark {

const char* SourceKindName(SourceKind k) {
    switch (k) {
    case SourceKind::File: return "File";
    case SourceKind::LocalInterface: return "Local interface";
    case SourceKind::Corelib: return "Vehicle Spy engine";
    case SourceKind::Libx: return "vspyx engine";
    case SourceKind::Icsneo: return "libicsneo device";
    }
    return "?";
}

namespace {

class FileSource final : public FrameSource {
public:
    FileSource(std::string path, PcapFile&& file) : path_(std::move(path)), file_(std::move(file)) {
        name_ = path_;
        const auto slash = name_.find_last_of("/\\");
        if (slash != std::string::npos) name_ = name_.substr(slash + 1);
    }
    SourceKind kind() const override { return SourceKind::File; }
    const std::string& name() const override { return name_; }
    bool start(std::string&) override { running_ = true; return true; }
    void stop() override { running_ = false; }
    bool running() const override { return running_ && !delivered_; }
    std::size_t poll(std::vector<RawFrame>& out) override {
        if (!running_ || delivered_) return 0;
        const std::size_t n = file_.frames.size();
        for (RawFrame& f : file_.frames) out.push_back(std::move(f));
        file_.frames.clear();
        delivered_ = true;
        return n;
    }
    std::string status() const override {
        return file_.error.empty() ? std::string() : "file: " + file_.error;
    }
    bool finished() const override { return delivered_; }
private:
    std::string path_, name_;
    PcapFile file_;
    bool running_ = false, delivered_ = false;
};

} // namespace

std::unique_ptr<FrameSource> OpenFileSource(const std::string& path, std::string& error) {
    PcapFile f;
    if (!ReadPcap(path, f)) { error = f.error; return nullptr; }
    return std::make_unique<FileSource>(path, std::move(f));
}

} // namespace radshark
