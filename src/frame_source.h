// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// frame_source.h -- one raw Ethernet frame and the seam every capture source
// implements. Sources may deliver from their own thread (libpcap, libicsneo)
// or from the host's frame loop (corelib's monitor, a file): the Capture
// model drains a mutex-protected queue on the main thread either way.
#pragma once
#include "pcap_reader.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vspyshark {

using wirespy::RawFrame;   // the client library's frame (src/client/pcap_reader.h)
using wirespy::PcapFile;
using wirespy::ReadPcap;
using wirespy::WritePcap;

// Where frames can come from. The kind is what the Welcome screen groups by.
enum class SourceKind { File = 0, LocalInterface, Corelib, Libx, Icsneo };

const char* SourceKindName(SourceKind k);

// One capturable thing: an interface, a device, a monitor.
struct SourceEntry {
    SourceKind kind = SourceKind::File;
    std::string id;            // stable id inside its kind (interface name, serial)
    std::string name;          // shown in the list
    std::string description;   // second line
    bool available = true;     // false + `reason` = listed but not openable
    std::string reason;
};

// A running capture. start() may fail with a reason; poll() is called from the
// main thread every frame and moves anything queued into `out`.
class FrameSource {
public:
    virtual ~FrameSource() = default;
    virtual SourceKind kind() const = 0;
    virtual const std::string& name() const = 0;    // for the status bar
    virtual bool start(std::string& error) = 0;
    virtual void stop() = 0;
    virtual bool running() const = 0;
    // Drain queued frames (appends). Returns how many were moved.
    virtual std::size_t poll(std::vector<RawFrame>& out) = 0;
    // "…" for the status bar: dropped counts, link state, the file's progress.
    virtual std::string status() const { return {}; }
    // True once a finite source (a file) has delivered everything.
    virtual bool finished() const { return false; }
};

// Thread-safe queue helper the threaded sources share.
class FrameQueue {
public:
    void push(RawFrame&& f) {
        std::lock_guard<std::mutex> g(m_);
        q_.push_back(std::move(f));
        if (q_.size() > kMaxQueued) { q_.erase(q_.begin()); ++dropped_; }
    }
    std::size_t drain(std::vector<RawFrame>& out) {
        std::lock_guard<std::mutex> g(m_);
        const std::size_t n = q_.size();
        for (auto& f : q_) out.push_back(std::move(f));
        q_.clear();
        return n;
    }
    std::uint64_t dropped() const { std::lock_guard<std::mutex> g(m_); return dropped_; }
private:
    static constexpr std::size_t kMaxQueued = 200000;
    mutable std::mutex m_;
    std::vector<RawFrame> q_;
    std::uint64_t dropped_ = 0;
};

} // namespace vspyshark
