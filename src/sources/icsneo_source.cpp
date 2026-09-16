// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// icsneo_source.cpp -- an Intrepid device opened straight through libicsneo,
// bypassing both engines. Frames arrive on libicsneo's receive thread via a
// MessageCallback filtered to the Ethernet and Automotive Ethernet network
// types; timestamps are nanoseconds since 1 Jan 2007 and are rebased to the
// Unix epoch here. The FCS libicsneo reports separately is left off, which
// is what Wireshark expects of an Ethernet frame by default.
//
// Opening a device that corelib or vspyx already holds fails; the library's
// own error text is the reason shown.
#include "sources.h"

#ifdef VSPYSHARK_HAVE_ICSNEO
#include <icsneo/icsneocpp.h>
#include <atomic>
#include <mutex>
#endif

namespace vspyshark {

#ifdef VSPYSHARK_HAVE_ICSNEO

namespace {

constexpr std::int64_t kEpoch2007 = 1167609600ll;

std::mutex g_devices_mutex;
std::vector<std::shared_ptr<icsneo::Device>> g_devices;   // FindAllDevices() keeps them openable

void Rescan() {
    std::lock_guard<std::mutex> g(g_devices_mutex);
    g_devices = icsneo::FindAllDevices();
}

class IcsneoSource final : public FrameSource {
public:
    explicit IcsneoSource(std::shared_ptr<icsneo::Device> dev) : dev_(std::move(dev)) {
        name_ = dev_->describe();
    }
    ~IcsneoSource() override { stop(); }
    SourceKind kind() const override { return SourceKind::Icsneo; }
    const std::string& name() const override { return name_; }

    bool start(std::string& error) override {
        if (!dev_->open()) {
            error = "libicsneo could not open " + dev_->describe() + ": " + icsneo::GetLastError().describe();
            return false;
        }
        auto on_msg = [this](std::shared_ptr<icsneo::Message> m) { OnMessage(m); };
        cb_eth_ = dev_->addMessageCallback(std::make_shared<icsneo::MessageCallback>(
            on_msg, icsneo::MessageFilter(icsneo::Network::Type::Ethernet)));
        cb_ae_ = dev_->addMessageCallback(std::make_shared<icsneo::MessageCallback>(
            on_msg, icsneo::MessageFilter(icsneo::Network::Type::AutomotiveEthernet)));
        if (!dev_->goOnline()) {
            error = "libicsneo could not go online on " + dev_->describe() + ": " + icsneo::GetLastError().describe();
            dev_->removeMessageCallback(cb_eth_);
            dev_->removeMessageCallback(cb_ae_);
            dev_->close();
            return false;
        }
        running_ = true;
        return true;
    }

    void stop() override {
        if (!running_) return;
        running_ = false;
        dev_->goOffline();
        dev_->removeMessageCallback(cb_eth_);
        dev_->removeMessageCallback(cb_ae_);
        dev_->close();
    }
    bool running() const override { return running_; }
    std::size_t poll(std::vector<RawFrame>& out) override { return queue_.drain(out); }
    std::string status() const override {
        std::string s;
        if (dev_->isDisconnected()) s = "device disconnected";
        if (const std::uint64_t d = queue_.dropped()) s += (s.empty() ? "" : " · ") + std::string("Dropped: ") + std::to_string(d);
        return s;
    }

private:
    void OnMessage(const std::shared_ptr<icsneo::Message>& m) {
        if (!running_ || m->type != icsneo::Message::Type::Frame) return;
        auto frame = std::static_pointer_cast<icsneo::Frame>(m);
        RawFrame f;
        f.bytes = frame->data;
        f.orig_len = (std::uint32_t)frame->data.size();
        f.dlt = 1;
        f.has_ts = true;
        const std::uint64_t ns = frame->timestamp;
        f.ts_sec = (std::int64_t)(ns / 1000000000ull) + kEpoch2007;
        f.ts_nsec = (std::int32_t)(ns % 1000000000ull);
        f.transmitted = frame->transmitted;
        f.iface = icsneo::Network::GetNetIDString(frame->network.getNetID());
        queue_.push(std::move(f));
    }

    std::shared_ptr<icsneo::Device> dev_;
    std::string name_;
    int cb_eth_ = 0, cb_ae_ = 0;
    std::atomic<bool> running_{false};
    FrameQueue queue_;
};

} // namespace

bool IcsneoAvailable() { return true; }

std::vector<SourceEntry> ListIcsneoDevices(bool rescan) {
    static bool scanned = false;
    if (rescan || !scanned) { Rescan(); scanned = true; }
    std::vector<SourceEntry> out;
    std::lock_guard<std::mutex> g(g_devices_mutex);
    for (const auto& d : g_devices) {
        SourceEntry e;
        e.kind = SourceKind::Icsneo;
        e.id = d->getSerial();
        e.name = d->describe();
        std::size_t eth = 0;
        for (const icsneo::Network& n : d->getSupportedRXNetworks())
            if (n.getType() == icsneo::Network::Type::Ethernet || n.getType() == icsneo::Network::Type::AutomotiveEthernet) ++eth;
        e.description = std::to_string(eth) + " Ethernet network" + (eth == 1 ? "" : "s");
        if (eth == 0) { e.available = false; e.reason = "no Ethernet networks on this device"; }
        out.push_back(e);
    }
    if (out.empty()) {
        SourceEntry e;
        e.kind = SourceKind::Icsneo;
        e.name = "(no Intrepid devices found)";
        e.available = false;
        e.reason = "libicsneo found nothing -- attach a device and Refresh";
        out.push_back(e);
    }
    return out;
}

std::unique_ptr<FrameSource> OpenIcsneoDevice(const std::string& serial) {
    std::shared_ptr<icsneo::Device> dev;
    {
        std::lock_guard<std::mutex> g(g_devices_mutex);
        for (const auto& d : g_devices) if (d->getSerial() == serial) dev = d;
    }
    if (!dev) {
        Rescan();
        std::lock_guard<std::mutex> g(g_devices_mutex);
        for (const auto& d : g_devices) if (d->getSerial() == serial) dev = d;
    }
    if (!dev) return nullptr;
    return std::make_unique<IcsneoSource>(dev);
}

#else   // no libicsneo in this build

bool IcsneoAvailable() { return false; }

std::vector<SourceEntry> ListIcsneoDevices(bool) {
    SourceEntry e;
    e.kind = SourceKind::Icsneo;
    e.name = "Intrepid devices (libicsneo)";
    e.available = false;
    e.reason = "libicsneo support is not installed in this build";
    return {e};
}

std::unique_ptr<FrameSource> OpenIcsneoDevice(const std::string&) { return nullptr; }

#endif

} // namespace vspyshark
