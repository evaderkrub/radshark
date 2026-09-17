// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// live_source.cpp -- a local interface through libpcap. The capture thread
// is libpcap's dispatch loop; frames land in a FrameQueue the main thread
// drains. Opening needs CAP_NET_RAW (Linux) / Npcap (Windows): the failure
// text from libpcap is shown as the reason, verbatim.
#include "sources.h"

#ifdef RADSHARK_HAVE_PCAP
#include <pcap.h>
#include <atomic>
#include <thread>
#endif

namespace radshark {

#ifdef RADSHARK_HAVE_PCAP

namespace {

class LiveSource final : public FrameSource {
public:
    LiveSource(std::string id, bool promisc, std::string bpf)
        : id_(std::move(id)), promisc_(promisc), bpf_(std::move(bpf)) { name_ = id_; }
    ~LiveSource() override { stop(); }
    SourceKind kind() const override { return SourceKind::LocalInterface; }
    const std::string& name() const override { return name_; }

    bool start(std::string& error) override {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t* p = pcap_create(id_.c_str(), errbuf);
        if (!p) { error = errbuf; return false; }
        pcap_set_snaplen(p, 262144);
        pcap_set_promisc(p, promisc_ ? 1 : 0);
        pcap_set_timeout(p, 100);
        pcap_set_immediate_mode(p, 1);
        pcap_set_tstamp_precision(p, PCAP_TSTAMP_PRECISION_NANO);
        const int rc = pcap_activate(p);
        if (rc < 0) {
            error = std::string(pcap_geterr(p));
            if (error.empty()) error = pcap_statustostr(rc);
            pcap_close(p);
            return false;
        }
        if (!bpf_.empty()) {
            bpf_program prog{};
            if (pcap_compile(p, &prog, bpf_.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0 ||
                pcap_setfilter(p, &prog) < 0) {
                error = std::string("capture filter: ") + pcap_geterr(p);
                pcap_close(p);
                return false;
            }
            pcap_freecode(&prog);
        }
        dlt_ = pcap_datalink(p);
        nano_ = pcap_get_tstamp_precision(p) == PCAP_TSTAMP_PRECISION_NANO;
        pcap_ = p;
        running_ = true;
        thread_ = std::thread([this] { Loop(); });
        return true;
    }

    void stop() override {
        if (!running_) return;
        running_ = false;
        if (pcap_) pcap_breakloop(pcap_);
        if (thread_.joinable()) thread_.join();
        if (pcap_) { pcap_close(pcap_); pcap_ = nullptr; }
    }
    bool running() const override { return running_; }
    std::size_t poll(std::vector<RawFrame>& out) override { return queue_.drain(out); }
    std::string status() const override {
        std::string s;
        if (!error_.empty()) s = error_;
        const std::uint64_t d = queue_.dropped() + dropped_;
        if (d) s += (s.empty() ? "" : " · ") + std::string("Dropped: ") + std::to_string(d);
        return s;
    }

private:
    static void OnPacket(u_char* user, const pcap_pkthdr* h, const u_char* bytes) {
        LiveSource* self = reinterpret_cast<LiveSource*>(user);
        RawFrame f;
        f.bytes.assign(bytes, bytes + h->caplen);
        f.orig_len = h->len;
        f.ts_sec = (std::int64_t)h->ts.tv_sec;
        f.ts_nsec = (std::int32_t)(self->nano_ ? h->ts.tv_usec : h->ts.tv_usec * 1000);
        f.dlt = self->dlt_;
        f.iface = self->id_;
        self->queue_.push(std::move(f));
    }
    void Loop() {
        while (running_) {
            const int rc = pcap_dispatch(pcap_, -1, &LiveSource::OnPacket, reinterpret_cast<u_char*>(this));
            if (rc == PCAP_ERROR) { error_ = pcap_geterr(pcap_); break; }
            if (rc == PCAP_ERROR_BREAK) break;
            pcap_stat st{};
            if (pcap_stats(pcap_, &st) == 0) dropped_ = st.ps_drop;
        }
    }

    std::string id_, name_, bpf_;
    bool promisc_;
    pcap_t* pcap_ = nullptr;
    int dlt_ = 1;
    bool nano_ = false;
    std::atomic<bool> running_{false};
    std::thread thread_;
    FrameQueue queue_;
    std::atomic<std::uint64_t> dropped_{0};
    std::string error_;
};

} // namespace

bool LocalCaptureAvailable() { return true; }

std::vector<SourceEntry> ListLocalInterfaces() {
    std::vector<SourceEntry> out;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* all = nullptr;
    if (pcap_findalldevs(&all, errbuf) != 0 || !all) {
        SourceEntry e;
        e.kind = SourceKind::LocalInterface;
        e.name = "(no interfaces)";
        e.available = false;
        e.reason = errbuf[0] ? errbuf : "libpcap listed nothing -- capture privileges?";
        out.push_back(e);
        return out;
    }
    for (pcap_if_t* d = all; d; d = d->next) {
        SourceEntry e;
        e.kind = SourceKind::LocalInterface;
        e.id = d->name ? d->name : "";
        e.name = e.id;
        if (d->description && *d->description) e.description = d->description;
        if (d->flags & PCAP_IF_LOOPBACK) e.description += (e.description.empty() ? "" : " · ") + std::string("loopback");
        if ((d->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
            e.description += (e.description.empty() ? "" : " · ") + std::string("disconnected");
        out.push_back(e);
    }
    pcap_freealldevs(all);
    return out;
}

std::unique_ptr<FrameSource> OpenLocalInterface(const std::string& id, bool promiscuous, const std::string& bpf) {
    return std::make_unique<LiveSource>(id, promiscuous, bpf);
}

#else   // no libpcap in this build

bool LocalCaptureAvailable() { return false; }

std::vector<SourceEntry> ListLocalInterfaces() {
    SourceEntry e;
    e.kind = SourceKind::LocalInterface;
    e.name = "Local interfaces";
    e.available = false;
    e.reason = "this build has no libpcap (install libpcap-dev / Npcap and rebuild)";
    return {e};
}

std::unique_ptr<FrameSource> OpenLocalInterface(const std::string&, bool, const std::string&) {
    return nullptr;
}

#endif

} // namespace radshark
