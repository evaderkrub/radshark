// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// capture.h -- the packet store the view draws from, and the worker thread
// that keeps it dissected through wirespy_server.
//
// Threading: the store itself is MAIN-THREAD-ONLY. Sources hand frames in
// through AddFrames(); the worker only ever sees shared_ptr copies of the raw
// frames and answers through a result queue that Pump() drains once per host
// frame. Two connections to the server: an in-order one that numbers frames
// 1..N and fills the summary columns (Wireshark's relative Time column needs
// the sequence), and a transient one for the details pane.
#pragma once
#include "frame_source.h"
#include "wirespy_client.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace radshark {

using wirespy::DetailNode;
using wirespy::DecodeAsk;
using wirespy::DecodeReply;
using wirespy::WirespyClient;
using wirespy::ServerLauncher;

struct Packet {
    std::shared_ptr<const RawFrame> raw;
    enum class State : std::uint8_t { Queued, Decoded, Failed } state = State::Queued;
    std::vector<std::string> cols;      // server column order
    bool match = true;                  // display filter
    bool has_color = false;
    std::uint32_t fg = 0, bg = 0;       // 0xRRGGBB
    std::string error;
};

struct DecoderStatus {
    bool ready = false;                 // server up, both connections open
    std::string text;                   // "Wireshark 4.4.18 via wirespy_server (pid…)" or the failure
    std::string wireshark_version;
    bool colors = false;
    std::vector<std::string> columns;   // titles
};

class Capture {
public:
    Capture();
    ~Capture();

    using Logger = std::function<void(int level, const std::string&)>;   // 0 info 1 warn 2 error
    void SetLogger(Logger l) { log_ = std::move(l); }

    // Starts the server if needed and connects. Cheap when already ready.
    bool EnsureDecoder(std::string& error);
    const DecoderStatus& Decoder() const { return status_; }
    void RestartDecoder();

    // Frames in. Also queues them for dissection.
    void AddFrames(std::vector<RawFrame>& frames);
    // New capture: drops everything, renumbers from 1.
    void Clear();

    // Wireshark display filter. Asynchronous: FilterState() tells the bar
    // what colour to be; a good filter re-dissects the whole capture.
    void SetFilter(const std::string& text);
    enum class FilterState { Empty, Pending, Valid, Invalid };
    FilterState FilterStatus() const { return filter_state_; }
    const std::string& Filter() const { return filter_applied_; }
    const std::string& FilterError() const { return filter_error_; }

    // Once per host frame, main thread.
    void Pump();

    std::size_t Count() const { return packets_.size(); }
    const Packet& At(std::size_t i) const { return packets_[i]; }
    // Indices of packets passing the display filter AND the column filters, in order.
    const std::vector<std::uint32_t>& Displayed() const { return displayed_; }

    // Per-column filters, the Messages view's: one text per column, applied
    // here on the decoded column text (no re-dissection). Empty = all;
    // "!x" excludes x; "=x" is an exact match; on a numeric column (No.,
    // Time, Length) "a-b", ">n", "<n" and "n" are numeric; anything else is a
    // case-insensitive substring. The master switch gates the whole row.
    void SetColumnFilter(std::size_t column, const std::string& text);
    void SetColumnFiltersEnabled(bool on);
    bool ColumnFiltersEnabled() const { return col_filters_on_; }
    const std::vector<std::string>& ColumnFilters() const { return col_filters_; }
    bool AnyColumnFilter() const;
    // Distinct values seen in one column (for the filter cell's dropdown), capped.
    std::vector<std::string> ColumnValues(std::size_t column, std::size_t max = 200) const;
    std::size_t DecodedCount() const { return decoded_; }
    std::size_t PendingCount() const { return pending_; }
    std::uint64_t Generation() const { return generation_; }   // moves on Clear / filter change

    // Details tree for one packet: asynchronous, one at a time.
    void RequestTree(std::uint32_t index);
    // Non-null once the requested packet's tree arrived (and until another is requested).
    const DetailNode* Tree(std::uint32_t index) const {
        return (tree_ready_ && tree_index_ == index) ? &tree_ : nullptr;
    }
    bool TreePending() const { return tree_requested_ && !tree_ready_; }
    const std::string& TreeError() const { return tree_error_; }

    // Wireshark's "Frame" pseudo-fields for a row the columns do not hold.
    static std::uint32_t PackRgb(const std::string& hex);   // "#rrggbb" -> 0xRRGGBB, 0 on error

    // Lookups the view needs for the sort-free list.
    int ColumnIndex(const char* title) const;   // -1 when unknown

private:
    struct Job {
        enum Kind { Decode, Tree, SetFilter, Reset, Stop } kind;
        std::uint32_t index = 0;
        std::shared_ptr<const RawFrame> raw;
        std::shared_ptr<const RawFrame> ref, prev;   // Tree: the timing context
        std::string text;                            // SetFilter
        std::uint64_t generation = 0;
    };
    struct Result {
        enum Kind { Decoded, TreeDone, FilterDone, Disconnected } kind;
        std::uint32_t index = 0;
        std::uint64_t generation = 0;
        DecodeReply reply;
        bool ok = true;
        std::string error;
    };

    void WorkerMain();
    void Post(Job&& j);
    bool ConnectWorkerClients(std::string& error);
    void RequeueAll();
    bool PassesColumnFilters(const Packet& p) const;
    void RebuildDisplayed();

    Logger log_;
    ServerLauncher launcher_;
    DecoderStatus status_;
    std::uint16_t port_ = 0;

    std::vector<Packet> packets_;
    std::vector<std::uint32_t> displayed_;
    std::size_t decoded_ = 0;
    std::size_t pending_ = 0;
    std::uint64_t generation_ = 1;          // the view's: row set changed
    std::uint64_t decode_generation_ = 1;   // the server's: numbering restarted

    std::string filter_applied_, filter_error_, filter_wanted_;
    std::vector<std::string> col_filters_;
    bool col_filters_on_ = true;
    FilterState filter_state_ = FilterState::Empty;

    std::uint32_t tree_index_ = 0;
    bool tree_requested_ = false, tree_ready_ = false;
    DetailNode tree_;
    std::string tree_error_;

    // worker
    std::thread worker_;
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<Job> jobs_;
    std::deque<Result> results_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> worker_connected_{false};
    WirespyClient seq_, tree_client_;   // worker-owned after start
    std::string column_titles_json_;
};

} // namespace radshark
