// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// capture.cpp
#include "capture.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <set>

namespace radshark {

namespace {
constexpr std::size_t kPipeline = 128;   // decodes in flight per round trip
}

Capture::Capture() = default;

Capture::~Capture() {
    stop_ = true;
    {
        std::lock_guard<std::mutex> g(m_);
        jobs_.clear();
        jobs_.push_back(Job{Job::Stop});
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    launcher_.stop();
}

std::uint32_t Capture::PackRgb(const std::string& hex) {
    if (hex.size() != 7 || hex[0] != '#') return 0;
    return (std::uint32_t)std::strtoul(hex.c_str() + 1, nullptr, 16);
}

namespace {

std::string Lower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}
std::string Trim(const std::string& s) {
    const auto a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return {};
    const auto b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}
bool ParseNumber(const std::string& s, double& out) {
    const std::string t = Trim(s);
    if (t.empty()) return false;
    char* end = nullptr;
    out = std::strtod(t.c_str(), &end);
    return end && *end == '\0';
}
bool NumericColumn(const std::string& title) {
    return title == "No." || title == "Time" || title == "Length";
}

// One column's filter against one cell. The Messages view's engine "guesses
// numeric / range / string" from the text; this is that guess, spelled out.
bool CellMatches(const std::string& filterRaw, const std::string& cell, bool numeric) {
    const std::string f = Trim(filterRaw);
    if (f.empty()) return true;
    if (f[0] == '!') return !CellMatches(f.substr(1), cell, numeric);
    if (f[0] == '=') return Lower(Trim(f.substr(1))) == Lower(cell);
    if (numeric) {
        double v = 0.0;
        const bool cellNum = ParseNumber(cell, v);
        double a = 0.0, b = 0.0;
        if (f[0] == '>' && ParseNumber(f.substr(1), a)) return cellNum && v > a;
        if (f[0] == '<' && ParseNumber(f.substr(1), a)) return cellNum && v < a;
        const auto dash = f.find('-', 1);
        if (dash != std::string::npos && ParseNumber(f.substr(0, dash), a) && ParseNumber(f.substr(dash + 1), b))
            return cellNum && v >= std::min(a, b) && v <= std::max(a, b);
        if (ParseNumber(f, a)) return cellNum && v == a;
    }
    return Lower(cell).find(Lower(f)) != std::string::npos;
}

} // namespace

bool Capture::PassesColumnFilters(const Packet& p) const {
    if (!col_filters_on_) return true;
    for (std::size_t c = 0; c < col_filters_.size(); ++c) {
        if (col_filters_[c].empty()) continue;
        const std::string& cell = p.cols.size() > c ? p.cols[c] : std::string();
        const bool numeric = status_.columns.size() > c && NumericColumn(status_.columns[c]);
        if (!CellMatches(col_filters_[c], cell, numeric)) return false;
    }
    return true;
}

bool Capture::AnyColumnFilter() const {
    for (const std::string& f : col_filters_) if (!Trim(f).empty()) return true;
    return false;
}

void Capture::RebuildDisplayed() {
    displayed_.clear();
    for (std::uint32_t i = 0; i < packets_.size(); ++i) {
        const Packet& p = packets_[i];
        if (p.state == Packet::State::Queued) continue;
        if (p.state == Packet::State::Failed || (p.match && PassesColumnFilters(p))) displayed_.push_back(i);
    }
    ++generation_;   // the view's row-to-packet mapping changed; not the server's numbering
}

void Capture::SetColumnFilter(std::size_t column, const std::string& text) {
    if (col_filters_.size() <= column) col_filters_.resize(column + 1);
    if (col_filters_[column] == text) return;
    col_filters_[column] = text;
    RebuildDisplayed();
}

void Capture::SetColumnFiltersEnabled(bool on) {
    if (col_filters_on_ == on) return;
    col_filters_on_ = on;
    RebuildDisplayed();
}

std::vector<std::string> Capture::ColumnValues(std::size_t column, std::size_t max) const {
    std::set<std::string> seen;
    for (const Packet& p : packets_) {
        if (p.cols.size() <= column || p.cols[column].empty()) continue;
        seen.insert(p.cols[column]);
        if (seen.size() >= max) break;
    }
    return std::vector<std::string>(seen.begin(), seen.end());
}

int Capture::ColumnIndex(const char* title) const {
    for (std::size_t i = 0; i < status_.columns.size(); ++i)
        if (status_.columns[i] == title) return (int)i;
    return -1;
}

bool Capture::ConnectWorkerClients(std::string& error) {
    if (!seq_.connect("127.0.0.1", port_, error)) return false;
    if (!tree_client_.connect("127.0.0.1", port_, error)) { seq_.close(); return false; }
    return true;
}

bool Capture::EnsureDecoder(std::string& error) {
    if (status_.ready) return true;
    error.clear();
    if (port_ == 0) {
        port_ = launcher_.ensure(error);
        if (port_ == 0) { status_.text = error; return false; }
    }
    // Probe once from here (the worker owns the sockets afterwards) for the
    // titles the packet list needs before the first frame arrives.
    WirespyClient probe;
    if (!probe.connect("127.0.0.1", port_, error)) { status_.text = error; port_ = 0; return false; }
    nlohmann::json info;
    if (!probe.info(info, error)) { status_.text = "wirespy_server answered badly: " + error; return false; }
    status_.columns.clear();
    if (auto c = info.find("columns"); c != info.end() && c->is_array())
        for (const auto& s : *c) status_.columns.push_back(s.is_string() ? s.get<std::string>() : "");
    status_.wireshark_version = info.value("wireshark", "");
    status_.colors = info.value("colors", false);
    status_.text = "Wireshark " + status_.wireshark_version + " via " +
                   (launcher_.spawned() ? launcher_.description() : "wirespy_server on port " + std::to_string(port_));
    if (!status_.colors) status_.text += " (no colouring rules found)";
    probe.close();

    if (!worker_.joinable()) {
        stop_ = false;
        worker_ = std::thread([this] { WorkerMain(); });
    }
    status_.ready = true;
    if (log_) log_(0, "radshark: " + status_.text);
    return true;
}

void Capture::RestartDecoder() {
    // Tear the worker down, forget the server, start over on the next Ensure.
    stop_ = true;
    {
        std::lock_guard<std::mutex> g(m_);
        jobs_.clear();
        jobs_.push_back(Job{Job::Stop});
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    seq_.close();
    tree_client_.close();
    launcher_.stop();
    port_ = 0;
    status_ = DecoderStatus{};
    worker_connected_ = false;
    {
        std::lock_guard<std::mutex> g(m_);
        results_.clear();
    }
    std::string err;
    if (EnsureDecoder(err)) RequeueAll();
}

void Capture::Post(Job&& j) {
    {
        std::lock_guard<std::mutex> g(m_);
        jobs_.push_back(std::move(j));
    }
    cv_.notify_one();
}

void Capture::AddFrames(std::vector<RawFrame>& frames) {
    packets_.reserve(packets_.size() + frames.size());
    std::vector<Job> batch;
    batch.reserve(frames.size());
    for (RawFrame& f : frames) {
        Packet p;
        p.raw = std::make_shared<const RawFrame>(std::move(f));
        const std::uint32_t index = (std::uint32_t)packets_.size();
        packets_.push_back(std::move(p));
        Job j{Job::Decode};
        j.index = index;
        j.raw = packets_.back().raw;
        j.generation = decode_generation_;
        batch.push_back(std::move(j));
        ++pending_;
    }
    frames.clear();
    if (!batch.empty()) {
        std::lock_guard<std::mutex> g(m_);
        for (Job& j : batch) jobs_.push_back(std::move(j));
        cv_.notify_one();
    }
}

void Capture::Clear() {
    ++generation_;
    ++decode_generation_;
    packets_.clear();
    displayed_.clear();
    decoded_ = 0;
    pending_ = 0;
    tree_requested_ = tree_ready_ = false;
    tree_ = DetailNode{};
    {
        std::lock_guard<std::mutex> g(m_);
        jobs_.clear();
        results_.clear();
        Job r{Job::Reset};
        r.generation = decode_generation_;
        jobs_.push_back(std::move(r));
        // The server's filter outlives its reset, and a SetFilter still in
        // the queue was just dropped: re-send what the user wants so the new
        // capture starts under it (or under none), never under a stale one.
        if (!filter_wanted_.empty() || !filter_applied_.empty()) {
            Job f{Job::SetFilter};
            f.text = filter_wanted_;
            f.generation = decode_generation_;
            jobs_.push_back(std::move(f));
            filter_state_ = filter_wanted_.empty() && filter_applied_.empty() ? FilterState::Empty : FilterState::Pending;
        }
    }
    cv_.notify_one();
}

void Capture::RequeueAll() {
    // Renumber from 1 on the server and dissect everything again, in order.
    ++generation_;
    ++decode_generation_;
    displayed_.clear();
    decoded_ = 0;
    pending_ = packets_.size();
    tree_ready_ = false;
    std::lock_guard<std::mutex> g(m_);
    jobs_.clear();
    results_.clear();
    Job r{Job::Reset};
    r.generation = generation_;
    jobs_.push_back(std::move(r));
    for (std::uint32_t i = 0; i < packets_.size(); ++i) {
        packets_[i].state = Packet::State::Queued;
        Job j{Job::Decode};
        j.index = i;
        j.raw = packets_[i].raw;
        j.generation = decode_generation_;
        jobs_.push_back(std::move(j));
    }
    cv_.notify_one();
}

void Capture::SetFilter(const std::string& text) {
    filter_wanted_ = text;
    filter_state_ = text.empty() && filter_applied_.empty() ? FilterState::Empty : FilterState::Pending;
    Job j{Job::SetFilter};
    j.text = text;
    j.generation = decode_generation_;
    Post(std::move(j));
}

void Capture::RequestTree(std::uint32_t index) {
    if (index >= packets_.size()) return;
    if (tree_requested_ && tree_index_ == index && (tree_ready_ || !tree_ready_)) {
        if (tree_ready_) return;   // already have it
    }
    tree_index_ = index;
    tree_requested_ = true;
    tree_ready_ = false;
    tree_error_.clear();
    Job j{Job::Tree};
    j.index = index;
    j.raw = packets_[index].raw;
    j.ref = packets_[0].raw;
    if (index > 0) j.prev = packets_[index - 1].raw;
    j.generation = decode_generation_;
    Post(std::move(j));
}

void Capture::Pump() {
    std::deque<Result> got;
    {
        std::lock_guard<std::mutex> g(m_);
        got.swap(results_);
    }
    for (Result& r : got) {
        switch (r.kind) {
        case Result::Decoded: {
            if (r.generation != decode_generation_ || r.index >= packets_.size()) break;
            Packet& p = packets_[r.index];
            if (p.state == Packet::State::Queued && pending_ > 0) --pending_;
            if (r.reply.ok) {
                p.state = Packet::State::Decoded;
                p.cols = std::move(r.reply.columns);
                p.match = r.reply.match;
                p.has_color = !r.reply.color_bg.empty();
                p.fg = PackRgb(r.reply.color_fg);
                p.bg = PackRgb(r.reply.color_bg);
                ++decoded_;
                if (p.match && PassesColumnFilters(p)) displayed_.push_back(r.index);
            } else {
                p.state = Packet::State::Failed;
                p.error = r.reply.error;
                p.match = true;
                displayed_.push_back(r.index);
            }
            break;
        }
        case Result::TreeDone:
            if (r.generation != decode_generation_ || !tree_requested_ || r.index != tree_index_) break;
            if (r.reply.ok && r.reply.has_tree) {
                tree_ = std::move(r.reply.tree);
                tree_ready_ = true;
            } else {
                tree_error_ = r.reply.error.empty() ? r.error : r.reply.error;
                tree_ready_ = false;
                tree_requested_ = false;
            }
            break;
        case Result::FilterDone:
            if (r.ok) {
                filter_applied_ = filter_wanted_;
                filter_error_.clear();
                filter_state_ = filter_applied_.empty() ? FilterState::Empty : FilterState::Valid;
                RequeueAll();
            } else {
                filter_error_ = r.error;
                filter_state_ = FilterState::Invalid;
            }
            break;
        case Result::Disconnected:
            status_.ready = false;
            status_.text = "wirespy_server connection lost: " + r.error;
            if (log_) log_(1, "radshark: " + status_.text);
            break;
        }
    }
}

void Capture::WorkerMain() {
    std::string err;
    if (!ConnectWorkerClients(err)) {
        std::lock_guard<std::mutex> g(m_);
        results_.push_back(Result{Result::Disconnected, 0, 0, {}, false, err});
        return;
    }
    worker_connected_ = true;
    std::vector<Job> decodes;
    std::vector<DecodeAsk> asks;
    std::vector<DecodeReply> replies;
    auto fail = [&](const std::string& why) {
        std::lock_guard<std::mutex> g(m_);
        results_.push_back(Result{Result::Disconnected, 0, 0, {}, false, why});
        jobs_.clear();
    };
    while (!stop_) {
        Job first{Job::Stop};
        {
            std::unique_lock<std::mutex> lk(m_);
            cv_.wait(lk, [&] { return stop_ || !jobs_.empty(); });
            if (stop_) break;
            // Trees and control jobs jump the queue: the user is waiting on them.
            auto it = std::find_if(jobs_.begin(), jobs_.end(), [](const Job& j) { return j.kind != Job::Decode; });
            if (it != jobs_.end()) { first = std::move(*it); jobs_.erase(it); }
            else { first = std::move(jobs_.front()); jobs_.pop_front(); }
        }
        switch (first.kind) {
        case Job::Stop:
            return;
        case Job::Reset:
            if (!seq_.reset(err)) { fail(err); return; }
            break;
        case Job::SetFilter: {
            const bool ok = seq_.set_filter(first.text, err);
            if (!seq_.connected()) { fail(err); return; }
            std::lock_guard<std::mutex> g(m_);
            results_.push_back(Result{Result::FilterDone, 0, first.generation, {}, ok, ok ? "" : err});
            break;
        }
        case Job::Tree: {
            // Transient decode on the second connection with the timing the
            // in-order pass had for this frame.
            asks.clear();
            replies.clear();
            DecodeAsk a;
            a.frame = std::span<const std::uint8_t>(first.raw->bytes);
            a.dlt = first.raw->dlt;
            a.has_ts = first.raw->has_ts;
            a.ts_sec = first.raw->ts_sec;
            a.ts_nsec = first.raw->ts_nsec;
            a.tree = true;
            a.columns = true;
            a.color = false;
            a.transient = true;
            a.frame_number = first.index + 1;
            if (first.ref && first.ref->has_ts) { a.has_ref = true; a.ref_ts_sec = first.ref->ts_sec; a.ref_ts_nsec = first.ref->ts_nsec; }
            if (first.prev && first.prev->has_ts) { a.has_prev = true; a.prev_ts_sec = first.prev->ts_sec; a.prev_ts_nsec = first.prev->ts_nsec; }
            asks.push_back(a);
            if (!tree_client_.decode(asks, replies, err)) { fail(err); return; }
            Result r{Result::TreeDone, first.index, first.generation, std::move(replies[0]), true, ""};
            std::lock_guard<std::mutex> g(m_);
            results_.push_back(std::move(r));
            break;
        }
        case Job::Decode: {
            decodes.clear();
            decodes.push_back(std::move(first));
            {
                std::lock_guard<std::mutex> g(m_);
                while (decodes.size() < kPipeline && !jobs_.empty() && jobs_.front().kind == Job::Decode) {
                    decodes.push_back(std::move(jobs_.front()));
                    jobs_.pop_front();
                }
            }
            asks.clear();
            for (const Job& j : decodes) {
                DecodeAsk a;
                a.frame = std::span<const std::uint8_t>(j.raw->bytes);
                a.dlt = j.raw->dlt;
                a.has_ts = j.raw->has_ts;
                a.ts_sec = j.raw->ts_sec;
                a.ts_nsec = j.raw->ts_nsec;
                a.tree = false;
                a.columns = true;
                a.color = true;
                asks.push_back(a);
            }
            replies.clear();
            if (!seq_.decode(asks, replies, err)) { fail(err); return; }
            std::lock_guard<std::mutex> g(m_);
            for (std::size_t i = 0; i < decodes.size(); ++i) {
                results_.push_back(Result{Result::Decoded, decodes[i].index, decodes[i].generation,
                                          std::move(replies[i]), true, ""});
            }
            break;
        }
        }
    }
}

} // namespace radshark
