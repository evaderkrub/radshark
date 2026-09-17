// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#pragma once
#include "shark_view.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <cstdlib>
namespace radshark {
struct Reply {
    std::function<void(const std::string&)> ok, error;
    void Ok(const std::string& value) const { ok(value); }
    void Error(const std::string& value) const { error(value); }
};
class Args {
    nlohmann::json j_;
public:
    explicit Args(std::string_view s) : j_(nlohmann::json::parse(s)) {
        if (!j_.is_object()) throw std::invalid_argument("arguments must be an object");
    }
    bool Has(const char* k) const { return j_.contains(k); }
    std::string String(const char* k, const char* d) const { return j_.value(k,std::string(d)); }
    int64_t Int(const char* k, int64_t d) const { return j_.value(k,d); }
    bool Bool(const char* k, bool d) const { return j_.value(k,d); }
};
inline nlohmann::json TreeJson(const DetailNode& n) {
    nlohmann::json j={{"name",n.name},{"text",n.text},{"pos",n.pos},{"size",n.size}};
    if (!n.children.empty()) { j["children"]=nlohmann::json::array(); for(const auto& c:n.children) j["children"].push_back(TreeJson(c)); }
    return j;
}
class Analyzer {
public:
    void Init(Services s) { services_=std::move(s); view_.Init(services_); }
    void Shutdown() { view_.Shutdown(); }
    void Frame() { view_.OnFrame(services_); }
    void Draw() { view_.Draw(services_); }
    SharkView& View() { return view_; }
    const Services& Host() const { return services_; }
    void StateTool(std::string_view, const Reply& reply) {
        radshark::Capture& cap = view_.capture();
        nlohmann::json j = {
            {"capturing", view_.Capturing()},
            {"source", view_.SourceName()},
            {"file", view_.FilePath()},
            {"packets", cap.Count()},
            {"displayed", cap.Displayed().size()},
            {"dissecting", cap.PendingCount()},
            {"filter", cap.Filter()},
            {"filter_state", FilterStateName(cap.FilterStatus())},
            {"filter_error", cap.FilterError()},
            {"dissector", {{"ready", cap.Decoder().ready}, {"text", cap.Decoder().text}, {"wireshark", cap.Decoder().wireshark_version}}},
            {"columns", cap.Decoder().columns},
            {"column_filters", cap.ColumnFilters()},
            {"column_filters_enabled", cap.ColumnFiltersEnabled()},
            {"selected", view_.Selected() + 1},
            {"last_error", view_.LastError()},
        };
        reply.Ok(j.dump());
    }

    void PacketsTool(std::string_view args, const Reply& reply) {
        Args a(args);
        const int first = (int)a.Int("first", 0);
        const int count = std::min<int>(500, std::max<int>(1, (int)a.Int("count", 100)));
        const bool all = a.Bool("all", false);
        radshark::Capture& cap = view_.capture();
        nlohmann::json rows = nlohmann::json::array();
        const std::size_t total = all ? cap.Count() : cap.Displayed().size();
        for (int r = first; r < first + count && r >= 0 && (std::size_t)r < total; ++r) {
            const std::uint32_t idx = all ? (std::uint32_t)r : cap.Displayed()[(std::size_t)r];
            const radshark::Packet& p = cap.At(idx);
            nlohmann::json row = {{"index", idx}, {"number", idx + 1}, {"columns", p.cols}, {"match", p.match},
                                  {"state", p.state == radshark::Packet::State::Decoded ? "decoded" : p.state == radshark::Packet::State::Failed ? "failed" : "queued"},
                                  {"length", p.raw->bytes.size()}, {"interface", p.raw->iface}, {"transmitted", p.raw->transmitted}};
            if (p.has_color) row["color"] = {{"fg", p.fg}, {"bg", p.bg}};
            if (!p.error.empty()) row["error"] = p.error;
            rows.push_back(std::move(row));
        }
        reply.Ok(nlohmann::json{{"total", total}, {"first", first}, {"columns", cap.Decoder().columns}, {"rows", rows}}.dump());
    }

    void PacketTool(std::string_view args, const Reply& reply) {
        Args a(args);
        const std::int64_t number = a.Int("number", 0);
        radshark::Capture& cap = view_.capture();
        if (number < 1 || (std::size_t)number > cap.Count()) { reply.Error("no such packet"); return; }
        const std::uint32_t idx = (std::uint32_t)(number - 1);
        if (a.Bool("select", false)) view_.Select(idx);
        // The tree is fetched asynchronously: request it, and answer with what
        // is there. A second call a moment later has the tree.
        cap.RequestTree(idx);
        const radshark::Packet& p = cap.At(idx);
        std::string hex;
        hex.reserve(p.raw->bytes.size() * 2);
        static const char* kHex = "0123456789abcdef";
        for (std::uint8_t b : p.raw->bytes) { hex += kHex[b >> 4]; hex += kHex[b & 15]; }
        nlohmann::json j = {{"number", number}, {"columns", p.cols}, {"bytes", hex}, {"interface", p.raw->iface},
                            {"ts_sec", p.raw->ts_sec}, {"ts_nsec", p.raw->ts_nsec}};
        if (const radshark::DetailNode* t = cap.Tree(idx)) j["tree"] = TreeJson(*t);
        else j["tree_pending"] = true;
        reply.Ok(j.dump());
    }

    void FilterTool(std::string_view args, const Reply& reply) {
        Args a(args);
        view_.ApplyFilter(a.String("filter", ""));
        reply.Ok(nlohmann::json{{"ok", true}, {"filter", a.String("filter", "")}}.dump());
    }

    void ColumnFilterTool(std::string_view args, const Reply& reply) {
        Args a(args);
        radshark::Capture& cap = view_.capture();
        if (a.Has("enabled")) { const bool on = a.Bool("enabled", true); cap.SetColumnFiltersEnabled(on); view_.ShowColumnFilters(on); }
        if (a.Has("column")) {
            const std::string col = a.String("column", "");
            int idx = -1;
            for (std::size_t i = 0; i < cap.Decoder().columns.size(); ++i) if (cap.Decoder().columns[i] == col) idx = (int)i;
            if (idx < 0 && !col.empty() && std::isdigit((unsigned char)col[0])) idx = std::atoi(col.c_str());
            if (idx < 0 || (std::size_t)idx >= cap.Decoder().columns.size()) { reply.Error("no such column: " + col); return; }
            cap.SetColumnFilter((std::size_t)idx, a.String("text", ""));
            view_.SyncColumnFilterCells();
        }
        reply.Ok(nlohmann::json{{"ok", true}, {"column_filters", cap.ColumnFilters()}, {"enabled", cap.ColumnFiltersEnabled()},
                                {"displayed", cap.Displayed().size()}}.dump());
    }

    void SaveTool(std::string_view args, const Reply& reply) {
        Args a(args);
        std::string err;
        if (!view_.SaveAs(a.String("path", ""), a.Bool("displayed_only", false), err)) { reply.Error(err); return; }
        reply.Ok(nlohmann::json{{"ok", true}, {"path", a.String("path", "")}}.dump());
    }

    void OpenTool(std::string_view args, const Reply& reply) {
        Args a(args);
        std::string err;
        if (!view_.OpenFile(services_, a.String("path", ""), err)) { reply.Error(err); return; }
        reply.Ok(nlohmann::json{{"ok", true}, {"packets", view_.capture().Count()}}.dump());
    }

    void CaptureTool(std::string_view args, const Reply& reply) {
        Args a(args);
        const std::string action = a.String("action", "");
        if (action == "stop") { view_.StopCapture(); reply.Ok(R"({"ok":true})"); return; }
        if (action != "start") { reply.Error("action must be start or stop"); return; }
        const std::string source = a.String("source", "corelib");
        radshark::SourceKind kind;
        if (source == "corelib") kind = radshark::SourceKind::Corelib;
        else if (source == "libx") kind = radshark::SourceKind::Libx;
        else { reply.Error("refused: \"" + source + "\" opens hardware; start it from the view"); return; }
        std::string err;
        if (!view_.StartCapture(services_, kind, source, err)) { reply.Error(err); return; }
        reply.Ok(nlohmann::json{{"ok", true}, {"source", view_.SourceName()}}.dump());
    }

    void SourcesTool(std::string_view, const Reply& reply) {
        nlohmann::json arr = nlohmann::json::array();
        for (const radshark::SourceEntry& e : view_.AllSources(services_, false)) {
            arr.push_back({{"kind", radshark::SourceKindName(e.kind)}, {"id", e.id}, {"name", e.name},
                           {"description", e.description}, {"available", e.available}, {"reason", e.reason}});
        }
        reply.Ok(arr.dump());
    }

private:
    static const char* FilterStateName(radshark::Capture::FilterState s) {
        switch (s) {
        case radshark::Capture::FilterState::Empty: return "empty";
        case radshark::Capture::FilterState::Pending: return "pending";
        case radshark::Capture::FilterState::Valid: return "valid";
        case radshark::Capture::FilterState::Invalid: return "invalid";
        }
        return "?";
    }
    Services services_;
    SharkView view_;
};
}
