// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// shark_view.cpp -- see shark_view.h.
#include "shark_view.h"
#include "pcap_reader.h"
#include "sources.h"

#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cmath>
#include <functional>
#include <cstdio>
#include <cstring>

#ifdef IMGUI_ENABLE_TEST_ENGINE
extern void ImGuiTestEngineHook_ItemInfo(ImGuiContext*, ImGuiID, const char*, int);
#endif

namespace vspyshark {

namespace {

// ---- Wireshark's colours (ui/qt, light palette) ---------------------------
constexpr ImU32 kFilterValidBg   = IM_COL32(0xaf, 0xff, 0xa8, 0xff);   // prefs.gui_text_valid
constexpr ImU32 kFilterInvalidBg = IM_COL32(0xff, 0xaf, 0xaf, 0xff);   // prefs.gui_text_invalid
constexpr ImU32 kSelectionBg     = IM_COL32(0x30, 0x8c, 0xc6, 0xff);   // QPalette::Highlight (Fusion)
constexpr ImU32 kSelectionFg     = IM_COL32(0xff, 0xff, 0xff, 0xff);
constexpr ImU32 kHeaderBg        = IM_COL32(0xf0, 0xf0, 0xf0, 0xff);
constexpr ImU32 kPaneBg          = IM_COL32(0xff, 0xff, 0xff, 0xff);
constexpr ImU32 kPaneText        = IM_COL32(0x00, 0x00, 0x00, 0xff);
constexpr ImU32 kToolbarBg       = IM_COL32(0xf5, 0xf5, 0xf5, 0xff);
constexpr ImU32 kStatusBg        = IM_COL32(0xef, 0xef, 0xef, 0xff);
constexpr ImU32 kSeparator       = IM_COL32(0xc8, 0xc8, 0xc8, 0xff);
constexpr ImU32 kFinBlue         = IM_COL32(0x1b, 0x6a, 0xc9, 0xff);   // the shark fin
constexpr ImU32 kFinGreen        = IM_COL32(0x2e, 0x9e, 0x44, 0xff);   // restart
constexpr ImU32 kStopRed         = IM_COL32(0xd9, 0x2b, 0x2b, 0xff);
constexpr ImU32 kProtoBytesBg    = IM_COL32(0xc9, 0xdc, 0xf0, 0xff);   // the protocol's span in the bytes pane
constexpr ImU32 kWelcomeLink     = IM_COL32(0x1b, 0x6a, 0xc9, 0xff);
constexpr ImU32 kGrey            = IM_COL32(0x80, 0x80, 0x80, 0xff);

ImU32 Rgb(std::uint32_t rgb) {
    return IM_COL32((rgb >> 16) & 0xff, (rgb >> 8) & 0xff, rgb & 0xff, 0xff);
}

// Default column widths, in characters, from Wireshark's column prefs.
float ColumnCharWidth(const std::string& title) {
    if (title == "No.") return 7.0f;
    if (title == "Time") return 12.0f;
    if (title == "Source" || title == "Destination") return 22.0f;
    if (title == "Protocol") return 10.0f;
    if (title == "Length") return 8.0f;
    return 0.0f;   // stretch (Info)
}

void RegisterCombo(const char* label) {
#ifdef IMGUI_ENABLE_TEST_ENGINE
    if (ImGui::GetCurrentContext()->TestEngineHookItems)
        ImGuiTestEngineHook_ItemInfo(ImGui::GetCurrentContext(), ImGui::GetItemID(), label, 0);
#else
    (void)label;
#endif
}

// A toolbar glyph button drawn by hand (the shark fins and the stop square
// have no icon-font equivalent). Returns true when clicked.
enum class Glyph { StartFin, RestartFin, Stop };
bool GlyphButton(const char* id, Glyph g, bool enabled, float size, const char* tooltip) {
    ImGui::BeginDisabled(!enabled);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const bool clicked = ImGui::InvisibleButton(id, ImVec2(size, size));
    const bool hovered = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (hovered && enabled) dl->AddRectFilled(p, ImVec2(p.x + size, p.y + size), IM_COL32(0xd0, 0xe0, 0xf5, 0xff), 3.0f);
    const float m = size * 0.18f;
    const ImU32 dim = IM_COL32(0xa0, 0xa0, 0xa0, 0xff);
    switch (g) {
    case Glyph::StartFin:
    case Glyph::RestartFin: {
        // Wireshark's fin: a swept triangle, tip to the upper left.
        const ImU32 c = !enabled ? dim : (g == Glyph::StartFin ? kFinBlue : kFinGreen);
        const ImVec2 a(p.x + m, p.y + size - m);
        const ImVec2 b(p.x + size - m, p.y + size - m);
        const ImVec2 t(p.x + size * 0.40f, p.y + m);
        dl->AddTriangleFilled(a, t, b, c);
        dl->AddBezierQuadratic(a, ImVec2(p.x + size * 0.28f, p.y + size * 0.45f), t, c, 2.0f);
        if (g == Glyph::RestartFin) {
            dl->AddCircle(ImVec2(p.x + size - m * 0.9f, p.y + m * 1.1f), size * 0.16f, c, 12, 2.0f);
        }
        break;
    }
    case Glyph::Stop:
        dl->AddRectFilled(ImVec2(p.x + m, p.y + m), ImVec2(p.x + size - m, p.y + size - m), enabled ? kStopRed : dim, 2.0f);
        break;
    }
    ImGui::EndDisabled();
    if (hovered && tooltip && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) ImGui::SetTooltip("%s", tooltip);
    return clicked && enabled;
}

bool IconButton(const Services& host, const char* id, Icon icon, const char* fallback,
                bool enabled, float size, const char* tooltip, bool toggled = false) {
    const std::string_view glyph = host.Icon(icon);
    std::string label(glyph.empty() ? std::string_view(fallback) : glyph);
    label += "###";
    label += id;
    ImGui::BeginDisabled(!enabled);
    // A checkable action reads as pressed-in while on: filled, with a border.
    ImGui::PushStyleColor(ImGuiCol_Button, toggled ? IM_COL32(0xb8, 0xd0, 0xf0, 0xff) : IM_COL32(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_Border, toggled ? IM_COL32(0x6f, 0x9c, 0xd3, 0xff) : IM_COL32(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, toggled ? 1.0f : 0.0f);
    const bool clicked = ImGui::Button(label.c_str(), ImVec2(size, size));
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_ForTooltip) && tooltip) ImGui::SetTooltip("%s", tooltip);
    return clicked && enabled;
}

void ToolbarSeparator(float h) {
    ImGui::SameLine(0.0f, 6.0f);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddLine(ImVec2(p.x, p.y + 3.0f), ImVec2(p.x, p.y + h - 3.0f), kSeparator);
    ImGui::Dummy(ImVec2(1.0f, h));
    ImGui::SameLine(0.0f, 6.0f);
}

std::string Trim(const std::string& s) {
    const auto a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return {};
    const auto b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

std::string Join(const std::vector<std::string>& v, char sep) {
    std::string s;
    for (const std::string& x : v) { if (!s.empty()) s += sep; s += x; }
    return s;
}
std::vector<std::string> Split(std::string_view s, char sep) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= s.size()) {
        const auto k = s.find(sep, start);
        const std::string_view part = s.substr(start, k == std::string_view::npos ? std::string_view::npos : k - start);
        if (!part.empty()) out.emplace_back(part);
        if (k == std::string_view::npos) break;
        start = k + 1;
    }
    return out;
}

} // namespace

// ===========================================================================
// lifecycle
// ===========================================================================
float SharkView::K() const { return ImGui::GetFontSize() / 13.0f; }

void SharkView::Init(const Services& host) {
    host_ = host;
    list_h_ = (float)host.SettingsGetNumber("layout.list_h", 300.0);
    details_h_ = (float)host.SettingsGetNumber("layout.details_h", 200.0);
    autoscroll_ = host.SettingsGetNumber("view.autoscroll", 1.0) != 0.0;
    colorize_ = host.SettingsGetNumber("view.colorize", 1.0) != 0.0;
    zoom_ = (float)host.SettingsGetNumber("view.zoom", 1.0);
    promisc_ = host.SettingsGetNumber("capture.promisc", 1.0) != 0.0;
    recent_ = Split(host.SettingsGet("recent"), '\n');
    col_filters_shown_ = host.SettingsGetNumber("view.colfilters", 0.0) != 0.0;
    cap_.SetColumnFiltersEnabled(col_filters_shown_);
    {
        // Per-column filters persist per user, one setting per column index.
        std::vector<std::string> f;
        for (int i = 0; i < 16; ++i) {
            const std::string_view v = host.SettingsGet(("colfilter." + std::to_string(i)).c_str());
            if (!v.empty()) { f.resize((std::size_t)i + 1); f[(std::size_t)i] = std::string(v); }
        }
        for (std::size_t i = 0; i < f.size(); ++i) cap_.SetColumnFilter(i, f[i]);
    }
    cap_.SetLogger([h = host](int level, const std::string& m) {
        if (level == 0) h.LogInfo(m); else if (level == 1) h.LogWarn(m); else h.LogError(m);
    });
}

void SharkView::SaveLayout(const Services& host) {
    host.SettingsSetNumber("layout.list_h", list_h_);
    host.SettingsSetNumber("layout.details_h", details_h_);
    host.SettingsSetNumber("view.autoscroll", autoscroll_ ? 1.0 : 0.0);
    host.SettingsSetNumber("view.colorize", colorize_ ? 1.0 : 0.0);
    host.SettingsSetNumber("view.zoom", zoom_);
    host.SettingsSetNumber("capture.promisc", promisc_ ? 1.0 : 0.0);
    host.SettingsSetNumber("view.colfilters", col_filters_shown_ ? 1.0 : 0.0);
    const std::vector<std::string>& f = cap_.ColumnFilters();
    for (int i = 0; i < 16; ++i) {
        const std::string v = (std::size_t)i < f.size() ? f[(std::size_t)i] : std::string();
        host.SettingsSet(("colfilter." + std::to_string(i)).c_str(), v.c_str());
    }
}

void SharkView::Shutdown() {
    StopCapture();
    SaveLayout(host_);
}


void SharkView::OnFrame(const Services& host) {
    if (selected_ >= 0 && cap_.Generation() != tree_gen_) {
        // The displayed row set changed (filter, column filter): the packet
        // keeps its selection, its row is looked up again.
        tree_gen_ = cap_.Generation();
        selected_row_ = -1;
        const auto& d = cap_.Displayed();
        for (std::size_t r = 0; r < d.size(); ++r) if (d[r] == (std::uint32_t)selected_) { selected_row_ = (int)r; break; }
    }
    if (src_) {
        incoming_.clear();
        src_->poll(incoming_);
        if (!incoming_.empty()) {
            frames_in_ += incoming_.size();
            cap_.AddFrames(incoming_);
        }
        if (src_->finished() && stop_when_drained_) { src_->stop(); }
    }
    cap_.Pump();
    PumpFileDialogs(host);
}

// ===========================================================================
// capture control
// ===========================================================================
void SharkView::NewCapture() {
    saved_note_.clear();
    cap_.Clear();
    selected_ = selected_row_ = -1;
    field_name_.clear();
    field_text_.clear();
    hl_pos_ = proto_pos_ = -1;
    hl_size_ = proto_size_ = 0;
    last_seen_count_ = 0;
    frames_in_ = 0;
}

bool SharkView::OpenFile(const Services& host, const std::string& path, std::string& error) {
    std::string derr;
    if (!cap_.EnsureDecoder(derr)) { error = derr; last_error_ = error; return false; }
    std::unique_ptr<FrameSource> s = OpenFileSource(path, error);
    if (!s) { last_error_ = error; return false; }
    StopCapture();
    NewCapture();
    src_ = std::move(s);
    stop_when_drained_ = true;
    file_path_ = path;
    if (!src_->start(error)) { last_error_ = error; src_.reset(); return false; }
    PushRecent(host, path);
    return true;
}

bool SharkView::StartCapture(const Services& host, SourceKind kind, const std::string& id, std::string& error) {
    std::string derr;
    if (!cap_.EnsureDecoder(derr)) { error = derr; last_error_ = error; return false; }
    std::unique_ptr<FrameSource> s;
    switch (kind) {
    case SourceKind::File: return OpenFile(host, id, error);
    case SourceKind::LocalInterface: s = OpenLocalInterface(id, promisc_, bpf_buf_); break;
    case SourceKind::Corelib:
    case SourceKind::Libx: if (host.open_source) s = host.open_source(kind, id); break;
    case SourceKind::Icsneo: s = OpenIcsneoDevice(id); break;
    }
    if (!s) { error = std::string(SourceKindName(kind)) + ": not available in this build, or no such source \"" + id + "\""; last_error_ = error; return false; }
    StopCapture();
    NewCapture();
    file_path_.clear();
    src_ = std::move(s);
    stop_when_drained_ = false;
    if (!src_->start(error)) { last_error_ = error; src_.reset(); return false; }
    host.SettingsSetNumber("capture.kind", (double)(int)kind);
    host.SettingsSet("capture.id", id.c_str());
    return true;
}

void SharkView::StopCapture() {
    if (src_) src_->stop();
    // The frames stay; a File source is simply spent.
    if (src_ && src_->kind() != SourceKind::File) src_.reset();
}

void SharkView::ApplyFilter(const std::string& text) {
    std::snprintf(filter_buf_, sizeof filter_buf_, "%s", text.c_str());
    std::string derr;
    if (!cap_.EnsureDecoder(derr)) return;
    cap_.SetFilter(text);
    host_.SettingsSet("filter.last", text.c_str());
}

void SharkView::Select(std::uint32_t index) {
    const auto& d = cap_.Displayed();
    for (std::size_t r = 0; r < d.size(); ++r) if (d[r] == index) { SelectDisplayedRow((int)r); return; }
}

void SharkView::SelectDisplayedRow(int row) {
    const auto& d = cap_.Displayed();
    if (row < 0 || row >= (int)d.size()) return;
    selected_row_ = row;
    selected_ = (int)d[(std::size_t)row];
    field_name_.clear();
    field_text_.clear();
    hl_pos_ = proto_pos_ = -1;
    hl_size_ = proto_size_ = 0;
    cap_.RequestTree((std::uint32_t)selected_);
}

bool SharkView::SaveAs(const std::string& path, bool displayed_only, std::string& error) {
    std::vector<const RawFrame*> frames;
    int dlt = 1;
    if (displayed_only) {
        for (std::uint32_t i : cap_.Displayed()) frames.push_back(cap_.At(i).raw.get());
    } else {
        for (std::size_t i = 0; i < cap_.Count(); ++i) frames.push_back(cap_.At(i).raw.get());
    }
    if (!frames.empty()) dlt = frames.front()->dlt;
    return WritePcap(path, frames, dlt, error);
}

std::vector<SourceEntry> SharkView::AllSources(const Services& host, bool rescan) {
    std::vector<SourceEntry> all;
    for (auto& e : ListLocalInterfaces()) all.push_back(e);
    if (host.list_sources) for (auto& e : host.list_sources()) all.push_back(e);
    for (auto& e : ListIcsneoDevices(rescan)) all.push_back(e);
    return all;
}

void SharkView::StartEntry(const Services& host, const SourceEntry& e) {
    if (!e.available) { last_error_ = e.reason; return; }
    std::string err;
    if (!StartCapture(host, e.kind, e.id, err)) last_error_ = err;
    else last_error_.clear();
}

void SharkView::PushRecent(const Services& host, const std::string& path) {
    recent_.erase(std::remove(recent_.begin(), recent_.end(), path), recent_.end());
    recent_.insert(recent_.begin(), path);
    if (recent_.size() > 10) recent_.resize(10);
    host.SettingsSet("recent", Join(recent_, '\n').c_str());
}

void SharkView::PumpFileDialogs(const Services& host) {
    std::string_view path;
    int32_t tag = 0;
    const FileDialogState st = host.FileDialogResult(path, tag);
    if (st != FileDialogState::Picked) return;
    std::string err;
    if (tag == 1) {
        if (!OpenFile(host, std::string(path), err)) last_error_ = err;
    } else if (tag == 2 || tag == 3) {
        if (!SaveAs(std::string(path), tag == 3, err)) last_error_ = err;
        else { last_error_.clear(); saved_note_ = "Saved " + std::string(path); }
    }
}

// ===========================================================================
// the window
// ===========================================================================
void SharkView::Draw(const Services& host) {
    ImGui::SetWindowFontScale(zoom_);
    if (!decoder_tried_) {
        decoder_tried_ = true;
        std::string err;
        cap_.EnsureDecoder(err);
        const std::string_view last = host.SettingsGet("filter.last");
        if (!last.empty()) ApplyFilter(std::string(last));
    }
    // Wireshark is a light application whatever the host theme is.
    ImGui::PushStyleColor(ImGuiCol_Text, kPaneText);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, kPaneBg);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, kPaneBg);
    ImGui::PushStyleColor(ImGuiCol_Header, kSelectionBg);
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, IM_COL32(0x4a, 0x9b, 0xe0, 0xff));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive, kSelectionBg);
    ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, kHeaderBg);
    ImGui::PushStyleColor(ImGuiCol_TableBorderLight, kSeparator);
    ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, kSeparator);
    ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(0xe6, 0xe6, 0xe6, 0xff));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(0xd0, 0xe0, 0xf5, 0xff));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(0xb8, 0xd0, 0xf0, 0xff));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, IM_COL32(0xfa, 0xfa, 0xfa, 0xff));
    ImGui::PushStyleColor(ImGuiCol_CheckMark, kFinBlue);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 2.0f);

    DrawMenuBar(host);
    DrawToolbar(host);
    DrawFilterBar(host);

    const float status_h = ImGui::GetFrameHeight() + 4.0f * K();
    // Four items follow (up to three panes and the status bar): their
    // ItemSpacing is part of the height budget, or the window scrolls.
    const float avail = ImGui::GetContentRegionAvail().y - status_h - ImGui::GetStyle().ItemSpacing.y * 4.0f;
    const bool welcome = cap_.Count() == 0 && !src_ && file_path_.empty();
    if (welcome) {
        DrawWelcome(host);
    } else {
        // Three panes stacked, two draggable dividers (Wireshark's default
        // layout: list over details over bytes). Each divider is drawn
        // BETWEEN its two panes: the host's horizontal splitter clamps the
        // pane above against the room left at the point it is called, and
        // the drag it reports lands in the stored height for the next frame.
        const int shown = (show_list_ ? 1 : 0) + (show_details_ ? 1 : 0) + (show_bytes_ ? 1 : 0);
        if (shown == 0) {
            ImGui::Dummy(ImVec2(0, avail));
        } else {
            const float min_pane = 40.0f * K();
            const bool below_list = show_details_ || show_bytes_;
            const bool below_details = show_bytes_;
            float list_h = avail;
            if (show_list_) {
                if (below_list) {
                    const float others = (show_details_ ? min_pane : 0.0f) + (show_bytes_ ? min_pane : 0.0f);
                    list_h = std::clamp(list_h_, min_pane, std::max(min_pane, avail - others));
                }
                DrawPacketList(host, list_h);
                if (below_list) {
                    float h = list_h;
                    host.Splitter("###cs_split1", h, avail, min_pane, min_pane, false);
                    list_h_ = h;
                }
            }
            if (show_details_) {
                float details_h = ImGui::GetContentRegionAvail().y - status_h;
                if (below_details) details_h = std::clamp(details_h_, min_pane, std::max(min_pane, details_h - min_pane));
                DrawDetails(host, details_h);
                if (below_details) {
                    float h = details_h;
                    host.Splitter("###cs_split2", h, 0.0f, min_pane, min_pane, false);
                    details_h_ = h;
                }
            }
            if (show_bytes_) DrawBytes(host, ImGui::GetContentRegionAvail().y - status_h);
        }
    }
    DrawStatusBar(host);

    DrawCaptureOptions(host);
    DrawGoTo();
    DrawFind();
    DrawAbout(host);
    DrawFileProperties();

    ImGui::PopStyleVar();
    ImGui::PopStyleColor(14);
    ImGui::SetWindowFontScale(1.0f);
}

// ---------------------------------------------------------------------------
// menu bar (Wireshark's menus, the entries this view has)
// ---------------------------------------------------------------------------
void SharkView::DrawMenuBar(const Services& host) {
    if (!ImGui::BeginMenuBar()) return;
    const bool have = cap_.Count() > 0;
    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open...", "Ctrl+O")) host.OpenFileDialog("Capture files", "pcap;pcapng;cap", 1);
        if (ImGui::BeginMenu("Open Recent", !recent_.empty())) {
            for (const std::string& r : recent_) {
                if (ImGui::MenuItem(r.c_str())) { std::string e; if (!OpenFile(host, r, e)) last_error_ = e; }
            }
            ImGui::EndMenu();
        }
        if (ImGui::MenuItem("Close", "Ctrl+W", false, have || src_ != nullptr)) { StopCapture(); src_.reset(); NewCapture(); file_path_.clear(); }
        ImGui::Separator();
        if (ImGui::MenuItem("Save As...", "Ctrl+Shift+S", false, have)) host.OpenFileDialog("Capture files", "pcap;pcapng", 2, true);
        if (ImGui::MenuItem("Export Specified Packets... (displayed)", nullptr, false, have)) host.OpenFileDialog("Capture files", "pcap;pcapng", 3, true);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Edit")) {
        if (ImGui::MenuItem("Find Packet...", "Ctrl+F", false, have)) show_find_ = true;
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("Packet List", nullptr, &show_list_);
        ImGui::MenuItem("Packet Details", nullptr, &show_details_);
        ImGui::MenuItem("Packet Bytes", nullptr, &show_bytes_);
        ImGui::Separator();
        ImGui::MenuItem("Colorize Packet List", nullptr, &colorize_);
        ImGui::MenuItem("Auto Scroll in Live Capture", nullptr, &autoscroll_);
        if (ImGui::MenuItem("Column Filters", "F", &col_filters_shown_)) cap_.SetColumnFiltersEnabled(col_filters_shown_);
        ImGui::Separator();
        if (ImGui::MenuItem("Zoom In", "Ctrl++")) zoom_ = std::min(2.5f, zoom_ + 0.1f);
        if (ImGui::MenuItem("Zoom Out", "Ctrl+-")) zoom_ = std::max(0.6f, zoom_ - 0.1f);
        if (ImGui::MenuItem("Normal Size", "Ctrl+0")) zoom_ = 1.0f;
        ImGui::Separator();
        if (ImGui::MenuItem("Reload", "Ctrl+R", false, !file_path_.empty())) { std::string e; OpenFile(host, file_path_, e); }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Go")) {
        if (ImGui::MenuItem("Go to Packet...", "Ctrl+G", false, have)) show_goto_ = true;
        if (ImGui::MenuItem("First Packet", "Ctrl+Home", false, have)) { SelectDisplayedRow(0); ScrollToSelected(); }
        if (ImGui::MenuItem("Last Packet", "Ctrl+End", false, have)) { SelectDisplayedRow((int)cap_.Displayed().size() - 1); ScrollToSelected(); }
        if (ImGui::MenuItem("Previous Packet", "Ctrl+Up", false, selected_row_ > 0)) { SelectDisplayedRow(selected_row_ - 1); ScrollToSelected(); }
        if (ImGui::MenuItem("Next Packet", "Ctrl+Down", false, have)) { SelectDisplayedRow(selected_row_ + 1); ScrollToSelected(); }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Capture")) {
        if (ImGui::MenuItem("Options...", "Ctrl+K")) { show_options_ = true; entries_at_ = -1.0; }
        if (ImGui::MenuItem("Start", "Ctrl+E", false, !Capturing())) {
            const int kind = (int)host.SettingsGetNumber("capture.kind", -1.0);
            const std::string id(host.SettingsGet("capture.id"));
            if (kind < 0) { show_options_ = true; entries_at_ = -1.0; }
            else { std::string e; if (!StartCapture(host, (SourceKind)kind, id, e)) last_error_ = e; }
        }
        if (ImGui::MenuItem("Stop", "Ctrl+E", false, Capturing())) StopCapture();
        if (ImGui::MenuItem("Restart", "Ctrl+R", false, src_ != nullptr)) {
            const int kind = (int)host.SettingsGetNumber("capture.kind", -1.0);
            const std::string id(host.SettingsGet("capture.id"));
            std::string e;
            if (!file_path_.empty()) OpenFile(host, file_path_, e);
            else if (kind >= 0) StartCapture(host, (SourceKind)kind, id, e);
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Restart dissector (wirespy_server)")) cap_.RestartDecoder();
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Analyze")) {
        if (ImGui::MenuItem("Apply Display Filter", "Enter")) ApplyFilter(filter_buf_);
        if (ImGui::MenuItem("Clear Display Filter", nullptr, false, !cap_.Filter().empty() || filter_buf_[0])) ApplyFilter("");
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Statistics")) {
        if (ImGui::MenuItem("Capture File Properties", "Ctrl+Alt+Shift+C", false, have)) show_props_ = true;
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("Contents", "F1")) host.OpenDoc("index");
        if (ImGui::MenuItem("About VSpy Shark")) show_about_ = true;
        ImGui::EndMenu();
    }
    ImGui::EndMenuBar();
}

// ---------------------------------------------------------------------------
// main toolbar
// ---------------------------------------------------------------------------
void SharkView::DrawToolbar(const Services& host) {
    const float h = ImGui::GetFrameHeight() + 6.0f * K();
    const float bs = ImGui::GetFrameHeight() + 2.0f * K();
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddRectFilled(p, ImVec2(p.x + ImGui::GetContentRegionAvail().x, p.y + h), kToolbarBg);
    ImGui::SetCursorScreenPos(ImVec2(p.x + 4.0f * K(), p.y + 3.0f * K()));
    ImGui::BeginGroup();
    const bool have = cap_.Count() > 0;
    const bool capturing = Capturing();
    if (GlyphButton("###cs_start", Glyph::StartFin, !capturing, bs, "Start capturing packets")) {
        const int kind = (int)host.SettingsGetNumber("capture.kind", -1.0);
        const std::string id(host.SettingsGet("capture.id"));
        if (kind < 0) { show_options_ = true; entries_at_ = -1.0; }
        else { std::string e; if (!StartCapture(host, (SourceKind)kind, id, e)) last_error_ = e; }
    }
    ImGui::SameLine(0.0f, 2.0f);
    if (GlyphButton("###cs_stop", Glyph::Stop, capturing, bs, "Stop capturing packets")) StopCapture();
    ImGui::SameLine(0.0f, 2.0f);
    if (GlyphButton("###cs_restart", Glyph::RestartFin, src_ != nullptr, bs, "Restart current capture")) {
        std::string e;
        if (!file_path_.empty()) OpenFile(host, file_path_, e);
        else { const int kind = (int)host.SettingsGetNumber("capture.kind", -1.0); if (kind >= 0) StartCapture(host, (SourceKind)kind, std::string(host.SettingsGet("capture.id")), e); }
    }
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_options", Icon::SETTINGS, "*", true, bs, "Capture options...")) { show_options_ = true; entries_at_ = -1.0; }
    ToolbarSeparator(bs);
    if (IconButton(host, "cs_open", Icon::OPEN, "O", true, bs, "Open a capture file")) host.OpenFileDialog("Capture files", "pcap;pcapng;cap", 1);
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_save", Icon::SAVE, "S", have, bs, "Save this capture file")) host.OpenFileDialog("Capture files", "pcap;pcapng", 2, true);
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_close", Icon::CLOSE, "X", have || src_ != nullptr, bs, "Close this capture file")) { StopCapture(); src_.reset(); NewCapture(); file_path_.clear(); }
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_reload", Icon::REFRESH, "R", !file_path_.empty(), bs, "Reload this file")) { std::string e; OpenFile(host, file_path_, e); }
    ToolbarSeparator(bs);
    if (IconButton(host, "cs_find", Icon::SEARCH, "?", have, bs, "Find a packet")) show_find_ = true;
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_goto", Icon::LINK, "#", have, bs, "Go to specified packet")) show_goto_ = true;
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_first", Icon::ARROW_UP, "^", have, bs, "Go to the first packet")) { SelectDisplayedRow(0); ScrollToSelected(); }
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_last", Icon::ARROW_DOWN, "v", have, bs, "Go to the last packet")) { SelectDisplayedRow((int)cap_.Displayed().size() - 1); ScrollToSelected(); }
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_autoscroll", Icon::DOWNLOAD, "A", true, bs,
                   autoscroll_ ? "Auto scroll is ON: the list follows the last packet during a live capture (click to stop)"
                               : "Auto scroll is OFF (click to follow the last packet during a live capture)",
                   autoscroll_)) autoscroll_ = !autoscroll_;
    ToolbarSeparator(bs);
    if (IconButton(host, "cs_colorize", Icon::CHART, "C", true, bs, "Colorize packet list", colorize_)) colorize_ = !colorize_;
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_colfilters", Icon::FILTER, "F", true, bs,
                   col_filters_shown_ ? "Column filters are ON: the row under the header filters each column, as in the Messages view (click to turn off)"
                                      : "Column filters are OFF (click to show the per-column filter row)",
                   col_filters_shown_)) {
        col_filters_shown_ = !col_filters_shown_;
        cap_.SetColumnFiltersEnabled(col_filters_shown_);
    }
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_zoomin", Icon::ADD, "+", true, bs, "Zoom in")) zoom_ = std::min(2.5f, zoom_ + 0.1f);
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_zoomout", Icon::NONE, "-", true, bs, "Zoom out")) zoom_ = std::max(0.6f, zoom_ - 0.1f);
    ImGui::SameLine(0.0f, 2.0f);
    if (IconButton(host, "cs_zoom1", Icon::NONE, "1:1", true, bs * 1.4f, "Normal size")) zoom_ = 1.0f;
    ImGui::EndGroup();
    // The bar's full extent, claimed the way ImGui wants it claimed (a Dummy,
    // never a cursor moved past the content boundary).
    ImGui::SetCursorScreenPos(p);
    ImGui::Dummy(ImVec2(ImGui::GetContentRegionAvail().x, h));
}

// ---------------------------------------------------------------------------
// display filter bar
// ---------------------------------------------------------------------------
void SharkView::DrawFilterBar(const Services& host) {
    (void)host;
    const float k = K();
    const float h = ImGui::GetFrameHeight() + 6.0f * k;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float w = ImGui::GetContentRegionAvail().x;
    ImGui::GetWindowDrawList()->AddRectFilled(p, ImVec2(p.x + w, p.y + h), kToolbarBg);
    ImGui::SetCursorScreenPos(ImVec2(p.x + 4.0f * k, p.y + 3.0f * k));
    // The bookmark ribbon at the left edge.
    {
        const ImVec2 b = ImGui::GetCursorScreenPos();
        const float bh = ImGui::GetFrameHeight();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const float bw = bh * 0.55f;
        const ImVec2 pts[5] = {ImVec2(b.x + 2, b.y + 2), ImVec2(b.x + 2 + bw, b.y + 2), ImVec2(b.x + 2 + bw, b.y + bh - 2),
                               ImVec2(b.x + 2 + bw * 0.5f, b.y + bh * 0.7f), ImVec2(b.x + 2, b.y + bh - 2)};
        dl->AddConvexPolyFilled(pts, 5, kFinBlue);
        ImGui::Dummy(ImVec2(bw + 6.0f, bh));
        ImGui::SameLine(0.0f, 4.0f);
    }
    ImU32 bg = kPaneBg;
    const char* tip = nullptr;
    switch (cap_.FilterStatus()) {
    case Capture::FilterState::Valid: bg = kFilterValidBg; break;
    case Capture::FilterState::Invalid: bg = kFilterInvalidBg; tip = cap_.FilterError().c_str(); break;
    case Capture::FilterState::Pending: bg = IM_COL32(0xff, 0xff, 0xa8, 0xff); break;
    case Capture::FilterState::Empty: break;
    }
    // Typing since the last apply: white again until Enter, like Wireshark's
    // live syntax check would recolour it.
    if (std::string_view(filter_buf_) != cap_.Filter() && cap_.FilterStatus() != Capture::FilterState::Invalid) bg = kPaneBg;
    ImGui::PushStyleColor(ImGuiCol_FrameBg, bg);
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, bg);
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, bg);
    const float right = ImGui::GetFrameHeight() * 2.0f + 12.0f * k + ImGui::CalcTextSize("Apply a display filter ...").x * 0.0f;
    ImGui::SetNextItemWidth(std::max(80.0f, w - (ImGui::GetCursorScreenPos().x - p.x) - right - ImGui::GetFrameHeight() * 2.6f));
    if (filter_focus_) { ImGui::SetKeyboardFocusHere(); filter_focus_ = false; }
    const bool entered = ImGui::InputTextWithHint("###cs_filter", "Apply a display filter ... <Ctrl-/>",
                                                  filter_buf_, sizeof filter_buf_, ImGuiInputTextFlags_EnterReturnsTrue);
    const bool active = ImGui::IsItemActive() || ImGui::IsItemDeactivated();
    if (entered || (active && ImGui::IsKeyPressed(ImGuiKey_Enter))) ApplyFilter(filter_buf_);   // trap 18
    if (tip && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) ImGui::SetTooltip("%s", tip);
    ImGui::PopStyleColor(3);
    ImGui::SameLine(0.0f, 2.0f);
    {
        const std::string_view g = host.Icon(Icon::ARROW_RIGHT);
        std::string l(g.empty() ? std::string_view("->") : g);
        l += "###cs_filter_apply";
        if (ImGui::Button(l.c_str(), ImVec2(ImGui::GetFrameHeight(), ImGui::GetFrameHeight()))) ApplyFilter(filter_buf_);
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) ImGui::SetTooltip("Apply this filter string to the display");
    }
    ImGui::SameLine(0.0f, 2.0f);
    {
        const std::string_view g = host.Icon(Icon::CLOSE);
        std::string l(g.empty() ? std::string_view("x") : g);
        l += "###cs_filter_clear";
        if (ImGui::Button(l.c_str(), ImVec2(ImGui::GetFrameHeight(), ImGui::GetFrameHeight()))) ApplyFilter("");
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) ImGui::SetTooltip("Clear the display filter");
    }
    // Ctrl-/ focuses the bar, as in Wireshark.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Slash)) filter_focus_ = true;
    ImGui::SetCursorScreenPos(p);
    ImGui::Dummy(ImVec2(w, h));
}

// ---------------------------------------------------------------------------
// welcome page
// ---------------------------------------------------------------------------
void SharkView::DrawWelcome(const Services& host) {
    const float k = K();
    const float status_h = ImGui::GetFrameHeight() + 4.0f * k;
    ImGui::BeginChild("##cs_welcome", ImVec2(0, ImGui::GetContentRegionAvail().y - status_h - ImGui::GetStyle().ItemSpacing.y * 2.0f), ImGuiChildFlags_None);
    const double now = ImGui::GetTime();
    if (entries_at_ < 0.0 || now - entries_at_ > 5.0) { entries_ = AllSources(host, false); entries_at_ = now; }

    ImGui::Dummy(ImVec2(0, 12.0f * k));
    ImGui::Indent(24.0f * k);
    host.PushFont(Font::Bold);
    ImGui::SetWindowFontScale(zoom_ * 1.6f);
    TextMarked("###cs_welcome_title", "Welcome to VSpy Shark");
    ImGui::SetWindowFontScale(zoom_);
    host.PopFont();
    ImGui::Dummy(ImVec2(0, 10.0f * k));

    host.PushFont(Font::Bold);
    ImGui::SetWindowFontScale(zoom_ * 1.2f);
    ImGui::TextUnformatted("Open");
    ImGui::SetWindowFontScale(zoom_);
    host.PopFont();
    ImGui::Indent(12.0f * k);
    if (recent_.empty()) {
        ImGui::TextDisabled("No recent files. Use File > Open... to open a capture file.");
    }
    for (const std::string& r : recent_) {
        ImGui::PushStyleColor(ImGuiCol_Text, kWelcomeLink);
        if (ImGui::Selectable(r.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) {
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) { std::string e; if (!OpenFile(host, r, e)) last_error_ = e; }
        }
        ImGui::PopStyleColor();
    }
    ImGui::Unindent(12.0f * k);
    ImGui::Dummy(ImVec2(0, 10.0f * k));

    host.PushFont(Font::Bold);
    ImGui::SetWindowFontScale(zoom_ * 1.2f);
    ImGui::TextUnformatted("Capture");
    ImGui::SetWindowFontScale(zoom_);
    host.PopFont();
    ImGui::Indent(12.0f * k);
    ImGui::TextUnformatted("...using this filter:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(300.0f * k);
    ImGui::InputTextWithHint("###cs_welcome_bpf", "Enter a capture filter ...", bpf_buf_, sizeof bpf_buf_);
    ImGui::SameLine();
    if (ImGui::Button("Refresh###cs_welcome_refresh")) { entries_ = AllSources(host, true); entries_at_ = now; }
    ImGui::Dummy(ImVec2(0, 4.0f * k));

    if (ImGui::BeginTable("##cs_welcome_ifaces", 2, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoBordersInBody)) {
        ImGui::TableSetupColumn("Interface", ImGuiTableColumnFlags_WidthStretch, 0.55f);
        ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 0.45f);
        SourceKind last = SourceKind::File;
        bool first = true;
        int n = 0;
        for (const SourceEntry& e : entries_) {
            if (first || e.kind != last) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", SourceKindName(e.kind));
                first = false;
                last = e.kind;
            }
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            std::string label = e.name + "###cs_src" + std::to_string(n++);
            ImGui::BeginDisabled(!e.available);
            if (ImGui::Selectable(label.c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) StartEntry(host, e);
            }
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_ForTooltip)) {
                if (!e.available) ImGui::SetTooltip("%s", e.reason.c_str());
                else ImGui::SetTooltip("Double-click to start capturing from %s", e.name.c_str());
            }
            ImGui::TableNextColumn();
            // The sparkline Wireshark draws per interface: a flat line here.
            const ImVec2 q = ImGui::GetCursorScreenPos();
            const float lw = 90.0f * k;
            ImGui::GetWindowDrawList()->AddLine(ImVec2(q.x, q.y + ImGui::GetTextLineHeight() * 0.6f), ImVec2(q.x + lw, q.y + ImGui::GetTextLineHeight() * 0.6f), kGrey, 1.0f);
            ImGui::Dummy(ImVec2(lw, ImGui::GetTextLineHeight()));
            ImGui::SameLine();
            if (e.available) ImGui::TextUnformatted(e.description.c_str());
            else ImGui::TextDisabled("%s", e.reason.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::Unindent(12.0f * k);
    ImGui::Dummy(ImVec2(0, 10.0f * k));

    host.PushFont(Font::Bold);
    ImGui::SetWindowFontScale(zoom_ * 1.2f);
    ImGui::TextUnformatted("Learn");
    ImGui::SetWindowFontScale(zoom_);
    host.PopFont();
    ImGui::Indent(12.0f * k);
    ImGui::PushStyleColor(ImGuiCol_Text, kWelcomeLink);
    if (ImGui::Selectable("User's Guide", false, 0, ImVec2(120.0f * k, 0))) host.OpenDoc("index");
    ImGui::SameLine();
    ImGui::TextDisabled("·");
    ImGui::SameLine();
    if (ImGui::Selectable("Display filters", false, 0, ImVec2(120.0f * k, 0))) host.OpenDoc("filters");
    ImGui::PopStyleColor();
    ImGui::Unindent(12.0f * k);
    ImGui::Dummy(ImVec2(0, 16.0f * k));
    const DecoderStatus& d = cap_.Decoder();
    if (d.ready) {
        ImGui::TextDisabled("You are running VSpy Shark with %s.", d.text.c_str());
    } else {
        ImGui::PushStyleColor(ImGuiCol_Text, kStopRed);
        TextMarked("###cs_welcome_nodecoder", "The dissector is not available: " + d.text);
        ImGui::PopStyleColor();
        if (ImGui::Button("Try again###cs_welcome_retry")) { std::string e; cap_.RestartDecoder(); }
    }
    if (!last_error_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, kStopRed);
        TextMarked("###cs_welcome_error", last_error_);
        ImGui::PopStyleColor();
    }
    ImGui::Unindent(24.0f * k);
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// packet list
// ---------------------------------------------------------------------------
void SharkView::DrawPacketList(const Services& host, float height) {
    (void)host;
    const std::vector<std::string>& titles = cap_.Decoder().columns;
    ImGui::BeginChild("##cs_list", ImVec2(0, height), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);
    const int ncols = (int)titles.size();
    if (ncols == 0) {
        TextDisabledMarked("###cs_list_nocols", "No dissector: " + cap_.Decoder().text);
        ImGui::EndChild();
        return;
    }
    const ImGuiTableFlags flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_NoBordersInBody |
                                  ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##cs_packets", ncols, flags)) { ImGui::EndChild(); return; }
    const float cw = ImGui::CalcTextSize("0").x;
    for (int c = 0; c < ncols; ++c) {
        const float chars = ColumnCharWidth(titles[(std::size_t)c]);
        ImGui::TableSetupColumn(titles[(std::size_t)c].c_str(),
                                chars > 0.0f ? ImGuiTableColumnFlags_WidthFixed : ImGuiTableColumnFlags_WidthStretch,
                                chars > 0.0f ? chars * cw : 0.0f);
    }
    ImGui::TableSetupScrollFreeze(0, col_filters_shown_ ? 2 : 1);
    ImGui::TableHeadersRow();

    // The Messages view's filter row: one edit cell per column, Enter
    // commits, a right click offers the values seen so far and "(All)".
    if (col_filters_shown_) {
        if (col_filter_buf_.size() < (std::size_t)ncols) col_filter_buf_.resize((std::size_t)ncols);
        const std::vector<std::string>& applied = cap_.ColumnFilters();
        ImGui::TableNextRow(ImGuiTableRowFlags_None);
        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(0xf7, 0xf7, 0xf7, 0xff));
        for (int c = 0; c < ncols; ++c) {
            if (!ImGui::TableNextColumn()) continue;
            ImGui::PushID(c);
            std::string& buf = col_filter_buf_[(std::size_t)c];
            const std::string current = (std::size_t)c < applied.size() ? applied[(std::size_t)c] : std::string();
            char text[256];
            std::snprintf(text, sizeof text, "%s", buf.c_str());
            const bool active = !Trim(current).empty();
            ImGui::PushStyleColor(ImGuiCol_FrameBg, active ? kFilterValidBg : kPaneBg);
            ImGui::PushStyleColor(ImGuiCol_Text, active ? IM_COL32(0x00, 0x40, 0x00, 0xff) : kPaneText);
            ImGui::SetNextItemWidth(-FLT_MIN);
            char id[24];
            std::snprintf(id, sizeof id, "###cs_cf%d", c);
            const bool entered = ImGui::InputText(id, text, sizeof text, ImGuiInputTextFlags_EnterReturnsTrue);
            const bool commit = entered || ((ImGui::IsItemActive() || ImGui::IsItemDeactivated()) && ImGui::IsKeyPressed(ImGuiKey_Enter));
            buf = text;
            if (commit) cap_.SetColumnFilter((std::size_t)c, buf);
            ImGui::PopStyleColor(2);
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip) && !active)
                ImGui::SetTooltip("Filter this column: text, =exact, !not, and on numeric columns >n, <n, a-b. Enter applies; right-click for the values seen.");
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                col_filter_dropdown_ = c;
                ImGui::OpenPopup("##cs_cfchoices");
            }
            if (col_filter_dropdown_ == c && ImGui::BeginPopup("##cs_cfchoices")) {
                if (ImGui::MenuItem("(All)")) { buf.clear(); cap_.SetColumnFilter((std::size_t)c, ""); }
                for (const std::string& v : cap_.ColumnValues((std::size_t)c)) {
                    if (ImGui::MenuItem(v.c_str())) { buf = "=" + v; cap_.SetColumnFilter((std::size_t)c, buf); }
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    }

    const std::vector<std::uint32_t>& shown = cap_.Displayed();
    const int nrows = (int)shown.size();
    ImGuiListClipper clipper;
    clipper.Begin(nrows);
    // A "go to" targets a row the clipper would skip; submitting it is what
    // lets SetScrollHereY below bring it into view.
    if (scroll_to_selected_ && selected_row_ >= 0 && selected_row_ < nrows) clipper.IncludeItemByIndex(selected_row_);
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const std::uint32_t idx = shown[(std::size_t)r];
            const Packet& p = cap_.At(idx);
            ImGui::TableNextRow();
            const bool selected = (r == selected_row_);
            const bool colored = colorize_ && p.has_color && !selected;
            if (colored) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, Rgb(p.bg));
            if (colored) ImGui::PushStyleColor(ImGuiCol_Text, Rgb(p.fg));
            else if (selected) ImGui::PushStyleColor(ImGuiCol_Text, kSelectionFg);
            for (int c = 0; c < ncols; ++c) {
                if (!ImGui::TableNextColumn()) continue;
                if (c == 0) {
                    char id[32];
                    std::snprintf(id, sizeof id, "###pkt%u", idx);
                    const char* text = p.cols.size() > (std::size_t)c ? p.cols[(std::size_t)c].c_str() : "";
                    std::string label = std::string(text) + id;
                    if (ImGui::Selectable(label.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                        SelectDisplayedRow(r);
                    }
                    if (selected && scroll_to_selected_) { ImGui::SetScrollHereY(0.5f); scroll_to_selected_ = false; }
                } else {
                    const char* text = p.cols.size() > (std::size_t)c ? p.cols[(std::size_t)c].c_str() : (p.state == Packet::State::Failed ? p.error.c_str() : "");
                    ImGui::TextUnformatted(text);
                }
            }
            if (colored || selected) ImGui::PopStyleColor();
        }
    }
    // Wireshark's auto-scroll: follow the tail while capturing and the user
    // has not scrolled up.
    if (autoscroll_ && Capturing() && (std::size_t)nrows > last_seen_count_) ImGui::SetScrollY(ImGui::GetScrollMaxY() + 1000.0f);
    last_seen_count_ = (std::size_t)nrows;

    // Keyboard navigation while the list has focus.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) && nrows > 0) {
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && selected_row_ + 1 < nrows) { SelectDisplayedRow(selected_row_ + 1); ScrollToSelected(); }
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && selected_row_ > 0) { SelectDisplayedRow(selected_row_ - 1); ScrollToSelected(); }
        if (ImGui::IsKeyPressed(ImGuiKey_F) && !ImGui::GetIO().KeyCtrl && !ImGui::GetIO().WantTextInput) {
            col_filters_shown_ = !col_filters_shown_;
            cap_.SetColumnFiltersEnabled(col_filters_shown_);
        }
        if (ImGui::IsKeyPressed(ImGuiKey_Home) && ImGui::GetIO().KeyCtrl) { SelectDisplayedRow(0); ScrollToSelected(); }
        if (ImGui::IsKeyPressed(ImGuiKey_End) && ImGui::GetIO().KeyCtrl) { SelectDisplayedRow(nrows - 1); ScrollToSelected(); }
    }
    ImGui::EndTable();
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// packet details
// ---------------------------------------------------------------------------
std::string SharkView::FilterFromField(const DetailNode& n, bool negate) const {
    // A protocol (or a field without a value) filters by name; a field with a
    // value by "name == value". The value is what follows ": " in the
    // display text -- Wireshark builds it from the typed value, which this
    // side does not have; the server rejects what does not parse and the
    // bar turns red.
    std::string f;
    const auto colon = n.text.find(": ");
    if (n.name.empty()) return f;
    if (colon == std::string::npos || n.children.size() > 0) {
        f = n.name;
        return negate ? "!(" + f + ")" : f;
    }
    std::string v = n.text.substr(colon + 2);
    const auto paren = v.find(" (");
    if (paren != std::string::npos) v.resize(paren);
    bool plain = !v.empty();
    for (char c : v) if (!(std::isalnum((unsigned char)c) || c == '.' || c == ':' || c == '-' || c == '_')) plain = false;
    if (!plain) {
        std::string q;
        for (char c : v) { if (c == '"' || c == '\\') q += '\\'; q += c; }
        v = "\"" + q + "\"";
    }
    f = n.name + (negate ? " != " : " == ") + v;
    return f;
}

void SharkView::SelectField(const DetailNode& n, const DetailNode* proto) {
    field_name_ = n.name;
    field_text_ = n.text;
    hl_pos_ = n.pos;
    hl_size_ = n.size;
    if (proto) { proto_pos_ = proto->pos; proto_size_ = proto->size; }
}

void SharkView::DrawFieldMenu(const DetailNode& n) {
    if (ImGui::BeginMenu("Apply as Filter")) {
        if (ImGui::MenuItem("Selected")) ApplyFilter(FilterFromField(n, false));
        if (ImGui::MenuItem("Not Selected")) ApplyFilter(FilterFromField(n, true));
        if (ImGui::MenuItem("...and Selected", nullptr, false, !cap_.Filter().empty())) ApplyFilter(cap_.Filter() + " && " + FilterFromField(n, false));
        if (ImGui::MenuItem("...or Selected", nullptr, false, !cap_.Filter().empty())) ApplyFilter(cap_.Filter() + " || " + FilterFromField(n, false));
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Prepare as Filter")) {
        if (ImGui::MenuItem("Selected")) std::snprintf(filter_buf_, sizeof filter_buf_, "%s", FilterFromField(n, false).c_str());
        if (ImGui::MenuItem("Not Selected")) std::snprintf(filter_buf_, sizeof filter_buf_, "%s", FilterFromField(n, true).c_str());
        ImGui::EndMenu();
    }
    ImGui::Separator();
    if (ImGui::BeginMenu("Copy")) {
        if (ImGui::MenuItem("Description")) ImGui::SetClipboardText(n.text.c_str());
        if (ImGui::MenuItem("Field Name")) ImGui::SetClipboardText(n.name.c_str());
        if (ImGui::MenuItem("Value")) {
            const auto colon = n.text.find(": ");
            ImGui::SetClipboardText(colon == std::string::npos ? n.text.c_str() : n.text.c_str() + colon + 2);
        }
        if (ImGui::MenuItem("As Filter")) ImGui::SetClipboardText(FilterFromField(n, false).c_str());
        ImGui::EndMenu();
    }
}

void SharkView::DrawTreeNode(const DetailNode& n, int depth, int& row) {
    if (n.text.empty()) { for (const DetailNode& c : n.children) DrawTreeNode(c, depth, row); return; }   // hidden fields
    static const DetailNode* s_proto = nullptr;
    if (depth == 0) s_proto = &n;
    const bool leaf = n.children.empty();
    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick | ImGuiTreeNodeFlags_SpanAvailWidth;
    if (leaf) flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
    const bool selected = (hl_pos_ == n.pos && hl_size_ == n.size && field_name_ == n.name && field_text_ == n.text);
    if (selected) flags |= ImGuiTreeNodeFlags_Selected;
    // Expansion is remembered per field NAME, so "Ethernet II" stays open
    // from packet to packet (Wireshark's behaviour).
    ImGui::PushID(n.name.empty() ? "?" : n.name.c_str());
    ImGui::PushID(row);
    std::string label = n.text + "###n";
    if (selected) ImGui::PushStyleColor(ImGuiCol_Text, kSelectionFg);
    const bool open = ImGui::TreeNodeEx(label.c_str(), flags);
    if (selected) ImGui::PopStyleColor();
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left) || ImGui::IsItemClicked(ImGuiMouseButton_Right)) SelectField(n, s_proto);
    if (ImGui::BeginPopupContextItem("##fieldmenu")) { DrawFieldMenu(n); ImGui::EndPopup(); }
    ++row;
    if (open && !leaf) {
        for (const DetailNode& c : n.children) DrawTreeNode(c, depth + 1, row);
        ImGui::TreePop();
    }
    ImGui::PopID();
    ImGui::PopID();
}

void SharkView::DrawDetails(const Services& host, float height) {
    (void)host;
    ImGui::BeginChild("##cs_details", ImVec2(0, height), ImGuiChildFlags_None);
    if (selected_ < 0) {
        ImGui::EndChild();
        return;
    }
    const DetailNode* tree = cap_.Tree((std::uint32_t)selected_);
    if (!tree) {
        if (cap_.TreePending()) TextDisabledMarked("###cs_details_wait", "Dissecting...");
        else if (!cap_.TreeError().empty()) TextDisabledMarked("###cs_details_err", cap_.TreeError());
        else TextDisabledMarked("###cs_details_none", "");
        ImGui::EndChild();
        return;
    }
    int row = 0;
    // The root ("frame") is the whole dissection: draw its children as the
    // top-level protocols, the way Wireshark does.
    for (const DetailNode& c : tree->children) DrawTreeNode(c, 0, row);
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// packet bytes
// ---------------------------------------------------------------------------
void SharkView::DrawBytes(const Services& host, float height) {
    ImGui::BeginChild("##cs_bytes", ImVec2(0, height), ImGuiChildFlags_None);
    if (selected_ < 0) { ImGui::EndChild(); return; }
    const Packet& p = cap_.At((std::uint32_t)selected_);
    const std::vector<std::uint8_t>& b = p.raw->bytes;
    host.PushFont(Font::Mono);
    const float cw = ImGui::CalcTextSize("0").x;
    const float lh = ImGui::GetTextLineHeightWithSpacing();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const DetailNode* tree = cap_.Tree((std::uint32_t)selected_);
    // One findable marker for the tests, at the top where nothing clips it.
    if (!b.empty()) {
        const ImVec2 keep = ImGui::GetCursorPos();
        Marker("###cs_bytes_marker");
        ImGui::SetCursorPos(keep);
    }
    ImGuiListClipper clipper;
    const int lines = (int)((b.size() + 15) / 16);
    clipper.Begin(lines, lh);
    while (clipper.Step()) {
        for (int line = clipper.DisplayStart; line < clipper.DisplayEnd; ++line) {
            const std::size_t off = (std::size_t)line * 16;
            const ImVec2 p0 = ImGui::GetCursorScreenPos();
            char offs[8];
            std::snprintf(offs, sizeof offs, "%04x", (unsigned)off);
            ImGui::TextUnformatted(offs);
            float x = p0.x + cw * 6.0f;
            // hex
            for (std::size_t i = off; i < off + 16 && i < b.size(); ++i) {
                const bool in_field = hl_pos_ >= 0 && (int)i >= hl_pos_ && (int)i < hl_pos_ + hl_size_;
                const bool in_proto = !in_field && proto_pos_ >= 0 && (int)i >= proto_pos_ && (int)i < proto_pos_ + proto_size_;
                if (in_field) dl->AddRectFilled(ImVec2(x - 1, p0.y), ImVec2(x + cw * 2 + 1, p0.y + lh), kSelectionBg);
                else if (in_proto) dl->AddRectFilled(ImVec2(x - 1, p0.y), ImVec2(x + cw * 2 + 1, p0.y + lh), kProtoBytesBg);
                char hx[4];
                std::snprintf(hx, sizeof hx, "%02x", b[i]);
                dl->AddText(ImVec2(x, p0.y), in_field ? kSelectionFg : kPaneText, hx);
                // Click a byte: select the smallest field holding it.
                if (tree && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                    const ImVec2 m = ImGui::GetIO().MousePos;
                    if (m.x >= x - 1 && m.x < x + cw * 2 + 1 && m.y >= p0.y && m.y < p0.y + lh && ImGui::IsWindowHovered()) {
                        const DetailNode* best = nullptr;
                        const DetailNode* proto = nullptr;
                        std::function<void(const DetailNode&, const DetailNode*)> walk = [&](const DetailNode& n, const DetailNode* pr) {
                            const bool holds = n.size > 0 && (int)i >= n.pos && (int)i < n.pos + n.size;
                            if (holds && !n.text.empty() && (!best || n.size <= best->size)) { best = &n; proto = pr; }
                            for (const DetailNode& c : n.children) walk(c, pr ? pr : &n);
                        };
                        for (const DetailNode& c : tree->children) walk(c, nullptr);
                        if (best) SelectField(*best, proto ? proto : best);
                    }
                }
                x += cw * 3.0f + ((i - off) == 7 ? cw : 0.0f);
            }
            // ascii
            x = p0.x + cw * (6.0f + 16.0f * 3.0f + 3.0f);
            for (std::size_t i = off; i < off + 16 && i < b.size(); ++i) {
                const bool in_field = hl_pos_ >= 0 && (int)i >= hl_pos_ && (int)i < hl_pos_ + hl_size_;
                const bool in_proto = !in_field && proto_pos_ >= 0 && (int)i >= proto_pos_ && (int)i < proto_pos_ + proto_size_;
                if (in_field) dl->AddRectFilled(ImVec2(x, p0.y), ImVec2(x + cw, p0.y + lh), kSelectionBg);
                else if (in_proto) dl->AddRectFilled(ImVec2(x, p0.y), ImVec2(x + cw, p0.y + lh), kProtoBytesBg);
                const char ch = (b[i] >= 0x20 && b[i] < 0x7f) ? (char)b[i] : '.';
                const char s[2] = {ch, 0};
                dl->AddText(ImVec2(x, p0.y), in_field ? kSelectionFg : kPaneText, s);
                x += cw + ((i - off) == 7 ? cw : 0.0f);
            }
        }
    }
    host.PopFont();
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// status bar
// ---------------------------------------------------------------------------
void SharkView::DrawStatusBar(const Services& host) {
    (void)host;
    const float k = K();
    const float h = ImGui::GetFrameHeight() + 4.0f * k;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float w = ImGui::GetContentRegionAvail().x;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), kStatusBg);
    dl->AddLine(p, ImVec2(p.x + w, p.y), kSeparator);
    ImGui::SetCursorScreenPos(ImVec2(p.x + 6.0f * k, p.y + 2.0f * k));
    // Expert info dot (no expert summary crosses the wire: grey).
    const ImVec2 c = ImGui::GetCursorScreenPos();
    dl->AddCircleFilled(ImVec2(c.x + 6.0f * k, c.y + ImGui::GetTextLineHeight() * 0.55f), 5.0f * k, kGrey);
    ImGui::Dummy(ImVec2(14.0f * k, ImGui::GetTextLineHeight()));
    ImGui::SameLine();
    std::string left;
    if (!field_text_.empty()) {
        left = field_text_ + " (" + field_name_ + "), " + std::to_string(hl_size_) + " byte" + (hl_size_ == 1 ? "" : "s");
    } else if (Capturing()) {
        left = "Capturing from " + src_->name();
        const std::string st = src_->status();
        if (!st.empty()) left += " · " + st;
    } else if (!file_path_.empty()) {
        left = file_path_;
    } else if (cap_.Count() > 0 && src_) {
        left = "Stopped: " + src_->name();
    } else {
        left = cap_.Decoder().ready ? "Ready to load or capture" : "No dissector: " + cap_.Decoder().text;
    }
    if (!last_error_.empty() && field_text_.empty()) left = last_error_;
    else if (!saved_note_.empty() && field_text_.empty()) left = saved_note_;
    const float third = w * 0.55f;
    ImGui::PushTextWrapPos(p.x + third);
    TextMarked("###cs_status_left", left);
    ImGui::PopTextWrapPos();
    ImGui::SameLine(third);
    dl->AddLine(ImVec2(p.x + third - 6.0f * k, p.y + 3.0f * k), ImVec2(p.x + third - 6.0f * k, p.y + h - 3.0f * k), kSeparator);
    char mid[160];
    const std::size_t n = cap_.Count(), d = cap_.Displayed().size();
    const double pct = n ? 100.0 * (double)d / (double)n : 100.0;
    const char* cf = (col_filters_shown_ && cap_.AnyColumnFilter()) ? " · Column filters" : "";
    if (cap_.PendingCount() > 0)
        std::snprintf(mid, sizeof mid, "Packets: %zu · Displayed: %zu (%.1f%%) · Dissecting: %zu%s", n, d, pct, cap_.PendingCount(), cf);
    else
        std::snprintf(mid, sizeof mid, "Packets: %zu · Displayed: %zu (%.1f%%)%s", n, d, pct, cf);
    TextMarked("###cs_status_mid", mid);
    const float right = w * 0.86f;
    ImGui::SameLine(right);
    dl->AddLine(ImVec2(p.x + right - 6.0f * k, p.y + 3.0f * k), ImVec2(p.x + right - 6.0f * k, p.y + h - 3.0f * k), kSeparator);
    ImGui::TextUnformatted("Profile: Default");
    ImGui::SetCursorScreenPos(p);
    ImGui::Dummy(ImVec2(w, h));
}

// ---------------------------------------------------------------------------
// dialogs
// ---------------------------------------------------------------------------
void SharkView::DrawCaptureOptions(const Services& host) {
    if (show_options_) { ImGui::OpenPopup("Capture Options###cs_capopts"); show_options_ = false; entries_ = AllSources(host, false); options_sel_ = -1; }
    const float k = K();
    ImGui::SetNextWindowSize(ImVec2(720.0f * k, 440.0f * k), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Capture Options###cs_capopts", nullptr, ImGuiWindowFlags_NoSavedSettings)) return;
    if (ImGui::BeginTabBar("##cs_capopts_tabs")) {
        if (ImGui::BeginTabItem("Input###cs_capopts_input")) {
            const float table_h = ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() * 3.2f;
            if (ImGui::BeginTable("##cs_capopts_table", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, table_h))) {
                ImGui::TableSetupColumn("Interface", ImGuiTableColumnFlags_WidthStretch, 0.45f);
                ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthStretch, 0.2f);
                ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 0.35f);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                int n = 0;
                for (const SourceEntry& e : entries_) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    std::string label = e.name + "###cs_opt" + std::to_string(n);
                    ImGui::BeginDisabled(!e.available);
                    if (ImGui::Selectable(label.c_str(), options_sel_ == n, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                        options_sel_ = n;
                        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) { StartEntry(host, e); ImGui::CloseCurrentPopup(); }
                    }
                    ImGui::EndDisabled();
                    if (!e.available && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_ForTooltip)) ImGui::SetTooltip("%s", e.reason.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(SourceKindName(e.kind));
                    ImGui::TableNextColumn();
                    if (e.available) ImGui::TextUnformatted(e.description.c_str());
                    else ImGui::TextDisabled("%s", e.reason.c_str());
                    ++n;
                }
                ImGui::EndTable();
            }
            ImGui::Checkbox("Enable promiscuous mode on all interfaces###cs_capopts_promisc", &promisc_);
            ImGui::TextUnformatted("Capture filter for selected interfaces:");
            ImGui::SameLine();
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("###cs_capopts_bpf", "Enter a capture filter ...", bpf_buf_, sizeof bpf_buf_);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Options###cs_capopts_options")) {
            ImGui::Checkbox("Update list of packets in real-time (always on)", &colorize_);
            ImGui::Checkbox("Automatically scroll during live capture###cs_capopts_autoscroll", &autoscroll_);
            ImGui::TextDisabled("%s", cap_.Decoder().text.c_str());
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::Separator();
    const bool can_start = options_sel_ >= 0 && options_sel_ < (int)entries_.size() && entries_[(std::size_t)options_sel_].available;
    ImGui::BeginDisabled(!can_start);
    if (ImGui::Button("Start###cs_capopts_start", ImVec2(90.0f * k, 0))) { StartEntry(host, entries_[(std::size_t)options_sel_]); ImGui::CloseCurrentPopup(); }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Refresh###cs_capopts_refresh", ImVec2(90.0f * k, 0))) entries_ = AllSources(host, true);
    ImGui::SameLine();
    if (ImGui::Button("Close###cs_capopts_close", ImVec2(90.0f * k, 0))) ImGui::CloseCurrentPopup();
    ImGui::SameLine();
    if (ImGui::Button("Help###cs_capopts_help", ImVec2(90.0f * k, 0))) host.OpenDoc("index");
    ImGui::EndPopup();
}

void SharkView::DrawGoTo() {
    if (show_goto_) { ImGui::OpenPopup("Go to Packet###cs_goto"); show_goto_ = false; }
    if (!ImGui::BeginPopupModal("Go to Packet###cs_goto", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) return;
    ImGui::TextUnformatted("Packet:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f * K());
    ImGui::InputInt("###cs_goto_num", &goto_num_, 0, 0);
    const bool go = ImGui::Button("Go to packet###cs_goto_go") || (ImGui::IsItemActive() && ImGui::IsKeyPressed(ImGuiKey_Enter));
    ImGui::SameLine();
    if (ImGui::Button("Cancel###cs_goto_cancel")) ImGui::CloseCurrentPopup();
    if (go) {
        const int no = cap_.ColumnIndex("No.");
        const auto& d = cap_.Displayed();
        for (std::size_t r = 0; r < d.size(); ++r) {
            const Packet& p = cap_.At(d[r]);
            const int num = (no >= 0 && p.cols.size() > (std::size_t)no) ? std::atoi(p.cols[(std::size_t)no].c_str()) : (int)d[r] + 1;
            if (num == goto_num_) { SelectDisplayedRow((int)r); ScrollToSelected(); break; }
        }
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void SharkView::DrawFind() {
    if (show_find_) { ImGui::OpenPopup("Find Packet###cs_find"); show_find_ = false; find_status_.clear(); }
    if (!ImGui::BeginPopupModal("Find Packet###cs_find", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) return;
    ImGui::TextUnformatted("String in the packet list:");
    ImGui::SetNextItemWidth(320.0f * K());
    ImGui::InputText("###cs_find_text", find_buf_, sizeof find_buf_);
    const bool go = ImGui::Button("Find###cs_find_go") || (ImGui::IsItemActive() && ImGui::IsKeyPressed(ImGuiKey_Enter));
    ImGui::SameLine();
    if (ImGui::Button("Close###cs_find_close")) ImGui::CloseCurrentPopup();
    if (go && find_buf_[0]) {
        const auto& d = cap_.Displayed();
        const int start = selected_row_ + 1;
        bool found = false;
        for (std::size_t k = 0; k < d.size() && !found; ++k) {
            const std::size_t r = ((std::size_t)std::max(0, start) + k) % d.size();
            const Packet& p = cap_.At(d[r]);
            for (const std::string& c : p.cols) {
                if (c.find(find_buf_) != std::string::npos) { SelectDisplayedRow((int)r); ScrollToSelected(); found = true; break; }
            }
        }
        find_status_ = found ? "" : "No packet contained that string.";
    }
    if (!find_status_.empty()) ImGui::TextDisabled("%s", find_status_.c_str());
    ImGui::EndPopup();
}

void SharkView::DrawAbout(const Services& host) {
    if (show_about_) { ImGui::OpenPopup("About VSpy Shark###cs_about"); show_about_ = false; }
    if (!ImGui::BeginPopupModal("About VSpy Shark###cs_about", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) return;
    host.PushFont(Font::Bold);
    ImGui::TextUnformatted("VSpy Shark");
    host.PopFont();
    ImGui::TextUnformatted("An independent Ethernet analyzer with a FreeWili GUI plugin.");
    ImGui::TextUnformatted("Dissection: Wireshark's libwireshark, in the separate wirespy_server process (GPL-2.0-or-later).");
    ImGui::TextUnformatted(cap_.Decoder().text.c_str());
    if (ImGui::Button("OK###cs_about_ok", ImVec2(90.0f * K(), 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void SharkView::DrawFileProperties() {
    if (show_props_) { ImGui::OpenPopup("Capture File Properties###cs_props"); show_props_ = false; }
    if (!ImGui::BeginPopupModal("Capture File Properties###cs_props", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) return;
    std::uint64_t bytes = 0;
    std::int64_t first = 0, last = 0;
    bool any = false;
    for (std::size_t i = 0; i < cap_.Count(); ++i) {
        const RawFrame& f = *cap_.At(i).raw;
        bytes += f.bytes.size();
        if (f.has_ts) {
            if (!any) { first = last = f.ts_sec; any = true; }
            first = std::min(first, f.ts_sec);
            last = std::max(last, f.ts_sec);
        }
    }
    if (ImGui::BeginTable("##cs_props_table", 2, ImGuiTableFlags_Borders)) {
        auto row = [](const char* k, const std::string& v) { ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted(k); ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str()); };
        row("Name", file_path_.empty() ? (src_ ? src_->name() : std::string("(live capture)")) : file_path_);
        row("Packets", std::to_string(cap_.Count()));
        row("Displayed", std::to_string(cap_.Displayed().size()));
        row("Bytes", std::to_string(bytes));
        row("Elapsed", any ? std::to_string(last - first) + " s" : std::string("-"));
        row("Dissector", cap_.Decoder().text);
        ImGui::EndTable();
    }
    if (ImGui::Button("Close###cs_props_close", ImVec2(90.0f * K(), 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

} // namespace vspyshark
