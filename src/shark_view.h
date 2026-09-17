// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// shark_view.h -- the Wireshark-shaped window: menu bar, main toolbar,
// display-filter bar, the packet list / details / bytes panes with their
// splitters, the status bar, and the Welcome page when nothing is open.
// The reference is Wireshark 4.x's Qt UI in its default (light) look; the
// colours below are Wireshark's own where it has one.
#pragma once
#include "capture.h"
#include "frame_source.h"

#include "services.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace radshark {

class SharkView {
public:
    void Init(const Services& host);
    void Shutdown();
    void OnFrame(const Services& host);          // every host frame, drawn or not
    void Draw(const Services& host);

    // What the MCP tools and the tests reach in through.
    Capture& capture() { return cap_; }
    bool OpenFile(const Services& host, const std::string& path, std::string& error);
    bool StartCapture(const Services& host, SourceKind kind, const std::string& id, std::string& error);
    void StopCapture();
    bool Capturing() const { return src_ && src_->running(); }
    const std::string& FilePath() const { return file_path_; }
    std::string SourceName() const { return src_ ? src_->name() : std::string(); }
    void ApplyFilter(const std::string& text);
    void ShowColumnFilters(bool on) { col_filters_shown_ = on; }
    void SyncColumnFilterCells() { col_filter_buf_ = cap_.ColumnFilters(); }
    std::vector<SourceEntry> AllSources(const Services& host, bool rescan);
    int Selected() const { return selected_; }
    void Select(std::uint32_t index);
    bool SaveAs(const std::string& path, bool displayed_only, std::string& error);
    const std::string& LastError() const { return last_error_; }

private:
    // panes
    void DrawMenuBar(const Services& host);
    void DrawToolbar(const Services& host);
    void DrawFilterBar(const Services& host);
    void DrawWelcome(const Services& host);
    void DrawPacketList(const Services& host, float height);
    void DrawDetails(const Services& host, float height);
    void DrawBytes(const Services& host, float height);
    void DrawStatusBar(const Services& host);
    // dialogs
    void DrawCaptureOptions(const Services& host);
    void DrawGoTo();
    void DrawFind();
    void DrawAbout(const Services& host);
    void DrawFileProperties();
    void DrawFieldMenu(const DetailNode& n);
    // helpers
    void DrawTreeNode(const DetailNode& n, int depth, int& row);
    void SelectField(const DetailNode& n, const DetailNode* proto);
    void SelectDisplayedRow(int row);
    void PumpFileDialogs(const Services& host);
    void NewCapture();
    void PushRecent(const Services& host, const std::string& path);
    std::string FilterFromField(const DetailNode& n, bool negate) const;
    void StartEntry(const Services& host, const SourceEntry& e);
    void SaveLayout(const Services& host);
    float K() const;   // font/13, Wireshark's 13 px UI
    void ScrollToSelected() { scroll_to_selected_ = true; }

    Capture cap_;
    std::unique_ptr<FrameSource> src_;
    std::string file_path_, last_error_, saved_note_;
    std::vector<RawFrame> incoming_;
    std::uint64_t frames_in_ = 0;
    bool decoder_tried_ = false;
    bool stop_when_drained_ = false;

    // display filter bar
    char filter_buf_[1024] = {0};
    bool filter_focus_ = false;

    // selection
    int selected_ = -1;              // packet index
    int selected_row_ = -1;          // index into Displayed()
    bool scroll_to_selected_ = false;
    std::string field_name_, field_text_;
    int hl_pos_ = -1, hl_size_ = 0;          // selected field's bytes
    int proto_pos_ = -1, proto_size_ = 0;    // its protocol's bytes
    std::uint64_t tree_gen_ = 0;

    // layout / view
    float list_h_ = 300.0f, details_h_ = 200.0f;
    bool show_list_ = true, show_details_ = true, show_bytes_ = true;
    bool autoscroll_ = true, colorize_ = true;
    bool col_filters_shown_ = false;         // the Messages view's filter row
    std::vector<std::string> col_filter_buf_; // what the cells hold (Enter commits)
    int col_filter_dropdown_ = -1;
    float zoom_ = 1.0f;
    std::size_t last_seen_count_ = 0;

    // capture options
    bool show_options_ = false;
    bool promisc_ = true;
    char bpf_buf_[256] = {0};
    std::vector<SourceEntry> entries_;
    double entries_at_ = -1.0;
    int options_sel_ = -1;

    // popups
    bool show_goto_ = false, show_find_ = false, show_about_ = false, show_props_ = false;
    int goto_num_ = 1;
    char find_buf_[256] = {0};
    std::string find_status_;

    std::vector<std::string> recent_;
    std::string welcome_filter_;
    Services host_;
};

} // namespace radshark
