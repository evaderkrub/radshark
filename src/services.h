// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#pragma once
#include "frame_source.h"
#include <imgui.h>
#include <functional>
#include <string_view>

namespace vspyshark {
enum class Icon { NONE, SETTINGS, OPEN, SAVE, CLOSE, REFRESH, SEARCH, LINK,
                  ARROW_UP, ARROW_DOWN, DOWNLOAD, CHART, FILTER, ADD, ARROW_RIGHT };
enum class Font { Bold = 1, Mono = 3 };
enum class FileDialogState { None, Picked, Cancelled };

// Values are owned by the adapter. Borrowed strings last until its next callback.
// All callbacks run on the GUI thread, including optional engine sources.
struct Services {
    std::function<std::string_view(const char*)> settings_get;
    std::function<void(const char*, const char*)> settings_set;
    std::function<void(int, const std::string&)> log;
    std::function<std::string_view(Icon)> icon;
    std::function<void(Font)> push_font;
    std::function<void()> pop_font;
    std::function<void(const char*)> open_doc;
    std::function<void(const char*,const char*,int,bool)> open_file_dialog;
    std::function<FileDialogState(std::string_view&,int32_t&)> file_dialog_result;
    std::function<std::vector<SourceEntry>()> list_sources;
    std::function<std::unique_ptr<FrameSource>(SourceKind,const std::string&)> open_source;

    std::string_view SettingsGet(const char* key) const { return settings_get ? settings_get(key) : std::string_view(); }
    void SettingsSet(const char* key,const char* value) const { if(settings_set) settings_set(key,value); }
    double SettingsGetNumber(const char* key,double fallback) const;
    void SettingsSetNumber(const char* key,double value) const;
    void LogInfo(const std::string& s) const { if(log) log(0,s); }
    void LogWarn(const std::string& s) const { if(log) log(1,s); }
    void LogError(const std::string& s) const { if(log) log(2,s); }
    std::string_view Icon(vspyshark::Icon i) const { return icon ? icon(i) : std::string_view(); }
    void PushFont(Font f) const { if(push_font) push_font(f); else ImGui::PushFont(nullptr); }
    void PopFont() const { if(pop_font) pop_font(); else ImGui::PopFont(); }
    void OpenDoc(const char* id) const { if(open_doc) open_doc(id); }
    void OpenFileDialog(const char* title,const char* ext,int tag,bool save=false) const {
        if(open_file_dialog) open_file_dialog(title,ext,tag,save);
    }
    FileDialogState FileDialogResult(std::string_view& path,int32_t& tag) const {
        return file_dialog_result ? file_dialog_result(path,tag) : FileDialogState::None;
    }
    bool Splitter(const char* id,float& size,float extent,float min_before,float min_after,bool vertical) const;
};
inline void Marker(const char* id) { ImGui::InvisibleButton(id,ImVec2(1,1)); }
inline void TextMarked(const char* id,std::string_view s) {
    ImGui::TextUnformatted(s.empty()?"":s.data(),s.empty()?nullptr:s.data()+s.size());
    ImGui::SameLine(0,0); Marker(id);
}
inline void TextDisabledMarked(const char* id,std::string_view s) {
    ImGui::PushStyleColor(ImGuiCol_Text,ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    TextMarked(id,s); ImGui::PopStyleColor();
}
}
