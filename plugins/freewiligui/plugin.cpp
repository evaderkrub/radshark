// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#include <freewiligui/plugin.hpp>
#include "analyzer.h"
#include "tool_schemas.h"
#include "doc.h"
#include "portable_ui.h"
using namespace radshark;
class SharkPlugin : public fwgui::Plugin<SharkPlugin> {
public:
    FwGuiResult OnStartup(fwgui::Host host) {
        Services services;
        ui_.Bind(services);
        services.open_doc=[host](const char* id){host.OpenDoc(id);};
        services.settings_get=[host](const char* k){return host.SettingsGet(k);};
        services.settings_set=[host](const char* k,const char* v){host.SettingsSet(k,v);};
        services.log=[host](int level,const std::string& msg){if(level==0)host.LogInfo(msg.c_str());else if(level==1)host.LogWarn(msg.c_str());else host.LogError(msg.c_str());};
        services.push_font=[host](Font font){host.PushFont(static_cast<int32_t>(font));};
        services.pop_font=[host](){host.PopFont();};
        analyzer_.Init(std::move(services));
        RegisterDoc("index","RadShark",kDocIndex);
        RegisterDoc("filters","Display filters",kDocFilters);
        fwgui::View view;
        view.id="shark";view.title="RadShark";
        view.menu_path="Tools/RadShark";
        view.flags=FWGUI_VIEW_MENUBAR;
        view.imgui_window_flags=ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_NoScrollWithMouse;
        const auto result=RegisterView<&SharkPlugin::Draw>(view);
        if(result!=FWGUI_OK) return result;
        RegisterTool<&SharkPlugin::StateTool>("state","Analyzer state and decoder readiness",kStateSchema);
        RegisterTool<&SharkPlugin::PacketsTool>("packets","Packet summary rows",kPacketsSchema);
        RegisterTool<&SharkPlugin::PacketTool>("packet","Packet details and bytes",kPacketSchema);
        RegisterTool<&SharkPlugin::FilterTool>("filter","Apply a display filter",kFilterSchema);
        RegisterTool<&SharkPlugin::ColumnFilterTool>("column_filter","Set packet column filters",kColumnFilterSchema);
        RegisterTool<&SharkPlugin::SaveTool>("save","Save a capture file",kSaveSchema);
        RegisterTool<&SharkPlugin::OpenTool>("open","Open a capture file",kOpenSchema);
        RegisterTool<&SharkPlugin::CaptureTool>("capture","Watch a host engine or stop capture",kCaptureSchema);
        RegisterTool<&SharkPlugin::SourcesTool>("sources","List available capture sources",kStateSchema);
        return FWGUI_OK;
    }
    void OnShutdown() {analyzer_.Shutdown();}
    void OnFrame(const FwGuiFrameInfo&) {analyzer_.Frame();}
    void Draw(const fwgui::ViewCtx&) {analyzer_.Draw();ui_.Draw();}
    void StateTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.StateTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
    void PacketsTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.PacketsTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
    void PacketTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.PacketTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
    void FilterTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.FilterTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
    void ColumnFilterTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.ColumnFilterTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
    void SaveTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.SaveTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
    void OpenTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.OpenTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
    void CaptureTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.CaptureTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
    void SourcesTool(std::string_view args,const fwgui::McpReply& r) {
        Reply reply{[&](const std::string& s){r.Ok(s.c_str());},[&](const std::string& s){r.Error(s.c_str());}};
        try {analyzer_.SourcesTool(args,reply);}catch(const std::exception& e){reply.Error(e.what());}
    }
private:
    Analyzer analyzer_;
    PortableUi ui_;
};
static const FwGuiPluginDesc descriptor={
    sizeof(FwGuiPluginDesc),"com.intrepidcs.radshark","RadShark","0.2.0","Intrepid Control Systems",
    "Ethernet packet analysis with libicsneo, local interfaces and capture files",nullptr,FWGUI_FINGERPRINT_INIT
};
FWGUI_PLUGIN_MAIN(fwgui_radshark,&descriptor,SharkPlugin)
