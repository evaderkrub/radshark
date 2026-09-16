// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#include "portable_ui.h"
#include <algorithm>
#include <cstdio>
#include <vector>
namespace fs=std::filesystem;
namespace vspyshark {
void PortableUi::Bind(Services& s) {
    s.open_file_dialog=[this](const char*,const char*,int tag,bool save){
        tag_=tag;save_=save;requested_=true;error_.clear();filename_[0]=0;
        std::snprintf(location_,sizeof location_,"%s",directory_.string().c_str());
    };
    s.file_dialog_result=[this](std::string_view& path,int32_t& tag){
        if(!ready_) return FileDialogState::None;
        ready_=false;path=picked_;tag=tag_;return FileDialogState::Picked;
    };
    s.open_doc=[this](const char* id){doc_=id;};
}
void PortableUi::Draw() {
    if(requested_) { ImGui::OpenPopup("Capture file###shark_file");requested_=false; }
    ImGui::SetNextWindowSize(ImVec2(660,460),ImGuiCond_FirstUseEver);
    if(ImGui::BeginPopupModal("Capture file###shark_file",nullptr)) {
        if(ImGui::Button("Up")) {
            directory_=directory_.parent_path();
            std::snprintf(location_,sizeof location_,"%s",directory_.string().c_str());
        }
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-1);
        if(ImGui::InputText("###shark_directory",location_,sizeof location_,ImGuiInputTextFlags_EnterReturnsTrue)) {
            std::error_code ec; fs::path p=fs::u8path(location_);
            if(fs::is_directory(p,ec)) directory_=p; else error_="That folder is not available.";
        }
        ImGui::BeginChild("Files",ImVec2(0,-ImGui::GetFrameHeightWithSpacing()*3),ImGuiChildFlags_Borders);
        std::error_code ec;
        std::vector<fs::directory_entry> entries;
        for(fs::directory_iterator it(directory_,ec),end; !ec&&it!=end; it.increment(ec)) entries.push_back(*it);
        std::sort(entries.begin(),entries.end(),[](const auto&a,const auto&b){return a.path().filename()<b.path().filename();});
        for(const auto& e:entries) {
            const bool folder=e.is_directory(ec);
            const std::string ext=e.path().extension().string();
            if(!folder && ext!=".pcap" && ext!=".pcapng" && ext!=".cap") continue;
            const std::string name=e.path().filename().string();
            if(ImGui::Selectable(((folder?"[Folder] ":"")+name).c_str(),false,ImGuiSelectableFlags_AllowDoubleClick)) {
                if(folder) {
                    directory_=e.path();
                    std::snprintf(location_,sizeof location_,"%s",directory_.string().c_str());
                } else std::snprintf(filename_,sizeof filename_,"%s",name.c_str());
            }
        }
        ImGui::EndChild();
        ImGui::SetNextItemWidth(-1); ImGui::InputTextWithHint("###shark_filename",save_?"Filename.pcapng":"Capture filename",filename_,sizeof filename_);
        if(!error_.empty()) ImGui::TextWrapped("%s",error_.c_str());
        if(ImGui::Button(save_?"Save":"Open")) {
            fs::path p=fs::u8path(filename_); if(p.is_relative()) p=directory_/p;
            if(!*filename_) error_="Enter a filename.";
            else if(!save_ && !fs::is_regular_file(p,ec)) error_="Choose an existing capture file.";
            else if(save_ && fs::exists(p,ec)) { picked_=p.string(); ImGui::OpenPopup("Replace file?"); }
            else { picked_=p.string();ready_=true;ImGui::CloseCurrentPopup(); }
        }
        ImGui::SameLine(); if(ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        bool replaced=false;
        if(ImGui::BeginPopupModal("Replace file?",nullptr,ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::TextUnformatted("This file already exists. Replace it?");
            if(ImGui::Button("Replace")) {ready_=true;replaced=true;ImGui::CloseCurrentPopup();}
            ImGui::SameLine();if(ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
        if(replaced) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    if(!doc_.empty()) {
        bool open=true;
        ImGui::SetNextWindowSize(ImVec2(640,360),ImGuiCond_FirstUseEver);
        if(ImGui::Begin("VSpy Shark Help",&open)) {
            ImGui::SeparatorText("Capture and inspect");
            ImGui::TextWrapped("Open a pcap or pcapng file, or double-click an Ethernet interface or Intrepid device to start capture. Stop ends capture; selecting a packet shows its protocol details and bytes.");
            ImGui::SeparatorText("Display filters");
            ImGui::TextWrapped("Use Wireshark display filters such as tcp, arp, ip.addr == 192.168.1.1, or tcp.port == 80. Press Enter to apply. Green means valid; red means the filter needs correction. Clear the filter to show every packet.");
            ImGui::SeparatorText("Sources");
            ImGui::TextWrapped("Standard Ethernet uses Npcap on Windows and libpcap elsewhere. Intrepid devices use libicsneo. Listing a source does not start it. Capture options include promiscuous mode and a capture filter.");
        }
        ImGui::End(); if(!open) doc_.clear();
    }
}
}
