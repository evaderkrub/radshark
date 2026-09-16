// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#include "services.h"
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstdio>

namespace vspyshark {
double Services::SettingsGetNumber(const char* key,double fallback) const {
    std::string s(SettingsGet(key));
    if(s.empty()) return fallback;
    char* end=nullptr;
    const double value=std::strtod(s.c_str(),&end);
    return end==s.c_str()+s.size() && std::isfinite(value) ? value : fallback;
}
void Services::SettingsSetNumber(const char* key,double value) const {
    char text[64]; std::snprintf(text,sizeof text,"%.17g",value); SettingsSet(key,text);
}
bool Services::Splitter(const char* id,float& size,float extent,float before,float after,bool vertical) const {
    const float available=vertical?ImGui::GetContentRegionAvail().x:ImGui::GetContentRegionAvail().y;
    const float maximum=std::max(before, extent>0 ? extent-after : size+available-after);
    size=std::clamp(size,before,maximum);
    ImGui::InvisibleButton(id,vertical?ImVec2(5,available):ImVec2(ImGui::GetContentRegionAvail().x,5));
    if(ImGui::IsItemHovered() || ImGui::IsItemActive()) ImGui::SetMouseCursor(vertical?ImGuiMouseCursor_ResizeEW:ImGuiMouseCursor_ResizeNS);
    if(!ImGui::IsItemActive()) return false;
    const float delta=vertical?ImGui::GetIO().MouseDelta.x:ImGui::GetIO().MouseDelta.y;
    size=std::clamp(size+delta,before,maximum); return delta!=0;
}
}
