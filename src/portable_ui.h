// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#pragma once
#include "services.h"
#include <filesystem>
#include <map>
namespace radshark {
// Shared file browser/help for the standalone shell and SDKs without a file picker.
class PortableUi {
public:
    void Bind(Services&);
    void Draw();
private:
    std::filesystem::path directory_=std::filesystem::current_path();
    char filename_[1024]={};
    char location_[2048]={};
    bool requested_=false,save_=false,ready_=false;
    int tag_=0;
    std::string picked_,error_,doc_;
};
}
