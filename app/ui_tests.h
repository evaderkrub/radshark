// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#pragma once
#include "analyzer.h"
struct ImGuiTestEngine;
struct SharkUiTests {
    vspyshark::Analyzer* analyzer=nullptr;
    std::string screenshot;
};
void RegisterSharkTests(ImGuiTestEngine*,SharkUiTests&);
