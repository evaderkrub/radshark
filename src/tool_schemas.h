// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

#pragma once
namespace radshark {
constexpr const char* kStateSchema = R"JSON({"type":"object","properties":{}})JSON";
constexpr const char* kPacketsSchema = R"JSON({"type":"object","properties":{
  "first":{"type":"integer","description":"first row (0-based) of the displayed list"},
  "count":{"type":"integer","description":"how many rows, at most 500"},
  "all":{"type":"boolean","description":"true: walk every packet, not just the ones the display filter shows"}}})JSON";
constexpr const char* kPacketSchema = R"JSON({"type":"object","properties":{
  "number":{"type":"integer","description":"the packet number (the No. column, 1-based)"},
  "select":{"type":"boolean","description":"also select it in the view (details and bytes panes follow)"}},"required":["number"]})JSON";
constexpr const char* kFilterSchema = R"JSON({"type":"object","properties":{
  "filter":{"type":"string","description":"a Wireshark display filter, empty to clear"}},"required":["filter"]})JSON";
constexpr const char* kColumnFilterSchema = R"JSON({"type":"object","properties":{
  "column":{"type":"string","description":"a column title (No., Time, Source, Destination, Protocol, Length, Info) or its index"},
  "text":{"type":"string","description":"the filter: text, =exact, !not, and on numeric columns >n, <n, a-b; empty clears"},
  "enabled":{"type":"boolean","description":"the master switch for the whole filter row (optional)"}}})JSON";
constexpr const char* kSaveSchema = R"JSON({"type":"object","properties":{
  "path":{"type":"string","description":"where to write: .pcapng for pcapng, anything else is classic nanosecond pcap"},
  "displayed_only":{"type":"boolean","description":"write only the packets the filters currently show"}},"required":["path"]})JSON";
constexpr const char* kOpenSchema = R"JSON({"type":"object","properties":{
  "path":{"type":"string","description":"a pcap / pcapng file"}},"required":["path"]})JSON";
constexpr const char* kCaptureSchema = R"JSON({"type":"object","properties":{
  "action":{"type":"string","enum":["start","stop"]},
  "source":{"type":"string","enum":["corelib","libx"],"description":"start: which engine to watch"}},"required":["action"]})JSON";

}
