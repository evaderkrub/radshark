// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// sources.h -- the capture sources: a file, a local interface (libpcap), the
// Vehicle Spy engine (corelib, through the host's monitor API), the second
// engine (vspyx / libx, through the host's raw Ethernet tap), and an Intrepid
// device driven straight through libicsneo.
//
// Listing is cheap and main-thread; opening returns a FrameSource whose
// poll() is called every host frame. Sources that are not compiled in
// (no libpcap, no libicsneo) still list -- as one greyed entry that says why.
#pragma once
#include "frame_source.h"



#include <memory>
#include <string>
#include <vector>

namespace vspyshark {

// --- File --------------------------------------------------------------
std::unique_ptr<FrameSource> OpenFileSource(const std::string& path, std::string& error);

// --- Local interface (libpcap) -----------------------------------------
bool LocalCaptureAvailable();
std::vector<SourceEntry> ListLocalInterfaces();
std::unique_ptr<FrameSource> OpenLocalInterface(const std::string& id, bool promiscuous,
                                                const std::string& bpf);

// --- libicsneo ---------------------------------------------------------
bool IcsneoAvailable();
// rescan = ask the library again (USB enumeration takes a moment; the list
// is cached otherwise).
std::vector<SourceEntry> ListIcsneoDevices(bool rescan);
std::unique_ptr<FrameSource> OpenIcsneoDevice(const std::string& serial);

} // namespace vspyshark
