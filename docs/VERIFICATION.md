# Windows verification — 2026-09-15

Built with MSVC 19.50, x64, static release CRT, Dear ImGui 1.92.8 docking,
ImPlot 1.0, and ImGui test-engine support enabled. The decoder runtime uses
Wireshark 4.6.5.

| Check | Result |
| --- | --- |
| Standalone app with Npcap and libicsneo | Built and launched |
| Real Npcap loopback capture | Generated UDP payload received; capture stopped cleanly |
| Standalone ImGui tests | Welcome/options, 16-packet decode/details/filter/export, file browser passed |
| Standalone screenshots | Empty and populated states inspected; 860 × 650 layout inspected |
| Public FreeWili plugin in fwcom | Same DLL loaded and drew in host harness and actual GUI; decoder ready |
| Independent wirespy repository | Fresh server, client and CLI build succeeded after GUI relocation |

Live local-interface traffic was also observed decoding in the FreeWili GUI
plugin. No Intrepid device was detected: libicsneo support is compiled and its
enumeration runs, but capture from physical Intrepid hardware remains unverified.
Linux and macOS have build entry points but were not run on this Windows machine.

Reproduce standalone checks with `scripts/build.ps1 -Test`; reproduce public
plugin compatibility with `scripts/test-fwgui.ps1`. Read `uitest_results.txt`
for UI verdicts. Private host verification is maintained in those repositories.
