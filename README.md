# RadShark

An independent Ethernet packet analyzer with a standalone desktop application
and a plugin for FreeWili GUI.

- Capture from standard Ethernet/Wi-Fi interfaces through Npcap or libpcap.
- Capture Ethernet and Automotive Ethernet from Intrepid devices through libicsneo.
- Open and save pcap and pcapng captures.
- Inspect decoded packet columns, protocol trees and bytes; apply Wireshark display
  filters and per-column filters.
- Use the same analyzer UI in the standalone application and FreeWili GUI.

The [wirespy repository](https://github.com/evaderkrub/wirespy) is separate.
Its decoder runs as a separate process; RadShark links only its MIT-licensed
C++ client. See [architecture](docs/ARCHITECTURE.md).

## Build on Windows

Requires Visual Studio C++ tools, CMake and Ninja. Build output defaults to
`C:/buildfiles/radshark`, outside the source directory.
SDL3, Dear ImGui, ImPlot and nlohmann/json are fetched at pinned versions; their
standard `FETCHCONTENT_SOURCE_DIR_*` overrides can use local source caches.

```powershell
.\scripts\build.ps1
C:\buildfiles\radshark\radshark.exe
```

Place `wirespy` beside this repository, or pass
`-DRADSHARK_WIRESPY_DIR=<checkout>`. Point `RADSHARK_SERVER_DIST` at a staged
wirespy runtime folder; the build copies its decoder, DLLs and data alongside the
application. `WIRESPY_SERVER` can instead name a decoder executable at runtime.
Build the decoder using wirespy's own `scripts/build-server-msys2.sh`.

### Capture dependencies

Install Npcap for interface capture on Windows. Configure its SDK using
`RADSHARK_NPCAP_SDK`, `NPCAP_SDK`, or `C:/npcap-sdk`.

Configure libicsneo using:

- `RADSHARK_ICSNEO_INCLUDE`: directory containing `icsneo/icsneocpp.h`.
- `RADSHARK_ICSNEO_LIBRARY`: matching libicsneocpp static library.
- `RADSHARK_ICSNEO_DEPENDENCIES`: its matching dependency libraries, separated by
  semicolons. The current Windows build needs libredxx, fatfs, the bootloader,
  Protobuf/Abseil, minizip and zlib.

Use libraries built with the same compiler and static runtime. These dependencies
come from libicsneo; Vehicle Spy is not required. Omitted capture libraries leave
their source unavailable with an explanation in the capture list.

## Plugins

### FreeWili GUI

```powershell
.\scripts\build.ps1 -Plugins
```

Set `FREEWILIGUI_SDK_DIR` to the standalone SDK checkout if it is not found in the
usual sibling layout. The result is `C:/buildfiles/radshark/plugins/fwgui_radshark.dll`.
Install it in the host's plugin directory and stage the wirespy runtime in
`<host executable directory>/wirespy/`. Open **Tools > RadShark**. This public
SDK plugin requires matching host architecture, runtime and GUI fingerprints.

`scripts/install-fwgui.ps1 -HostDir <host directory>` installs the plugin and
decoder runtime together. Restart the host after installation.

## Run and test

```powershell
radshark.exe --open capture.pcapng
radshark.exe --list-sources
.\scripts\build.ps1 -Test
```

`--list-sources` enumerates capabilities without starting capture. UI tests use
the Dear ImGui test engine and the bundled sample capture. Read
`uitest_results.txt` and `uitest_results_junit.xml` in the build directory;
screenshots include the empty capture list and decoded packets. Tests do not
capture real devices or persist user settings.

`scripts/test-fwgui.ps1` loads and executes the FreeWili plugin DLL in the host's
compatibility harness. It accepts the application and host build directories.
Other host integrations maintain their compatibility checks in their own repositories.

The `scripts/build.sh` entry point supports native POSIX builds with SDL3 and
libpcap. Windows is the initial verified platform for the standalone application.

Standalone settings live in `%APPDATA%/IntrepidCS/RadShark/` on Windows.

## License

RadShark's source, documentation and included assets are licensed under the
[MIT License](LICENSE). Dependencies retain their own licenses; see
[THIRD_PARTY.md](THIRD_PARTY.md). The separate wirespy decoder is GPL-2.0-or-later
and is not linked into the application or plugin.

The default development build enables Dear ImGui Test Engine, which has its
own license. A standalone build without it can be configured with
`-DRADSHARK_TEST_ENGINE=OFF -DRADSHARK_BUILD_TESTS=OFF`. Plugin builds must
match the host's GUI and test-engine fingerprints.
