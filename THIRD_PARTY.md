# Third-party dependencies

The [MIT license](LICENSE) covers RadShark's own source, documentation and
included assets. It does not replace the licenses of dependencies or a
separately distributed decoder. Dependency source and binaries are not
vendored in this repository; CMake fetches dependencies or uses configured
local installations.

## Application and plugin

| Dependency | Use | License information |
| --- | --- | --- |
| [wirespy client](https://github.com/evaderkrub/wirespy/tree/main/src/client) | Capture-file I/O and decoder protocol | MIT; see wirespy's `LICENSE-MIT` and `LICENSING.md` |
| [SDL3](https://github.com/libsdl-org/SDL/blob/release-3.4.10/LICENSE.txt) | Standalone window and renderer | zlib |
| [Dear ImGui](https://github.com/ocornut/imgui/blob/v1.92.8-docking/LICENSE.txt) | User interface | MIT |
| [ImPlot](https://github.com/epezent/implot/blob/v1.0/LICENSE) | GUI dependency | MIT |
| [nlohmann/json](https://github.com/nlohmann/json/blob/v3.11.3/LICENSE.MIT) | JSON messages and settings | MIT |
| FreeWili GUI SDK | Optional public plugin adapter | MIT; retain the license from the SDK checkout used for the build |

## Capture and testing

- **libpcap:** the standard network-interface backend uses libpcap on POSIX
  systems. Retain the [upstream license](https://github.com/the-tcpdump-group/libpcap/blob/master/LICENSE)
  for the version distributed.
- **Npcap:** the Windows backend uses the installed Npcap runtime and SDK.
  Npcap's [use and redistribution terms](https://npcap.com/guide/npcap-users-guide.html)
  are separate from this repository's MIT license. No Npcap installer or driver
  is included here.
- **libicsneo:** optional direct capture from Intrepid devices uses
  [Intrepid's license](https://github.com/intrepidcs/libicsneo/blob/master/LICENSE),
  including its restriction on use with other manufacturers' vehicle-networking
  hardware. It is not MIT. Dependencies linked with libicsneo retain their own
  licenses. Disable this backend with `RADSHARK_WITH_ICSNEO=OFF` if unneeded.
- **Dear ImGui Test Engine:** the default development configuration enables it
  under the [Dear ImGui Test Engine License](https://github.com/ocornut/imgui_test_engine/blob/v1.92.8/imgui_test_engine/LICENSE.txt).
  Its free and paid license conditions are separate from MIT. Disable it with
  `RADSHARK_TEST_ENGINE=OFF` for a standalone build without that dependency.
  Plugin builds must match the host's test-engine configuration.

## Decoder process and distributions

Packet dissection runs in the separate `wirespy_server` process, which links
Wireshark and is licensed under GPL-2.0-or-later. The application and plugin
communicate with it through the MIT-licensed wirespy client; they do not link
Wireshark libraries. See [wirespy's licensing documentation](https://github.com/evaderkrub/wirespy/blob/main/LICENSING.md)
and [Wireshark's licensing FAQ](https://www.wireshark.org/faq.html#derived_work).

`RADSHARK_SERVER_DIST` can copy a locally staged decoder bundle beside the
application or plugin. A distribution containing that bundle must retain the
decoder and dependency notices and provide the corresponding source required
by their licenses. The MIT license on RadShark does not relicense that bundle.

When distributing binaries, retain the license notices required by the exact
versions of all included libraries. This repository publishes source code and
icon assets, without prebuilt applications, plugin DLLs or decoder bundles.
