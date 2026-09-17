# Architecture

RadShark is a standalone packet analyzer with a FreeWili GUI plugin. Both
compile the same packet model and UI. The standalone application does not
require a host SDK or a host engine.

## Repository boundary

- **radshark:** application shell, capture backends, packet model, analyzer UI,
  the public plugin adapter and UI tests.
- **wirespy:** decoder server, wire protocol, C++ client and capture-file I/O.
  RadShark consumes the client through `RADSHARK_WIRESPY_DIR`; decoding happens
  in a separate `wirespy_server` process. No decoder libraries enter the GUI binary.

## Layers

| Directory | Responsibility |
| --- | --- |
| `src/capture.*` | Packet ownership, asynchronous decoding, display and column filters |
| `src/sources/` | Capture files, libpcap/Npcap interfaces, libicsneo devices |
| `src/shark_view.*` | Shared packet list, protocol tree, bytes, capture controls |
| `src/services.*` | GUI-thread callbacks for settings, logging, fonts, dialogs and optional host sources |
| `src/analyzer.h` | Shared analyzer lifecycle and agent-tool behavior |
| `app/` | SDL3 standalone window, renderer, settings and ImGui UI tests |
| `plugins/freewiligui/` | Public FreeWili GUI SDK adapter |

Standalone and FreeWili GUI expose files, standard network interfaces and Intrepid
devices. Embedding hosts may supply additional sources through the service callbacks.
Private adapters and engine integrations live in their host repositories.

## Ownership and compatibility

All application state and host callbacks run on the GUI thread. Capture workers
queue raw frames. The decoder worker sees immutable frame copies and returns
results through a queue. Stop, shutdown and plugin unload join workers before
their code or callbacks disappear.

The public FreeWili adapter uses plugin id `com.intrepidcs.radshark`, view id
`shark` and `radshark_*` MCP tools. Install one adapter per host to avoid two
analyzer windows. The public FreeWili GUI SDK remains a separate repository.

Plugin binaries must match the host's architecture, MSVC runtime, compiler and
ImGui/ImPlot/test-engine fingerprint. Shared-library compatibility is established
by loading and executing the binary in each supported host, not by its filename.

Enumeration does not open devices or start capture. User capture actions may open
an interface or put an Intrepid device online. Agent capture tools preserve the
existing policy: engine watchers and stopping only; device capture starts in the UI.
