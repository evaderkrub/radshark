// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Dave Robins

// doc.h -- the help pages VSpy Shark carries in the binary.
#pragma once

namespace vspyshark {

static constexpr const char* kDocIndex = R"MD(
# VSpy Shark

*VSpy Shark* is a standalone Ethernet analyzer with a plugin for FreeWili GUI.
Its shared interface is Wireshark-shaped: the
same three panes (packet list, packet details, packet bytes), Wireshark's own
summary columns, colouring rules and display filters.

The dissection really is Wireshark's: the packets go to `libwireshark` in a
separate helper process, `wirespy_server`, which the application or plugin host
starts from `<exe>/wirespy/` and stops on shutdown.

## Sources

Choose one on the Welcome page (double-click), in *Capture > Options...*, or
with the shark-fin button once a source is remembered.

| Source | What it is |
|---|---|
| Local interface | A network adapter through libpcap (needs capture privileges: Npcap on Windows, `CAP_NET_RAW` or root on Linux). Promiscuous mode and a BPF capture filter are in *Capture > Options...*. |
| Host source | Additional traffic supplied by an embedding host, when available. Watching a host source does not start its engine. |
| libicsneo device | An Intrepid device opened directly through libicsneo. Another application may already hold the device. |
| File | A pcap or pcapng file (*File > Open...*, or drop it on the recent list). |

## The window

- **Display filter bar** -- a Wireshark display filter (`tcp.port == 80`,
  `ip.addr == 10.0.0.1 && !arp`, `someip`, `doip`...). Enter applies it; the
  bar turns green when it compiled and red (with the reason on hover) when it
  did not. Applying a filter re-dissects the capture so relative times and
  packet numbers stay Wireshark's.
- **Packet list** -- Wireshark's columns and colouring rules. Click a row for
  its details; Up / Down, Ctrl+Home / Ctrl+End move the selection; *Go > Go
  to Packet...* jumps by number; *Edit > Find Packet...* searches the columns.
- **Column filters** -- the Messages view's filter row, under the header
  (the funnel button, *View > Column Filters*, or F). One box per column,
  Enter applies: plain text is a case-insensitive substring, `=x` exact,
  `!x` excludes, and on No. / Time / Length `>n`, `<n`, `a-b` are numeric.
  Right-click a box for the values seen so far and *(All)*. They compose with
  the display filter and need no re-dissection.
- **Packet details** -- the dissection tree. Click a field to highlight its
  bytes (dark blue) and its protocol's bytes (light blue) below; expansion is
  remembered per protocol. Right-click: *Apply as Filter*, *Prepare as
  Filter*, *Copy*.
- **Packet bytes** -- offset, hex, ASCII. Click a byte to select the smallest
  field that holds it.
- **Status bar** -- the selected field (name and size), the capture source or
  file, packet / displayed counts, and the dissector's state.

*File > Save As...* writes the capture as pcapng when the name ends in
`.pcapng` (one interface per link type, nanosecond timestamps, interface
names as packet comments) and as classic nanosecond pcap otherwise; *Export
Specified Packets...* writes only the packets the filters show. Both come
back through *File > Open...* unchanged.

## Not here

Wireshark's statistics windows, Follow Stream, Decode As, expert info and
the preferences dialog are not ported. The columns are the profile's
defaults; there is no column editor.

## MCP

`vspyshark_state`, `vspyshark_packets`, `vspyshark_packet`,
`vspyshark_filter`, `vspyshark_column_filter`, `vspyshark_open`,
`vspyshark_save`, `vspyshark_sources`, and
`vspyshark_capture` (which starts only the corelib / libx watchers; an
interface or a device is opened from the view, by the user).
)MD";

static constexpr const char* kDocFilters = R"MD(
# Display filters

The filter bar takes Wireshark display filters, evaluated by Wireshark's own
engine. A few to start with:

| Filter | Shows |
|---|---|
| `arp` | ARP only |
| `ip.addr == 192.168.1.10` | packets to or from one host |
| `tcp.port == 80 \|\| tcp.port == 443` | web traffic |
| `udp && !dns` | UDP that is not DNS |
| `someip` / `doip` / `ptp` / `avtp` | the automotive protocols by name |
| `eth.src == 00:fc:70:00:00:01` | one MAC address |
| `frame.len > 1000` | large frames |
| `tcp.analysis.retransmission` | TCP retransmissions |

Right-click a field in the details pane for *Apply as Filter > Selected* to
build one from what is under the mouse.
)MD";

} // namespace vspyshark
