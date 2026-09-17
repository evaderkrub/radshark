# Application icon

`radshark.png` is the original artwork with transparent corners.
`radshark.ico` contains 16, 20, 24, 32, 40, 48, 64, 128 and 256 pixel frames.
Regenerate the ICO on Windows with `powershell -File scripts/build-icon.ps1`.

The Windows executable embeds resource 1 from `radshark.rc`. SDL3 adopts the
first icon resource for the window class, so Explorer, the title bar and taskbar
use the same artwork without needing an external image file at runtime.

The icon assets are distributed under the project's [MIT license](../LICENSE).
