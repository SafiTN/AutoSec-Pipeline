# Bundled fonts

Inter (SIL OFL 1.1), static 24pt instances from the Google Fonts "Inter" download
(upstream project: https://github.com/rsms/inter, https://fonts.google.com/specimen/Inter).
Full license text: `OFL.txt`.

| File | Source file | SHA-256 |
|------|-------------|---------|
| `Inter-Regular.ttf` | `static/Inter_24pt-Regular.ttf` | `d2a4911506ea4e124a47ca044e5e79f671ddf8f1a55f1ab9a56c58d088124b63` |
| `Inter-Bold.ttf` | `static/Inter_24pt-Bold.ttf` | `9a2a0b55e203727936212904dedea502e678ba0d6c27851cab1f5eec3d23ef98` |
| `OFL.txt` | `OFL.txt` | `3c8d13d97ea5eb62868833a377034c6be6a9833e768d32abec2a767a8101e4bc` |

Font file names and sizes are configured under `media.slide` in `config/settings.yaml`.
The optional `media.slide.fonts.mono` slot is empty by default and falls back to the regular font.
If a monospace font is ever added, its license text must be shipped here too.
