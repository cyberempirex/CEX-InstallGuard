# Termux

CEX-InstallGuard runs on Termux with only Python — no runtime package
beyond the standard library is required.

```bash
pkg update
pkg install python unzip
cd ~/storage/downloads
unzip CEX-InstallGuard-13.0.0.zip
cd CEX-InstallGuard
python -m cex_installguard examples/dangerous.sh --no-color
python -m cex_installguard . --recursive --json scan.json
```

Notes:

- Colors are auto-detected; pass `--no-color` (or set `NO_COLOR=1`) for
  plain output in a minimal terminal.
- Scanning is fully offline and never executes the analyzed scripts.
- A project config (`.cex-installguard.json`) and an ignore file
  (`.installguardignore`) are discovered automatically; pass `--no-rc` to
  disable discovery.
