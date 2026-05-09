# mofballs.py

Generates a WMI permanent subscription MOF: `__EventFilter` (new `Win32_Process`) + `CommandLineEventConsumer` + binding. The first line is `#pragma autorecover` so `mofcomp` records the MOF path for repository rebuild.

**Apply (Windows, elevated):** `mofcomp C:\path\to\out.mof`

---

### `--filter process_name` — exact image name

```bash
python3 tools/mofballs.py --filter process_name --match notepad.exe \
  --command-line-template "cmd.exe /c echo hello" -o out.mof
```

### `--filter process_name_contains` — substring in image name

Use a `--match` that is **not** a substring of the consumer binary (e.g. do not match `cmd` while running `cmd.exe`, or each run retriggers the filter).

```bash
python3 tools/mofballs.py --filter process_name_contains --match notepad \
  --command-line-template "cmd.exe /c echo hello" -o out.mof
```

### `--filter process_commandline_contains` — substring in full command line

```bash
python3 tools/mofballs.py --filter process_commandline_contains --match "-enc " \
  --command-line-template "cmd.exe /c echo hello" -o out.mof
```

---

**Optional:** `--poll-within 2` (event polling interval), `-o file.mof`, `--json-meta` (metadata line on stderr).



