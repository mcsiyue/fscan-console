# Tests

```bash
python -m unittest discover -s tests -v
```

- `test_args.py` — pure unit tests for fscan argument construction; no binary or network required.
- `smoke_scan.py` — optional integration smoke test; needs `tools/fscan.exe` and takes about 15 seconds:

```bash
python scripts/fetch_fscan.py
python tests/smoke_scan.py
```

`smoke_scan.py` writes its temporary data under `tests/tmpdata/` (ignored by git).
