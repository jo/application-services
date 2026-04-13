# validate_logins — scratch tooling for origin validation

Not intended to land. Used to investigate how login validation behaves
against real-world data from telemetry.

## Setup

If you run into NSS-related linker/runtime errors, you may need to add:
to your `~/.zshrc` (one-time):

```bash
export NSS_DIR=/path/to/application-services/libs/desktop/darwin-aarch64/nss
export NSS_STATIC=1
```

## Workflow

### 1. Get data from STMO


### 2. Convert and validate

From `components/logins/`:

```bash
python3 tools/stmo_to_ndjson.py src/bin/<file>.csv \
  | cargo run --bin validate_logins \
  > src/bin/results.txt
```

Alternatively, run

```
cat ~/CSV-EXPORT.json \
  | ./tools/massage-logins.sh \
  | cargo run --bin validate_logins --features ignore_form_action_origin_validation_errors
```

which also does further origin normalization.


### 3. Read results

Each line in `results.txt` corresponds to one entry:

| Output | Meaning |
|---|---|
| `[i] ok` | Entry is already valid, no fixup needed |
| `[i] fixed: ...` | Entry was invalid but could be repaired automatically |
| `[i] invalid: ...` | Entry is broken and cannot be repaired |


## What the validator checks

- `origin` must be a valid, normalized URL (e.g. `https://example.com` not `example.com`)
- Exactly one of `form_action_origin` or `http_realm` must be set
- No nul bytes or newlines in any field
- `password` must not be empty

### What can be fixed automatically

- URLs with path/query/fragment → truncated to origin (`https://example.com/login` → `https://example.com`)
- `form_action_origin = "."` → replaced with `""`
- Both `form_action_origin` and `http_realm` set → `http_realm` removed
- `username_field`/`password_field` set without `form_action_origin` → cleared

### What cannot be fixed

- Origins without a scheme (`example.com`, `ftp.foo.net/`) → `relative URL without a base`
- Origins with empty host (`https://`) → `empty host`
- Completely unparseable origins
