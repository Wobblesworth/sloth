# Sloth — Automated DFIR Analysis Platform

## Architecture
3 Docker containers on `sloth-net` bridge network:
- **elasticsearch** — indexes parsed evidence (security disabled, single-node)
- **kibana** — visualization UI at :5601
- **pipeline** — Python 3.12 watcher that polls `data/intake/`, auto-detects evidence, parses with Hayabusa, transforms to ECS, bulk-ingests into ES. Supports parallel workers (configurable via `PARALLEL_WORKERS`)

Evidence flow: ZIP dropped in `data/intake/` → extract → Hayabusa parse (verbose profile) → event-type-aware ECS transform → bulk ingest → Kibana

## Commands
```
make setup          # first-time init (creates dirs, checks Docker/RAM/disk)
make up             # start all services
make down           # stop all services (data preserved)
make build          # rebuild pipeline container after code changes
make rebuild        # stop + rebuild + restart pipeline
make test           # validate shell, docker-compose, JSON, Python syntax (no services needed)
make logs           # follow all container logs
make watch          # filtered pipeline logs with color
make status         # show container status
make list-cases     # list ES indices with doc counts
make clean-case CASE=<id>   # delete single case from ES + disk
make clean-all-cases        # delete all cases (preserves Kibana config)
make reset          # full wipe (asks confirmation)
```

## Code Conventions
- All files, comments, variable names, and documentation MUST be in English
- Shell scripts: `set -euo pipefail`, quote all variables, use `#!/usr/bin/env bash`
- Python: no type annotations unless already present, keep dependencies minimal
- Elasticsearch mappings: ECS-aligned field names (event.*, host.*, process.*, threat.*)
- Index naming: `sloth-{parser}-{case_id}` (lowercase)

## Evidence Naming Convention
`<organization>_<hostname>_<YYYYMMDD>.zip` — parsed by regex `^([^_]+)_(.+)_(\d{8})$`
Metadata extracted: `organization.name`, `case.hostname`, `case.date`, `case.id`

## Key Files
- `containers/pipeline/watcher.py` — main entry point, parallel worker pool, polling loop
- `containers/pipeline/process.py` — orchestrates extract → parse → ingest for a single ZIP
- `containers/pipeline/ingest.py` — ES bulk ingestion + template loading
- `containers/pipeline/parsers/hayabusa.py` — event-type-aware Hayabusa → ECS transform (dispatcher pattern, 50 handlers)
- `containers/pipeline/parsers/test_hayabusa.py` — unit tests for hayabusa parser
- `containers/pipeline/mappings/hayabusa.json` — ES index template (full ECS field mappings)
- `scripts/clean-cases.sh` — case cleanup (stops pipeline, deletes indices + dirs)

## Current State
- Phase 1 (foundation) and Phase 2 (Hayabusa pipeline) are complete
- Next: Phase 3 (EZ Tools: MFT, Registry, Prefetch), Phase 4 (Plaso), Phase 5 (dashboards)

## Workflow Tips
When starting a session, suggest the best approach for the task at hand:
- **Before a new phase/feature**: use interview mode — ask the user detailed questions about requirements, edge cases, and tradeoffs before writing any code
- **Before non-trivial changes**: enter Plan Mode (explore + plan first, implement after alignment)
- **New parser implementation**: TDD — write a test with expected input/output first, commit it, then implement the parser to pass the test
- **After implementing code**: run `make test` to validate shell, JSON, docker-compose, and Python syntax
- **After modifying shell scripts**: shellcheck runs automatically via hook (`.claude/settings.json`)
- **Reviewing own work**: suggest a fresh `/clear` + review session (clean context catches bugs the implementation session misses)
- **Multiple independent features**: suggest git worktrees (`claude --worktree feature-name`) to work in parallel without conflicts
- **Between unrelated tasks**: suggest `/clear` to keep context clean — don't mix pipeline work with dashboard work in the same session
- **Large exploration needed**: use `/compact` when context gets long, before it degrades output quality

## Parallel Workers
- `PARALLEL_WORKERS=auto` (default): 1 worker per GB of `ES_HEAP` (2g → 2 workers, 4g → 4)
- Or set explicit number: `PARALLEL_WORKERS=3`
- Workers use `ThreadPoolExecutor` — each runs the full pipeline (extract → Hayabusa → ingest) for one ZIP
- `process_zip()` is thread-safe: each invocation uses its own paths, lock file, and ES connection

## Hayabusa Parser
- Event-type-aware dispatcher: 50 handlers for specific Channel/EventID combinations (~90% coverage on real triages)
- Unhandled event types fall back to generic extraction (User, Proc, Cmdline, PID)
- ECS namespaces: `process.*`, `source.*`, `destination.*`, `network.*`, `file.*`, `dll.*`, `registry.*`, `winlog.*`, `powershell.*`, `url.*`, `service.*`, `group.*`, `task.*`
- **Normalized ECS fields** set by every handler:
  - `event.category` — array: `authentication`, `process`, `network`, `file`, `registry`, `iam`, `configuration`, `malware`, `driver`
  - `event.type` — array: `start`, `end`, `access`, `creation`, `change`, `deletion`, `info`, `connection`, `protocol`, `admin`
  - `event.outcome` — `success` or `failure` (where deterministic)
  - `event.action` — specific per event (e.g. `logon-success`, `file-created`, `rdp-logon`, `password-reset`)
- `network.protocol` set for RDP and SMB events (including logon type 10 on Sec/4624)
- Hash strings parsed into `process.hash.sha1/md5/sha256` and `process.pe.imphash`
- User strings parsed into `user.name` + `user.domain` (handles `DOMAIN\User` format, skips `n/a` and `-`)
- `winlog.*` fields duplicate base fields (event_id, channel, computer_name, record_id)
- `winlog.logon.type` enriches `event.category` for 4624/4625/4634 (Type 10 → adds `network` + `network.protocol: rdp`)
- ExtraFieldInfo: high-value fields extracted to ECS (`ParentImage`, `CurrentDirectory`, `OriginalFileName`, `TargetDomainName`, `TargetUserSid`, `SubjectDomainName`, `SubjectUserSid`, `IpPort`); rest preserved in `event.extra` (flattened)
- `event.original_details` (flattened) contains only unmapped Details fields — should be nearly empty for handled events

## ECS Normalization Conventions
### Universal queryability
Pivot fields MUST be populated on every event where the information exists, regardless of event type. A single Kibana query on a pivot field must match across all event types. Specific/contextual fields (user.target.*, source.port, process.parent.*) enrich but never replace pivot fields.

Pivot fields: `user.name`, `source.ip`, `process.executable`, `host.name`, `event.category`, `event.action`, `event.outcome`

Example: Sec/4624 has TgtUser="Administrator" → set BOTH `user.name: "Administrator"` AND `user.target.name: "Administrator"`. Sec/4648 has SrcUser="bob" and TgtUser="admin" → `user.name: "bob"`, `user.target.name: "admin"` — both queryable.

When adding new parsers or handlers, follow these conventions to keep data consistent across all parsers:
- **Always set** `event.category`, `event.type`, and `event.outcome` on every handler
- `event.category` and `event.type` are **arrays** — an RDP logon is `["authentication", "network"]`
- Use ECS-standard values only (see list above) — do not invent new categories
- `event.outcome` = `success`/`failure` — omit if the outcome is ambiguous (e.g. RDP connection attempt)
- `event.action` = lowercase-kebab-case, specific to the event (e.g. `logon-success`, not `logon`)
- `network.protocol` = set whenever the protocol is known (`rdp`, `smb`, `tcp`, etc.)
- Pop consumed fields from `details` dict — remaining fields go to `event.original_details` catchall
- Pop Hayabusa-internal fields (`PGUID`, `LGUID`, `ParentPGUID`, `Rule`) to keep catchall clean
- Parse `DOMAIN\User` into `user.name` + `user.domain` via `parse_user()` — skip `n/a` and `-`
- Parse hash strings via `parse_hashes()` — split into per-algorithm fields
- For source/target process patterns (Sysmon/8, 10): use `process.*` for source, `process.target.*` for target
- For logon events: user who logged on goes in BOTH `user.*` AND `user.target.*` (queryable with either). Only use `user.target.*` alone when there is a distinct subject (e.g. 4648 explicit logon has SrcUser in `user.*` and TgtUser in `user.target.*`)
- Extract high-value ExtraFieldInfo fields into ECS where a direct mapping exists; leave the rest in `event.extra`

## Gotchas
- Host needs `vm.max_map_count=262144` for Elasticsearch (`sysctl -w vm.max_map_count=262144`)
- Pipeline runs as non-root (UID/GID from .env) — file permissions matter on bind mounts
- Hayabusa binary is downloaded at Docker build time — rebuild if version changes
- `data/elasticsearch/` is bind-mounted — never delete while ES is running
- Original ZIPs are always preserved in `data/completed/`, never deleted by clean commands
- With parallel workers, ES heap is the limiting factor — more workers than heap GBs causes GC pressure
