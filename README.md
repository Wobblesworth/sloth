# 🦥 Sloth

**Chill 2 Kill.**

Sloth is an automated DFIR analysis platform. Drop forensic evidence — KAPE triages, log files, artifacts — and Sloth parses, indexes, and visualizes everything in Elasticsearch + Kibana. No manual work required.

## Features

- **Automated pipeline**: drop evidence in a folder, Sloth does the rest (parallel processing supported)
- **Multi-format support**: KAPE triages, Windows artifacts, web logs, Linux logs, and more
- **Built-in parsers**: Hayabusa (Sigma rules), Plaso (super timeline), Eric Zimmerman tools
- **Pre-built dashboards**: threat detections, timeline analysis, program execution, file system, registry, user activity
- **Portable**: clone the repo, run one command, start analyzing
- **Flexible**: runs on a laptop, a server, or split across multiple machines/VPS

## Requirements

- Docker and Docker Compose
- 8 GB RAM minimum (16 GB recommended)
- 20 GB free disk space (more for large triages)
- Linux (tested on Ubuntu 24.04)

## Quick Start

```bash
git clone https://github.com/Wobblesworth/sloth.git
cd sloth
make setup
make up
```

Kibana will be available at `http://localhost:5601` (give it ~60 seconds to start).

## Usage

```bash
make setup              # First-time setup (create directories, check dependencies)
make up                 # Start all services
make down               # Stop all services (data is preserved)
make status             # Show running containers
make watch              # Watch pipeline activity (human-readable)
make logs               # Follow raw logs (all containers, for debugging)
make restart            # Restart all services
make build              # Build containers (after code changes)
make rebuild            # Rebuild + restart pipeline
make list-cases         # List all cases in Elasticsearch
make clean-case CASE=   # Delete a single case
make clean-all-cases    # Delete all cases (keeps Kibana settings)
make reset              # Delete ALL data and start fresh
make help               # Show available commands
```

### Health Check

```bash
bash scripts/health-check.sh
```

### Watching Pipeline Activity

Use `make watch` to see what Sloth is doing in real time:

```
2026-03-19 22:37:25 === Processing case: cyberoo_NBFZANCHETTA_20260319 ===
2026-03-19 22:37:25 Organization: cyberoo, Host: NBFZANCHETTA, Date: 20260319
2026-03-19 22:37:25 Found 73 EVTX files
2026-03-19 22:37:29 Hayabusa produced 706 events
2026-03-19 22:37:29 Ingested 706 docs into 'sloth-hayabusa-cyberoo_nbfzanchetta_20260319', 0 errors
2026-03-19 22:37:29 Pipeline completed for cyberoo_NBFZANCHETTA_20260319.zip
```

Warnings and errors are highlighted with ⚠ and ✗ symbols.

## Configuration

Copy `.env.example` to `.env` and edit as needed:

| Variable | Default | Description |
|---|---|---|
| `ES_VERSION` | `8.17.0` | Elasticsearch and Kibana version |
| `ES_HEAP` | `2g` | Elasticsearch Java heap size |
| `ES_PORT` | `9200` | Elasticsearch port |
| `KIBANA_PORT` | `5601` | Kibana port |
| `BIND_ADDRESS` | `0.0.0.0` | Listen address (`0.0.0.0` = all interfaces, `127.0.0.1` = local only) |
| `ES_HOST` | `localhost` | Elasticsearch host (change if ES runs on a different machine) |
| `PARALLEL_WORKERS` | `auto` | Parallel evidence processing workers. `auto` = 1 per GB of ES heap, or set a number |
| `DATA_PATH` | `./data` | Where evidence and parsed data are stored |

## Evidence Naming Convention

Name your evidence ZIP files following this pattern:

```
<organization>_<hostname>_<date>.zip
```

Examples:
```
acmecorp_DC01_20260319.zip
clientB_LAPTOP-CFO_20260319.zip
incident42_WKS001_20260315.zip
```

Sloth automatically parses the filename and adds metadata to every event in Elasticsearch:

| Part | ECS Field | Example |
|---|---|---|
| `acmecorp` | `organization.name` | Filter all events by client |
| `DC01` | `case.hostname` | Identify the source machine |
| `20260319` | `case.date` | Date of the triage collection |
| (auto) | `case.id` | `acmecorp_DC01_20260319` (index name) |

This makes it easy to filter in Kibana: `organization.name: acmecorp` shows all triages for that client.

If the filename does not match the convention, Sloth still processes it — metadata fields are simply left empty and a timestamp is appended to ensure a unique case ID.

## Case Management

```bash
make list-cases               # List all cases in Elasticsearch
make clean-case CASE=<id>     # Delete a single case (ES indices + local files)
make clean-all-cases          # Delete all cases (keeps Kibana settings)
```

To reprocess a case:

1. `make clean-case CASE=<case_id>` — removes the case from Elasticsearch
2. Copy the original ZIP from `data/completed/` back into `data/intake/`
3. Sloth will automatically reprocess it

Original ZIP files in `data/completed/` are never deleted by clean commands. Delete them manually if you no longer need them.

## ECS Field Mapping

All parsed events are normalized to [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html). This means consistent field names across all event types, enabling powerful cross-event queries in Kibana:

| Query | What you find |
|---|---|
| `event.category: "authentication" AND event.outcome: "failure"` | All failed logons (any type) |
| `event.category: "network" AND network.protocol: "rdp"` | All RDP activity |
| `event.category: "iam"` | Privilege escalation, password resets, group changes |
| `event.category: "process" AND event.type: "start"` | All process executions |
| `process.hash.sha256: "abc..."` | Find events by file hash |
| `source.ip: "10.0.0.1" AND event.category: "authentication"` | Logons from a specific IP |

Key normalized fields set on every event:
- `event.category` — what kind of event (`authentication`, `process`, `network`, `file`, `iam`, `registry`, `configuration`, `malware`)
- `event.type` — what happened (`start`, `end`, `access`, `creation`, `change`, `deletion`)
- `event.outcome` — did it succeed? (`success`, `failure`)
- `event.action` — specific action (`logon-success`, `file-created`, `rdp-logon`, `password-reset`, etc.)

## Architecture

```
evidence (zip/logs/artifacts)
       │
       ▼
  data/intake/          ← drop files here
       │
  [Pipeline]            ← auto-detect, parse, ingest (parallel workers)
       │
  Elasticsearch         ← search and store (ECS-normalized)
       │
  Kibana                ← analyze in your browser
```

## Project Structure

```
sloth/
├── docker-compose.yml      # Container orchestration
├── .env.example            # Configuration template
├── Makefile                # Command shortcuts
├── scripts/
│   ├── setup.sh            # First-time setup
│   └── health-check.sh     # Service health check
├── containers/
│   └── pipeline/
│       ├── mappings/       # Elasticsearch index templates (ECS-aligned)
│       └── parsers/        # Parser modules (Hayabusa, MFT, etc.)
├── dashboards/             # Pre-built Kibana dashboards (coming soon)
├── docs/                   # Additional documentation (coming soon)
└── data/                   # Evidence and runtime data (git-ignored)
    ├── intake/             # Drop evidence here
    ├── processing/         # Currently being parsed
    ├── completed/          # Successfully processed
    ├── failed/             # Processing errors
    └── elasticsearch/      # ES data persistence
```

## Roadmap

- [x] Phase 1: Foundation (Elasticsearch + Kibana)
- [x] Phase 2: Pipeline + Hayabusa (automated threat detection, 50 event-type handlers, ECS normalization)
- [ ] Phase 3: EZ Tools (MFT, Registry, Prefetch, EVTX parsing)
- [ ] Phase 4: Plaso (super timeline generation)
- [ ] Phase 5: Pre-built dashboards
- [ ] Phase 6: Hardening and edge cases

## License

MIT
