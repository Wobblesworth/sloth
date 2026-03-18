# 🦥 Sloth

**Chill 2 Kill.**

Sloth is an automated DFIR analysis platform. Drop forensic evidence — KAPE triages, log files, artifacts — and Sloth parses, indexes, and visualizes everything in Elasticsearch + Kibana. No manual work required.

## Features

- **Automated pipeline**: drop evidence in a folder, Sloth does the rest
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
make setup      # First-time setup (create directories, check dependencies)
make up         # Start all services
make down       # Stop all services (data is preserved)
make status     # Show running containers
make logs       # Follow live logs
make restart    # Restart all services
make reset      # Delete ALL data and start fresh
make help       # Show available commands
```

### Health Check

```bash
bash scripts/health-check.sh
```

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
| `DATA_PATH` | `./data` | Where evidence and parsed data are stored |

## Architecture

```
evidence (zip/logs/artifacts)
       │
       ▼
  data/intake/          ← drop files here
       │
  [Pipeline]            ← auto-detect, parse, ingest
       │
  Elasticsearch         ← search and store
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
├── containers/             # Custom container definitions (coming soon)
│   └── pipeline/
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
- [ ] Phase 2: Pipeline + Hayabusa (automated threat detection)
- [ ] Phase 3: EZ Tools (MFT, Registry, Prefetch, EVTX parsing)
- [ ] Phase 4: Plaso (super timeline generation)
- [ ] Phase 5: Pre-built dashboards
- [ ] Phase 6: Hardening and edge cases

## License

MIT
