# Log Analyzer Tool

A portable, self-oriented log analysis tool for monitoring cyber security events on isolated networks.

## Project Structure

```
log-analyzer-tool/
├── backend/                    # Python backend
│   ├── analyzers/             # Detection engines
│   ├── api/                   # REST API
│   ├── storage/               # DuckDB interface
│   ├── core/                  # Core utilities
│   ├── auth/                  # Authentication
│   └── tests/                 # Tests
├── frontend/                  # React frontend
│   └── src/
│       ├── components/        # React components
│       ├── pages/             # UI pages
│       ├── services/          # API clients
│       └── utils/             # Frontend utilities
├── config/                    # Configuration files
│   ├── rules/                 # Detection rules
│   └── signatures/            # Attack signatures
├── data/                      # Data storage
│   ├── duckdb/               # DuckDB database files
│   └── archives/             # Raw log archives
├── updates/                   # Update packages
├── docs/                      # Documentation
└── scripts/                   # Deployment scripts
```

## Components

### Backend (Python)
- **Analyzers**: 7 detection methods (signature, anomaly, heuristic, behavioral, rule-based, network, threat intel)
- **API**: FastAPI REST API
- **Storage**: DuckDB query interface
- **Core**: Utilities and shared code
- **Auth**: Authentication and authorization

### Frontend (React + TypeScript)
- **Dashboard**: Real-time statistics and visualizations
- **Log Viewer**: Searchable log table
- **Alerts**: Alert management
- **Rules**: Detection rule management
- **Reports**: Report generation
- **Settings**: Configuration management

## Getting Started

See individual component READMEs for setup instructions:
- [Backend Setup](backend/README.md)
- [Frontend Setup](frontend/README.md)

## Documentation

- [Implementation Plan](../plan.md)
- [Analysis Layer Plan](../analysis_layer_plan.md)

## License

TBD
