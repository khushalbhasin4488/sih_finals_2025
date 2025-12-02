# Backend

Python-based backend for the log analyzer tool.

## Structure

```
backend/
├── analyzers/              # Detection engines
│   ├── __init__.py
│   ├── orchestrator.py    # Main analysis coordinator
│   ├── signature_detector.py
│   ├── anomaly_detector.py
│   ├── heuristic_analyzer.py
│   ├── behavioral_analyzer.py
│   ├── rule_engine.py
│   ├── network_analyzer.py
│   └── threat_intel_matcher.py
├── api/                    # REST API
│   ├── __init__.py
│   ├── main.py            # FastAPI application
│   ├── routes/            # API routes
│   └── middleware/        # Middleware
├── storage/                # DuckDB interface
│   ├── __init__.py
│   ├── db_manager.py      # Database operations
│   └── models.py          # Data models
├── core/                   # Core utilities
│   ├── __init__.py
│   ├── config.py          # Configuration management
│   ├── logger.py          # Logging setup
│   ├── report_generator.py
│   └── update_manager.py
├── auth/                   # Authentication
│   ├── __init__.py
│   ├── auth.py            # Authentication logic
│   └── rbac.py            # Role-based access control
└── tests/                  # Tests
    ├── unit/
    ├── integration/
    └── performance/
```

## Setup

1. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run tests:
```bash
pytest
```

4. Start API server:
```bash
uvicorn api.main:app --reload
```

## Technology Stack

- **Python**: 3.11+
- **FastAPI**: Web framework
- **DuckDB**: Database
- **scikit-learn**: Machine learning
- **pandas**: Data manipulation
- **pytest**: Testing

## Configuration

See `config/` directory for configuration files.
