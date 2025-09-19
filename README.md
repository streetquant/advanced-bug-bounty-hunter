# Advanced Bug Bounty Hunter 🎯

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status: Development](https://img.shields.io/badge/status-development-orange.svg)

A sophisticated, AI-powered bug bounty hunting tool that emulates human security researcher behavior using multi-agent frameworks, LLM intelligence, and advanced vulnerability detection capabilities.

## 🚀 Features

### Core Capabilities
- **Multi-Agent Architecture**: Specialized agents for different vulnerability types
- **AI-Powered Analysis**: LLM-driven vulnerability detection and pattern recognition
- **Browser Automation**: Headless testing with Playwright across multiple engines
- **Real-time Interception**: HTTP request/response modification and analysis
- **Stealth Testing**: Advanced evasion techniques and human-like behavior
- **Comprehensive Reporting**: Multiple output formats with detailed evidence

### Supported Vulnerability Types
- SQL Injection (Boolean, Time-based, Error-based, Union-based)
- Cross-Site Scripting (Reflected, Stored, DOM-based)
- Command Injection (OS Command, Code Injection)
- Business Logic Flaws
- Authentication & Authorization Issues
- API Security Vulnerabilities
- Infrastructure Weaknesses

### Advanced Features
- **Adaptive Learning**: Learns from successful attack patterns
- **Chain Discovery**: Identifies complex vulnerability chains
- **Context Awareness**: Understands application context and business logic
- **Evidence Collection**: Automatic screenshot, HAR file, and proof generation
- **Concurrent Testing**: Parallel agent execution with configurable limits

## 📋 Requirements

- Python 3.11+
- PostgreSQL (optional, SQLite supported)
- Redis (optional, for caching)
- Google Gemini API key (for LLM features)

## 🛠️ Installation

### Using Poetry (Recommended)

```bash
# Clone the repository
git clone https://github.com/streetquant/advanced-bug-bounty-hunter.git
cd advanced-bug-bounty-hunter

# Install dependencies with Poetry
poetry install

# Activate the virtual environment
poetry shell

# Install Playwright browsers
playwright install

# Initialize database
python scripts/migrate_db.py --action init
```

### Using pip

```bash
# Clone and setup
git clone https://github.com/streetquant/advanced-bug-bounty-hunter.git
cd advanced-bug-bounty-hunter

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Install Playwright browsers
playwright install

# Initialize database
python scripts/migrate_db.py --action init
```

## ⚙️ Configuration

### 1. Create Configuration File

```bash
# Generate default configuration
bbhunter config --init
```

This creates `config/default.yaml` with all configuration options.

### 2. Set API Keys

Edit `config/default.yaml` and set your Google Gemini API key:

```yaml
gemini:
  api_key: "your_actual_gemini_api_key_here"
  model: "gemini-1.5-pro"
```

Or set via environment variable:

```bash
export BBHUNTER_GEMINI__API_KEY="your_actual_gemini_api_key_here"
```

### 3. Database Setup (Optional)

For PostgreSQL (recommended for production):

```yaml
database:
  type: "postgresql"
  host: "localhost"
  port: 5432
  name: "bbhunter"
  username: "bbhunter"
  password: "your_secure_password"
```

## 🎯 Usage

### Basic Scan

```bash
# Scan a target website
bbhunter scan https://target.example.com

# Scan with custom configuration
bbhunter scan https://target.example.com --config config/custom.yaml

# Verbose output
bbhunter scan https://target.example.com --verbose
```

### Advanced Options

```bash
# Aggressive testing mode
bbhunter scan https://target.example.com --aggressive

# Stealth mode with evasion
bbhunter scan https://target.example.com --stealth

# Custom output directory
bbhunter scan https://target.example.com --output ./custom_reports

# Specific agent types only
bbhunter scan https://target.example.com --agents reconnaissance,injection
```

### Configuration Management

```bash
# Initialize default configuration
bbhunter config --init

# Validate configuration
bbhunter config --validate config/default.yaml

# Show version information
bbhunter version
```

## 🏗️ Architecture

### Core Components

```
advanced_bug_bounty_hunter/
├── core/                    # Core infrastructure
│   ├── browser/            # Playwright automation
│   ├── config/             # Configuration management
│   ├── models/             # Database models
│   └── state/              # Shared state management
├── agents/                  # Security testing agents
│   ├── base.py             # Base agent classes
│   ├── orchestrator.py     # Main coordination
│   ├── reconnaissance/     # Discovery agents
│   ├── injection/          # Injection testing
│   ├── xss/               # XSS testing
│   └── ...                # Other specialized agents
└── utils/                  # Utility modules
```

### Agent Types

1. **ReconnaissanceAgent**: Subdomain enumeration, technology detection
2. **AuthenticationAgent**: Login bypass, session management
3. **AuthorizationAgent**: Privilege escalation, access control
4. **InjectionAgent**: SQL, NoSQL, Command injection
5. **XSSAgent**: Reflected, Stored, DOM-based XSS
6. **BusinessLogicAgent**: Logic flaw detection
7. **ClientSideAgent**: JavaScript analysis, DOM manipulation
8. **InfrastructureAgent**: Server misconfiguration, exposed services
9. **APISecurityAgent**: REST/GraphQL API vulnerabilities

## 📊 Output Formats

The tool generates comprehensive reports in multiple formats:

- **JSON**: Machine-readable results with full details
- **HTML**: Interactive web report with evidence
- **PDF**: Professional report for clients
- **Markdown**: Human-readable summary
- **HAR**: HTTP traffic archive for analysis

### Sample Output Structure

```
reports/
├── security_report_1640995200.json    # Main JSON report
├── security_report_1640995200.html    # Interactive HTML
├── security_report_1640995200.pdf     # PDF report
├── traffic_1640995200.har              # Network traffic
└── evidence/                           # Screenshots & proofs
    ├── screenshots/
    ├── requests/
    └── responses/
```

## 🔧 Development

### Project Structure

This project follows a 24-week development roadmap:

- **Phase 1 (Weeks 1-4)**: Foundation Architecture ✅
- **Phase 2 (Weeks 5-12)**: Intelligence and Adaptation
- **Phase 3 (Weeks 13-20)**: Advanced Features
- **Phase 4 (Weeks 21-24)**: Validation and Hardening

### Current Status: Week 1 Complete

✅ **Completed Components:**
- Project structure and configuration
- Playwright browser automation
- Multi-agent architecture foundation
- State management system
- Database integration
- CLI interface
- Logging and error handling

🚧 **Next Steps (Week 2):**
- Basic ReconnaissanceAgent implementation
- Request/response interception
- LLM integration for pattern analysis
- Initial vulnerability detection

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
poetry install --with dev

# Run tests
pytest

# Code formatting
black advanced_bug_bounty_hunter/
isort advanced_bug_bounty_hunter/

# Type checking
mypy advanced_bug_bounty_hunter/

# Linting
flake8 advanced_bug_bounty_hunter/
```

## 🛡️ Legal and Ethical Usage

**⚖️ IMPORTANT LEGAL NOTICE**

This tool is designed for **authorized security testing only**. Users must:

- ✅ Have explicit written permission before testing any system
- ✅ Only test systems you own or have authorization to test
- ✅ Comply with all applicable laws and regulations
- ✅ Follow responsible disclosure practices
- ❌ NEVER use this tool for unauthorized access or malicious purposes

**The developers are not responsible for misuse of this tool.**

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

- 📧 Email: [your.email@example.com]
- 🐛 Issues: [GitHub Issues](https://github.com/streetquant/advanced-bug-bounty-hunter/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/streetquant/advanced-bug-bounty-hunter/discussions)

## 🙏 Acknowledgments

- [Playwright](https://playwright.dev/) for browser automation
- [LangChain](https://python.langchain.com/) for LLM orchestration
- [FastAPI](https://fastapi.tiangolo.com/) for web framework
- [SQLAlchemy](https://sqlalchemy.org/) for database ORM
- The bug bounty and security research community

---

**⭐ Star this repository if you find it useful!**
