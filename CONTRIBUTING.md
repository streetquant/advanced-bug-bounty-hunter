# Contributing to Advanced Bug Bounty Hunter

First off, thank you for considering contributing to the Advanced Bug Bounty Hunter project! 🎉

This document provides guidelines and information for contributors to help maintain code quality, security, and project consistency.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Security Guidelines](#security-guidelines)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Review Process](#review-process)

## 🤝 Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow:

- **Be respectful** and inclusive in all interactions
- **Be constructive** when providing feedback or criticism
- **Focus on the code**, not the person when discussing issues
- **Respect different perspectives** and experience levels
- **Follow responsible disclosure** for security vulnerabilities

## 🚀 Getting Started

### Prerequisites

- Python 3.11 or higher
- Poetry (recommended) or pip
- Git
- PostgreSQL (optional, SQLite works for development)
- Google Gemini API key (for AI features)

### Setting Up Development Environment

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/advanced-bug-bounty-hunter.git
   cd advanced-bug-bounty-hunter
   ```

2. **Install Dependencies**
   ```bash
   # Using Poetry (recommended)
   poetry install --with dev
   poetry shell
   
   # Or using pip
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. **Install Playwright Browsers**
   ```bash
   playwright install
   ```

4. **Set Up Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

5. **Initialize Database**
   ```bash
   python scripts/migrate_db.py --action init
   ```

6. **Run Tests**
   ```bash
   pytest
   ```

## 🔄 Development Workflow

### Branch Naming Convention

- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `hotfix/description` - Critical fixes
- `docs/description` - Documentation changes
- `refactor/description` - Code refactoring

### Development Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/awesome-new-feature
   ```

2. **Make Changes**
   - Write code following our standards
   - Add/update tests
   - Update documentation

3. **Test Your Changes**
   ```bash
   # Run all tests
   pytest
   
   # Run with coverage
   pytest --cov=advanced_bug_bounty_hunter
   
   # Run specific test file
   pytest tests/test_specific_feature.py
   ```

4. **Code Quality Checks**
   ```bash
   # Format code
   black advanced_bug_bounty_hunter/
   isort advanced_bug_bounty_hunter/
   
   # Type checking
   mypy advanced_bug_bounty_hunter/
   
   # Linting
   flake8 advanced_bug_bounty_hunter/
   ```

5. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add awesome new feature"
   ```

### Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(agents): add SQL injection detection
fix(browser): resolve memory leak in playwright manager
docs: update installation instructions
test(reconnaissance): add subdomain enumeration tests
```

## 📝 Coding Standards

### Python Code Style

- **PEP 8** compliance (enforced by `black` and `flake8`)
- **Type hints** for all function signatures
- **Docstrings** for all classes and public methods (Google style)
- **Maximum line length**: 88 characters (black default)
- **Import organization**: Use `isort` for consistent import ordering

### Code Organization

```python
# Example function with proper documentation
async def scan_target(target_url: str, config: SecurityTestingConfig) -> ScanResult:
    """Scan a target URL for security vulnerabilities.
    
    Args:
        target_url: The URL to scan for vulnerabilities
        config: Security testing configuration
        
    Returns:
        ScanResult containing discovered vulnerabilities and evidence
        
    Raises:
        ValueError: If target_url is invalid
        ConfigError: If configuration is invalid
    """
    # Implementation here
    pass
```

### Agent Development Guidelines

When creating new security testing agents:

1. **Inherit from AgentBase**
   ```python
   from advanced_bug_bounty_hunter.agents.base import AgentBase
   
   class MySecurityAgent(AgentBase):
       async def initialize(self) -> None:
           # Agent initialization logic
           pass
       
       async def execute(self) -> AgentResult:
           # Main agent logic
           pass
       
       async def cleanup(self) -> None:
           # Cleanup resources
           pass
   ```

2. **Follow naming conventions**
   - Agent classes: `PascalCase` ending with `Agent`
   - Methods: `snake_case`
   - Constants: `UPPER_SNAKE_CASE`

3. **Implement proper error handling**
   - Use try/except blocks for external calls
   - Log errors appropriately
   - Return meaningful error information

## 🔒 Security Guidelines

### Code Security

- **Never commit secrets** (API keys, passwords, etc.)
- **Validate all inputs** from external sources
- **Use parameterized queries** for database operations
- **Sanitize user inputs** before processing
- **Follow principle of least privilege**

### Vulnerability Detection

- **Minimize false positives** through proper validation
- **Provide proof of concept** for each vulnerability
- **Include remediation guidance** when possible
- **Respect rate limits** and avoid DoS conditions

### Ethical Testing

- **Only test authorized targets**
- **Implement proper scoping** mechanisms
- **Avoid destructive operations** by default
- **Include clear warnings** about legal usage

## 🧪 Testing Requirements

### Test Coverage

- **Minimum 80% code coverage** for new features
- **Unit tests** for individual functions/methods
- **Integration tests** for agent interactions
- **End-to-end tests** for complete workflows

### Test Structure

```python
# tests/test_example_agent.py
import pytest
from unittest.mock import AsyncMock, MagicMock

from advanced_bug_bounty_hunter.agents.example import ExampleAgent


class TestExampleAgent:
    """Test suite for ExampleAgent."""
    
    @pytest.fixture
    async def agent(self, mock_config, mock_browser, mock_state):
        """Create an ExampleAgent instance for testing."""
        return ExampleAgent(
            name="test_agent",
            config=mock_config,
            browser_manager=mock_browser,
            state_manager=mock_state
        )
    
    async def test_initialization(self, agent):
        """Test agent initialization."""
        await agent.initialize()
        assert agent.status == AgentStatus.IDLE
    
    async def test_vulnerability_detection(self, agent):
        """Test vulnerability detection functionality."""
        # Test implementation
        pass
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=advanced_bug_bounty_hunter --cov-report=html

# Run specific test categories
pytest -m "unit"  # Unit tests only
pytest -m "integration"  # Integration tests only

# Run tests for specific agent
pytest tests/agents/test_reconnaissance.py
```

## 📚 Documentation

### Code Documentation

- **Docstrings** for all public classes and methods
- **Type hints** for better IDE support
- **Inline comments** for complex logic
- **README files** for major modules

### User Documentation

When adding new features:

1. Update relevant sections in `README.md`
2. Add usage examples
3. Update configuration documentation
4. Include troubleshooting information

### API Documentation

For new agent types or major features:

1. Document configuration options
2. Provide usage examples
3. List supported vulnerability types
4. Include performance considerations

## 📤 Submitting Changes

### Pull Request Process

1. **Ensure all tests pass**
   ```bash
   pytest
   ```

2. **Check code quality**
   ```bash
   black --check advanced_bug_bounty_hunter/
   isort --check-only advanced_bug_bounty_hunter/
   flake8 advanced_bug_bounty_hunter/
   mypy advanced_bug_bounty_hunter/
   ```

3. **Update documentation** as needed

4. **Create Pull Request**
   - Use descriptive title
   - Fill out PR template completely
   - Link related issues
   - Add screenshots for UI changes

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Updated documentation

## Security Considerations
- [ ] No sensitive data exposed
- [ ] Input validation implemented
- [ ] Follows security guidelines

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## 👥 Review Process

### Review Criteria

- **Functionality**: Does it work as intended?
- **Code Quality**: Follows standards and best practices?
- **Security**: No security vulnerabilities introduced?
- **Performance**: Acceptable performance impact?
- **Testing**: Adequate test coverage?
- **Documentation**: Properly documented?

### Reviewer Guidelines

- **Be constructive** in feedback
- **Explain the why** behind suggestions
- **Test the changes** when possible
- **Check for security implications**
- **Verify documentation accuracy**

### Response to Feedback

- **Address all feedback** or explain why not
- **Update code and tests** as needed
- **Re-request review** after changes
- **Be respectful** in discussions

## 🆘 Getting Help

If you need help or have questions:

- **GitHub Discussions**: For general questions and ideas
- **GitHub Issues**: For bug reports and feature requests
- **Email**: [your.email@example.com] for security-related concerns

## 🏆 Recognition

Contributors will be recognized in:

- `CONTRIBUTORS.md` file
- Release notes for significant contributions
- GitHub repository contributors list

Thank you for contributing to Advanced Bug Bounty Hunter! 🎯
