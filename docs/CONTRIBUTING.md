# Contributing to SAGAR AdaptiveAuth Framework

Thank you for considering contributing to the SAGAR AdaptiveAuth Framework! We welcome contributions from the community to help make this project better.

## 🤝 Ways to Contribute

There are many ways you can contribute to the project:

- **Report Bugs**: Submit bug reports with detailed information about the issue
- **Feature Requests**: Suggest new features or improvements
- **Code Contributions**: Submit pull requests with bug fixes or new features
- **Documentation**: Improve documentation, tutorials, or examples
- **Testing**: Help test new releases and report issues
- **Community Support**: Answer questions and help other users

## 🐛 Reporting Bugs

When reporting a bug, please include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs. actual behavior
- Your environment (OS, Python version, etc.)
- Any relevant error messages or logs
- Screenshots if applicable

## 💡 Feature Requests

When suggesting a feature, please:

- Explain the problem you're trying to solve
- Describe your proposed solution
- Consider any alternatives you've thought of
- Explain why this feature would be useful

## 🧑‍💻 Code Contributions

### Setting Up Your Development Environment

1. **Fork the repository**
2. **Clone your fork**
```bash
git clone https://github.com/yourusername/adaptiveauth.git
cd adaptiveauth
```

3. **Create a virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

4. **Install dependencies**
```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development tools
```

5. **Run tests to verify setup**
```bash
python -m pytest
```

### Making Changes

1. **Create a new branch** for your feature or bug fix:
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b bugfix/issue-description
```

2. **Make your changes** following the coding standards below

3. **Test your changes** thoroughly

4. **Commit your changes** with clear, descriptive commit messages:
```bash
git add .
git commit -m "Add feature: brief description of your feature"
```

5. **Push to your fork**:
```bash
git push origin feature/your-feature-name
```

6. **Open a Pull Request** with a clear description of your changes

### Coding Standards

- **Python**: Follow PEP 8 style guide
- **Naming**: Use descriptive, consistent names
- **Comments**: Document complex logic and public APIs
- **Testing**: Include tests for new features
- **Documentation**: Update docstrings and documentation as needed
- **Security**: Follow security best practices

### Code Structure

The project follows this structure:
```
adaptiveauth/
├── auth/           # Authentication services
├── core/           # Core utilities and security
├── risk/           # Risk assessment and monitoring
├── routers/        # API route handlers
├── models.py       # Database models
├── schemas.py      # Pydantic schemas
└── config.py       # Configuration management
```

## 🧪 Testing

- Run all tests before submitting a PR: `python -m pytest`
- Add new tests for new features
- Ensure all tests pass before pushing

## 📄 Style Guide

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line

### Python Code

- Use 4 spaces for indentation
- Use docstrings for all public classes and methods
- Follow type hinting conventions
- Keep functions focused and small when possible

## 🔄 Pull Request Process

1. Ensure your PR addresses an existing issue or describes a clear improvement
2. Update documentation if needed
3. Add tests for new functionality
4. Ensure all tests pass
5. Wait for review and address feedback
6. Your PR will be merged once approved

## 🛡️ Security Policy

If you discover a security vulnerability, please contact us directly rather than filing a public issue. Include:

- Type of vulnerability
- Location in code
- Potential impact
- Steps to reproduce
- Suggested fix (if any)

## 🙏 Thank You

Thank you for your interest in contributing to SAGAR AdaptiveAuth Framework! Your contributions help make the project better for everyone.

If you have any questions, feel free to reach out through the issue tracker or community forums.