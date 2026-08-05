# Contributing to CyberShield-AI-SOC

Thank you for your interest in contributing to **CyberShield-AI-SOC**! We welcome bug reports, feature requests, documentation improvements, and code contributions from the security community.

---

## 🚀 How to Contribute

### 1. Reporting Bugs
- Search existing GitHub Issues before submitting a new report.
- Include OS version, Python version, steps to reproduce, expected vs actual behavior, and error tracebacks.

### 2. Feature Requests
- Describe the feature clearly and why it would benefit security operations teams.
- Outline proposed architectural changes or API additions.

### 3. Pull Request Guidelines
1. Fork the repository and create a feature branch (`git checkout -b feature/amazing-feature`).
2. Follow existing code formatting conventions:
   - Python code must pass `flake8 backend` without errors.
   - Frontend TypeScript must pass `npm run typecheck` and `npm run build` in `frontend/`.
   - Write pytest unit/integration tests for any backend logic changes.
3. Commit your changes with clear, descriptive commit messages.
4. Ensure all CI checks pass on your PR branch.

---

## 🧪 Local Test Commands

```bash
# Run backend pytest suite
pytest

# Run flake8 linting
flake8 backend

# Run frontend typecheck and build
cd frontend && npm run typecheck && npm run build
```
