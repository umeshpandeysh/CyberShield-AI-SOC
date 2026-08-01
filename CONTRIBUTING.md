# Contributing to CyberShield-AI-SOC

Thank you for your interest in contributing to **CyberShield-AI-SOC**! We welcome and appreciate contributions of all kinds, including bug fixes, feature enhancements, documentation improvements, and security reports.

## Getting Started

1. **Fork the Repository**: Create a personal copy of the repository on GitHub.
2. **Clone Locally**:
   ```bash
   git clone https://github.com/umeshpandeysh/CyberShield-AI-SOC.git
   cd CyberShield-AI-SOC
   ```
3. **Set Up the Environment**: Follow the environment setup instructions in the `README.md` to run the development services (Postgres, Redis, ClamAV) and install Node and Python dependencies.

## Branching Strategy

We use a simplified Git Flow model for development. Please target your branches accordingly:

* `main`: Represents the stable production release. Do not commit directly to `main`.
* `dev`: The active development branch. All feature branches should merge into `dev`.
* `feature/issue-<number>-<description>`: For new features or enhancements.
* `bugfix/issue-<number>-<description>`: For resolving bugs or performance issues.
* `release/v<version>`: For preparing official releases.

## Commit Message Standards

We enforce **Conventional Commits** format for all commit messages. This helps automate changelog generation and release management.

Format: `<type>(<scope>): <description>`

Common types:
* `feat`: A new feature
* `fix`: A bug fix
* `docs`: Documentation changes
* `style`: Code formatting changes (whitespace, missing semi-colons, etc.)
* `refactor`: Code changes that neither fix a bug nor add a feature
* `test`: Adding missing tests or correcting existing tests
* `chore`: Build process, dependencies, tooling, or repository adjustments

Example:
```text
feat(ai-engine): add fasttext classifier for spam headers
fix(backend): resolve memory leak in threat scanning stream
```

## Pull Request Lifecycle

1. **Create a Branch**: Create a branch off `dev` with a descriptive name.
2. **Implement Changes**: Write clean, commented, and well-tested code following the language style guides (PEP 8 for Python, ESLint/Prettier for JavaScript/React).
3. **Run Verification**: Ensure all tests and static analysis pass locally before pushing:
   - Backend tests: `pytest`
   - Frontend tests: `npm test`
   - Linting: `flake8` / `eslint`
4. **Submit PR**: Submit a pull request targeting the `dev` branch. Describe your changes clearly in the PR template.
5. **Review & Approve**: At least one maintainer must review and approve your code before it can be merged.
