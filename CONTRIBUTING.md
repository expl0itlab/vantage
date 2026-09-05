# Contributing to Vantage

Thanks for your interest in contributing to Vantage!

## How to Report Bugs

1. Check [existing issues](https://github.com/expl0itlab/vantage/issues) first
2. Open a new issue using the **Bug Report** template
3. Include: OS, Go version, steps to reproduce, expected vs actual behavior
4. Attach relevant logs (redact any sensitive target data)

## How to Submit Features

1. Open an issue first describing the feature and use case
2. Wait for feedback before starting implementation
3. Fork the repo, create a branch, implement, and submit a PR

## Code Style

- All Go code must pass `gofmt`
- Follow existing patterns in the codebase
- Keep functions focused and under ~100 lines where possible
- Use the existing logger pattern (`func(string, ...interface{})`) for new modules
- No hardcoded secrets, credentials, or internal URLs

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with clear, descriptive commits
4. Run `gofmt -w .` before submitting
5. Ensure the build compiles: `CGO_ENABLED=1 go build -mod=vendor -o vantage ./cmd/`
6. Submit your PR with a clear description of what changed and why

## Code of Conduct

Be respectful. We're all here to build good tools.

## Questions?

Open a discussion at https://github.com/expl0itlab/vantage/discussions
