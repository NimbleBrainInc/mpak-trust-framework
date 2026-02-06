# Contributing to MTF

Thank you for your interest in contributing to the mpak Trust Framework.

## Ways to Contribute

### Feedback and Discussion

- **Open an issue** for questions, suggestions, or bug reports
- **Start a discussion** for broader topics or proposals

### Specification Changes

For changes to the MTF specification (`MTF-0.1.md`):

1. Open an issue describing the proposed change
2. Include rationale and any security implications
3. Reference relevant standards (SLSA, SBOM, etc.) if applicable
4. Wait for maintainer feedback before submitting a PR

### Website and Tooling

For changes to the website or schemas:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `cd website && npm run build` to verify
5. Submit a pull request

## Development Setup

```bash
# Clone the repo
git clone https://github.com/NimbleBrainInc/mpak-trust-framework.git
cd mpak-trust-framework

# Install website dependencies
cd website
npm install

# Start dev server
npm run dev
```

## Style Guidelines

- Keep the spec language precise and unambiguous
- Use RFC 2119 keywords (MUST, SHOULD, MAY) consistently
- Include rationale for security controls
- Provide implementation examples where helpful

## License

By contributing, you agree that your contributions will be licensed under CC BY 4.0.
