# mpak Trust Framework (MTF)

MTF is an open security standard for describing and verifying the security posture of MCP server bundles.

**Status:** Draft (v0.1)
**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

## Overview

MCP servers extend AI assistants with powerful capabilities: filesystem access, network requests, database queries, and code execution. This power creates significant security risk. MTF provides a standardized framework for:

1. **Bundle authors** to demonstrate security best practices
2. **Registries** to enforce minimum security requirements
3. **Consumers** to make informed installation decisions
4. **Enterprises** to set procurement policies

## Compliance Levels

MTF defines four compliance levels, each building on the previous:

| Level | Name | Target | Controls |
|-------|------|--------|----------|
| L1 | Basic | Personal projects, experimentation | 6 |
| L2 | Standard | Team tools, published packages | 14 |
| L3 | Verified | Production, enterprise use | 22 |
| L4 | Attested | Critical infrastructure, regulated industries | 25 |

## Security Domains

Controls are organized into five domains:

- **Supply Chain (SC)**: SBOM, vulnerability scanning, dependency pinning
- **Code Quality (CQ)**: Secret detection, malicious patterns, static analysis
- **Artifact Integrity (AI)**: Manifest validation, content hashes, signatures
- **Provenance (PR)**: Source repository, author identity, build attestation
- **Capability Declaration (CD)**: Tool declarations, permission scopes

## Specification

See [MTF-0.1.md](MTF-0.1.md) for the full specification.

## Schemas

JSON schemas for validation:

- [schemas/manifest.schema.json](schemas/manifest.schema.json) - MCPB manifest with MTF security extensions
- [schemas/report.schema.json](schemas/report.schema.json) - MTF security scan report format

## Implementations

| Implementation | Language | Maintainer |
|----------------|----------|------------|
| [mpak-scanner](https://github.com/NimbleBrainInc/mpak-scanner) | Python | NimbleBrain (reference implementation) |

## Contributing

MTF is developed in the open. Contributions, feedback, and discussion are welcome.

## License

This specification is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

You are free to share and adapt this material for any purpose, including commercial use, as long as you provide appropriate attribution.
