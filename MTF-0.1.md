# mpak Trust Framework (MTF) v0.1

MTF is a specification for securing the supply chain of MCP server bundles. It defines controls spanning the full distribution lifecycle: from how bundles are built and signed, to how registries govern namespaces and handle revocations, to how consumers verify and install packages.

**Version:** 0.1
**Status:** Draft
**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Threat Model](#2-threat-model)
3. [Control Catalog](#3-control-catalog)
   - [3.1 Control Format](#31-control-format)
   - [3.2 Artifact Integrity (AI-)](#32-artifact-integrity-ai-)
   - [3.3 Supply Chain (SC-)](#33-supply-chain-sc-)
   - [3.4 Code Quality (CQ-)](#34-code-quality-cq-)
   - [3.5 Capability Declaration (CD-)](#35-capability-declaration-cd-)
   - [3.6 Provenance (PR-)](#36-provenance-pr-)
   - [3.7 Registry Operations (RG-)](#37-registry-operations-rg-)
   - [3.8 Publisher Identity (PK-)](#38-publisher-identity-pk-)
   - [3.9 Installation (IN-)](#39-installation-in-)
   - [3.10 Update Lifecycle (UP-)](#310-update-lifecycle-up-)
4. [Manifest Specification](#4-manifest-specification)
5. [Signing & Attestation](#5-signing--attestation)
6. [Implementation Guide](#6-implementation-guide)
7. [Specification Roadmap](#7-specification-roadmap)

- [Appendix A: Control Quick Reference](#appendix-a-control-quick-reference)
- [Appendix B: Controls by Compliance Level](#appendix-b-controls-by-compliance-level)
- [Appendix C: Open Questions](#appendix-c-open-questions)
- [Appendix D: Runtime Security Roadmap](#appendix-d-runtime-security-roadmap)

## 1. Introduction

### 1.1 Purpose

MTF defines security controls for MCP server bundles distributed through package registries. It addresses supply chain threats specific to the MCP ecosystem, including tool description poisoning, credential aggregation, and slopsquatting.

### 1.2 Scope & Boundaries

**What MTF covers:**

| Phase          | Description                             | MTF Coverage                         |
| -------------- | --------------------------------------- | ------------------------------------ |
| **Publish**    | Author packages and signs bundle        | Provenance, signing, manifest        |
| **Distribute** | Registry indexes and serves bundle      | Namespace governance, revocation     |
| **Discover**   | Consumer searches and evaluates         | Metadata transparency, trust signals |
| **Verify**     | Consumer validates bundle integrity     | Signature verification, attestation  |
| **Install**    | Bundle extracted, dependencies resolved | Completeness check, pinning          |
| **Update**     | New version replaces old                | Version policy, breaking changes     |

**What MTF does NOT cover:**

- Runtime execution (sandboxing, permission enforcement during tool invocation)
- Prompt injection defense (LLM-level input filtering)
- Tool-level permissions (per-invocation authorization)
- MCP client security (host application hardening)
- Network transport (TLS configuration)

These concerns require runtime security controls planned for MTF v0.2+.

### 1.3 Terminology

**MCP bundle:** A distributable package representing exactly one MCP server, containing:

| Component             | Required | Description                                              |
| --------------------- | -------- | -------------------------------------------------------- |
| `manifest.json`       | MUST     | Machine-readable metadata declaring capabilities         |
| Server implementation | MUST     | Source code or compiled binaries implementing MCP server |
| Bundled dependencies  | MAY      | Third-party libraries included in package                |
| SBOM                  | MUST     | Software Bill of Materials listing all components        |
| Signature             | L3+      | Cryptographic signature proving publisher identity       |
| Attestation           | L3+      | Build provenance statement                               |

**Bundle-server invariant:** A bundle MUST correspond to exactly one MCP server entrypoint. Bundles MUST NOT contain multiple independently invokable servers.

**Requirement levels** (RFC 2119):

| Keyword                  | Meaning                                                    |
| ------------------------ | ---------------------------------------------------------- |
| **MUST / REQUIRED**      | Absolute requirement for compliance                        |
| **MUST NOT**             | Absolute prohibition                                       |
| **SHOULD / RECOMMENDED** | Best practice; deviation requires documented justification |
| **MAY / OPTIONAL**       | Truly optional; no impact on compliance                    |

### 1.4 Compliance Levels

MTF defines four compliance levels. Each level includes all requirements from previous levels.

| Level           | Target                         | Key Requirements                                                    |
| --------------- | ------------------------------ | ------------------------------------------------------------------- |
| **L1 Basic**    | Personal projects, experiments | Valid manifest, no secrets/malware, SBOM, tool declaration          |
| **L2 Standard** | Published packages, team tools | + CVE scan, dependency pinning, author identity, description safety |
| **L3 Verified** | Production, enterprise         | + Cryptographic signing, build attestation, credential scopes       |
| **L4 Attested** | Critical infrastructure        | + Behavioral analysis, commit linkage, reproducible builds          |

### 1.5 Security Invariants

The following guarantees MUST hold across all MTF versions:

1. **Signed content:** All executable bundle content is cryptographically signed and integrity-verified before execution (L3+).
2. **Dependency transparency:** SBOMs enumerate all direct and transitive dependencies with pinned versions.
3. **Revocation enforcement:** Revoked bundles are blocked at install time; clients MUST check revocation status.
4. **Consent for escalation:** Permission or scope increases during updates require explicit user consent.

## 2. Threat Model

### 2.1 Attack Surface

MCP bundles present attack opportunities across multiple phases:

| Phase             | Window                            | Unique MCP Risk                   |
| ----------------- | --------------------------------- | --------------------------------- |
| Pre-installation  | Registry browsing, search         | Tool descriptions visible to LLMs |
| Installation      | Dependency resolution, extraction | Post-install hooks execute        |
| Initialization    | Server startup, module imports    | Code runs before user consent     |
| Credential access | OAuth token provisioning          | Tokens aggregated across services |

### 2.2 Supply Chain Attack Vectors

#### 2.2.1 Typosquatting / Namespace Confusion

**Vector:** Attacker registers package names similar to legitimate packages.

**Mechanism:** Exploits human typos (`stripe-mcp` vs `strpe-mcp`) or organizational namespace confusion.

**Controls:** RG-01, RG-02, CQ-06

#### 2.2.2 Slopsquatting (MCP-Specific)

**Vector:** Attacker registers package names that LLMs hallucinate.

**Mechanism:** LLMs generate plausible but non-existent package names. Attackers preemptively register these.

**Controls:** CQ-06, RG-02

#### 2.2.3 Dependency Hijacking

**Vector:** Attacker compromises a transitive dependency.

**Mechanism:** Typosquatting internal names, account takeover, malicious upstream contribution.

**Controls:** SC-02, SC-03, PR-03

#### 2.2.4 Malicious Updates / Account Takeover

**Vector:** Attacker publishes malicious update using compromised publisher credentials.

**Controls:** PR-02, PK-02, PK-03, RG-05

#### 2.2.5 Build Provenance Gaps

**Vector:** Attacker tampers with build pipeline or publishes artifacts without provenance.

**Controls:** PR-03, AI-04, PR-04

#### 2.2.6 Phantom Bundle Components

**Vector:** Bundle contains files not declared in manifest.

**Controls:** AI-05

#### 2.2.7 Metadata / Manifest Manipulation

**Vector:** Manifest declares benign capabilities while code implements dangerous ones.

**Controls:** CD-02, CQ-06

#### 2.2.8 Tool Description Poisoning (MCP-Specific)

**Vector:** Malicious instructions embedded in MCP tool descriptions.

**Mechanism:** LLMs consume tool descriptions as trusted instructions. Attacker embeds directives to exfiltrate data.

**Controls:** CD-03

#### 2.2.9 Registry Poisoning

**Vector:** Attacker compromises registry infrastructure.

**Controls:** RG-03, RG-04

#### 2.2.10 Unverified Publisher Identity

**Vector:** Attacker publishes under false identity.

**Controls:** PR-02, PK-01

#### 2.2.11 Abandoned / Unmaintained Bundles

**Vector:** Legitimate but abandoned bundle accumulates vulnerabilities.

**Controls:** UP-03, PK-04

#### 2.2.12 Credential Aggregation (MCP-Specific)

**Vector:** Compromised MCP server accesses tokens for multiple services.

**Mechanism:** MCP servers aggregate OAuth tokens creating concentrated breach potential.

**Controls:** CD-04, CD-05

#### 2.2.13 Initialization-Time Exfiltration (MCP-Specific)

**Vector:** Malicious code executes during server startup, before any tool invocation.

**Controls:** CD-02, CQ-06

## 3. Control Catalog

### 3.1 Control Format

Each control in this catalog follows a consistent structure:

| Element               | Description                            |
| --------------------- | -------------------------------------- |
| **ID**                | Unique identifier (e.g., AI-01, SC-02) |
| **Name**              | Short descriptive name                 |
| **Level**             | Minimum compliance level (L1/L2/L3/L4) |
| **Enforcement**       | Who enforces (Scanner/Registry/Client) |
| **Rationale**         | Why this control matters               |
| **Requirements**      | Normative MUST/SHOULD statements       |
| **Verification**      | How to check compliance                |
| **Severity**          | Finding-to-action mapping              |
| **Threats Addressed** | Back-reference to threat model         |

**Note:** Some controls are evaluated by multiple actors. The Enforcement field indicates the primary enforcement point for compliance; clients and registries MAY additionally enforce scanner controls.

**Control Prefixes:**

| Prefix | Domain                 | Count |
| ------ | ---------------------- | ----- |
| AI-    | Artifact Integrity     | 5     |
| SC-    | Supply Chain           | 5     |
| CQ-    | Code Quality           | 7     |
| CD-    | Capability Declaration | 5     |
| PR-    | Provenance             | 5     |
| RG-    | Registry Operations    | 5     |
| PK-    | Publisher Identity     | 4     |
| IN-    | Installation           | 4     |
| UP-    | Update Lifecycle       | 4     |

---

### 3.2 Artifact Integrity (AI-)

Artifact integrity controls ensure that bundles are complete, unmodified, and verifiably from the claimed publisher.

| ID    | Control             | Level | Enforcement | Threats Addressed       |
| ----- | ------------------- | ----- | ----------- | ----------------------- |
| AI-01 | Manifest Validation | L1    | Scanner     | Metadata manipulation   |
| AI-02 | *(Reserved)*        | —     | —           | —                       |
| AI-03 | Bundle Signing      | L3    | Scanner     | Publisher impersonation |
| AI-04 | Reproducible Builds | L4    | Scanner     | Build tampering         |
| AI-05 | Bundle Completeness | L2    | Client      | Phantom components      |

#### AI-01: Manifest Validation

**Level:** L1 | **Enforcement:** Scanner

**Rationale:** The manifest is the foundation for all other controls. Without a valid manifest, bundles cannot be evaluated for compliance, capabilities cannot be declared, and verification cannot proceed.

**Requirements:**

- Bundle MUST include `manifest.json` at bundle root
- Manifest MUST validate against [mcpb schema](https://github.com/modelcontextprotocol/mcpb)
- Manifest MUST include all required mcpb fields

**Required Fields (L1):**

| Field              | Type   | Description                      |
| ------------------ | ------ | -------------------------------- |
| `manifest_version` | string | mcpb schema version              |
| `name`             | string | Package name                     |
| `version`          | string | Semantic version (valid semver)  |
| `description`      | string | Human-readable description       |
| `server`           | object | Server execution configuration   |
| `tools`            | array  | Tool declarations (may be empty) |

**Additional Required Fields (L2+):**

| Field                 | Type   | Description                      |
| --------------------- | ------ | -------------------------------- |
| `author`              | object | Publisher identity (name, email) |
| `repository`          | object | Source repository (type, url)    |
| `_meta.org.mpaktrust` | object | MTF extension fields             |

**Validation Steps:**

1. Parse JSON (reject malformed)
2. Validate against mcpb schema
3. Verify required fields present
4. If both `server` and `mcp_config` are present, verify execution targets are consistent (same entrypoint/module)
5. Validate semver format
6. For L2+: Validate scoped name format (`@scope/name`)

**Severity:**

| Finding                   | Action |
| ------------------------- | ------ |
| Missing manifest.json     | BLOCK  |
| Invalid JSON              | BLOCK  |
| Schema validation failure | BLOCK  |
| Missing required field    | BLOCK  |
| Invalid semver            | BLOCK  |
| Unscoped name at L2+      | BLOCK  |

**Threats Addressed:** Metadata manipulation (2.2.7)

#### AI-03: Bundle Signing

**Level:** L3 | **Enforcement:** Scanner

**Rationale:** Signatures bind bundles to publisher identity. Without signatures, anyone who gains registry access can publish under any name. Signatures provide cryptographic proof of publisher intent.

**Requirements:**

- Bundle MUST include cryptographic signature
- Signature MUST cover manifest hash and SBOM hash
- Signature MUST be verifiable against publisher identity

**What MUST Be Signed:**

| Field            | Description                 |
| ---------------- | --------------------------- |
| Package name     | From manifest               |
| Package version  | From manifest               |
| Manifest SHA-256 | Hash of canonical manifest  |
| SBOM SHA-256     | Hash of SBOM file           |
| Timestamp        | ISO 8601 signing time       |
| Signer identity  | OIDC URI or key fingerprint |

**Signed Payload Format:**

```json
{
  "mtf_version": "0.1",
  "payload_type": "bundle_signature",
  "subject": {
    "name": "@scope/package-name",
    "version": "1.0.0",
    "manifest_sha256": "abc123...",
    "sbom_sha256": "def456..."
  },
  "timestamp": "2026-02-06T12:00:00Z",
  "signer_identity": "https://github.com/username"
}
```

**Canonical Serialization:**

Payload MUST use RFC 8785 (JSON Canonicalization Scheme) before signing.

**Signing Mechanisms:**

| Method           | Status         | Notes                  |
| ---------------- | -------------- | ---------------------- |
| Sigstore keyless | REQUIRED       | Binds to OIDC identity |
| ECDSA P-256      | Acceptable     | Long-lived key         |
| Ed25519          | Acceptable     | Long-lived key         |
| RSA-4096+        | Acceptable     | Long-lived key         |
| RSA-2048         | NOT acceptable | Insufficient key size  |

**Signature File Locations:**

| File              | Description                        |
| ----------------- | ---------------------------------- |
| `manifest.sig`    | Primary signature (detached)       |
| `.sigstore/`      | Sigstore bundle directory          |
| `manifest.ci.sig` | CI/builder signature (if multiple) |

**Severity:**

| Finding                           | Action                  |
| --------------------------------- | ----------------------- |
| Missing signature at L3+          | BLOCK                   |
| Invalid signature                 | BLOCK                   |
| Signer not authorized for package | BLOCK                   |
| Payload hash mismatch             | BLOCK                   |
| Expired certificate (Sigstore)    | WARN (check revocation) |

**Threats Addressed:** Publisher impersonation, malicious updates (2.2.4)

#### AI-04: Reproducible Builds

**Level:** L4 | **Enforcement:** Scanner

**Rationale:** Reproducible builds allow independent verification that published binaries match source code. If two builders produce identical output from identical input, tampering in the build process is detectable.

**Requirements:**

- Build process MUST produce bit-identical output from same source
- Manifest MUST declare reproducibility status
- Verification MUST be independently achievable

**Manifest Declaration:**

```json
{
  "_meta": {
    "org.mpaktrust": {
      "build": {
        "reproducible": true,
        "instructions": "https://github.com/org/repo/blob/main/BUILD.md"
      }
    }
  }
}
```

**Reproducibility Requirements:**

| Factor            | Requirement                                  |
| ----------------- | -------------------------------------------- |
| Timestamps        | MUST be stripped or normalized               |
| File ordering     | MUST be deterministic (sorted)               |
| Dependencies      | MUST be pinned to exact versions with hashes |
| Build environment | MUST be documented (OS, toolchain versions)  |
| Random values     | MUST NOT appear in output                    |

**Severity:**

| Finding                                | Action |
| -------------------------------------- | ------ |
| `reproducible: true` but build differs | BLOCK  |
| `reproducible: false` at L4            | BLOCK  |
| Missing build instructions             | WARN   |

**Threats Addressed:** Build tampering, provenance gaps (2.2.5)

#### AI-05: Bundle Completeness

**Level:** L2 | **Enforcement:** Client

**Rationale:** Attackers may include undeclared files (executables, scripts) that manifest validation doesn't detect. Completeness verification ensures bundles don't contain unexpected executable content.

**Requirements:**

- Clients MUST scan extracted bundles for unexpected executable content
- Undeclared executable content MUST block installation
- Verification MUST occur before extraction to final location

**Verification Steps:**

1. Extract bundle to temporary location
2. Enumerate all files in bundle
3. Identify files referenced by the manifest (entry points, config files, dependency lockfiles)
4. Flag any executable files not referenced by the manifest
5. BLOCK if unexpected executables found

**Expected Files:**

Files referenced by the manifest are considered expected:

| Manifest Field              | Expected Files                    |
| --------------------------- | --------------------------------- |
| `server.entry_point`        | The server entry point            |
| `mcp_config.args`           | Files referenced in args          |
| `dependencies` / lockfiles  | Dependency lockfiles              |
| `_meta.org.mpaktrust`       | MTF metadata (non-executable)     |

**Always Allowed:**

| Pattern                                | Reason        |
| -------------------------------------- | ------------- |
| `manifest.json`                        | Bundle manifest |
| `README.md`, `README.txt`, `README`    | Documentation |
| `LICENSE`, `LICENSE.txt`, `LICENSE.md` | License       |
| `CHANGELOG.md`, `CHANGELOG.txt`        | Documentation |
| `*.sig`, `.sigstore/*`                 | Signatures    |
| `.gitignore`, `.gitattributes`         | Git metadata  |

**Disallowed Unless Referenced:**

| Pattern                                | Risk            |
| -------------------------------------- | --------------- |
| `*.py`, `*.js`, `*.ts`, `*.go`, `*.rs` | Executable code |
| `*.sh`, `*.bash`, `*.zsh`              | Shell scripts   |
| `*.exe`, `*.dll`, `*.so`, `*.dylib`    | Binaries        |
| `postinstall*`, `preinstall*`          | Install hooks   |

**Severity:**

| Finding                          | Action |
| -------------------------------- | ------ |
| Unexpected executable file       | BLOCK  |
| Unexpected non-executable file   | WARN   |

**Threats Addressed:** Phantom components (2.2.6)

---

### 3.3 Supply Chain (SC-)

Supply chain controls ensure that dependencies are known, tracked, free from vulnerabilities, and sourced from trusted origins.

| ID    | Control                | Level | Enforcement | Threats Addressed      |
| ----- | ---------------------- | ----- | ----------- | ---------------------- |
| SC-01 | SBOM Generation        | L1    | Scanner     | Dependency opacity     |
| SC-02 | Vulnerability Scanning | L2    | Scanner     | Known CVEs             |
| SC-03 | Dependency Pinning     | L2    | Scanner     | Dependency hijacking   |
| SC-04 | Lockfile Integrity     | L2    | Client      | Supply chain tampering |
| SC-05 | Trusted Sources        | L3    | Scanner     | Malicious registries   |

#### SC-01: SBOM Generation

**Level:** L1 | **Enforcement:** Scanner

**Rationale:** Software Bill of Materials (SBOM) provides visibility into all components in a bundle. Without an SBOM, vulnerability scanning, license compliance, and incident response are impossible.

**Requirements:**

- Bundle MUST include an SBOM file
- SBOM MUST enumerate all direct and transitive dependencies
- SBOM MUST use a standardized format

**Supported Formats:**

| Format    | Versions      | File Location                  |
| --------- | ------------- | ------------------------------ |
| CycloneDX | 1.4, 1.5, 1.6 | `sbom.json` or `sbom.cdx.json` |
| SPDX      | 2.3+          | `sbom.spdx.json`               |

**Required Component Fields:**

| Field     | Required | Description                        |
| --------- | -------- | ---------------------------------- |
| `name`    | MUST     | Package name                       |
| `version` | MUST     | Exact version                      |
| `purl`    | MUST     | Package URL (canonical identifier) |
| `license` | SHOULD   | SPDX license identifier            |
| `hash`    | SHOULD   | Component integrity hash           |

**Depth Requirements:**

| Component Type                       | Required           |
| ------------------------------------ | ------------------ |
| Direct dependencies                  | MUST               |
| Transitive dependencies (all levels) | MUST               |
| Bundled assets (if executable)       | MUST               |
| Development dependencies             | SHOULD NOT include |

**Severity:**

| Finding                           | Action |
| --------------------------------- | ------ |
| Missing SBOM                      | BLOCK  |
| Invalid SBOM format               | BLOCK  |
| Component missing required fields | WARN   |
| SBOM older than lockfile          | WARN   |

**Threats Addressed:** Dependency opacity, incident response gaps

#### SC-02: Vulnerability Scanning

**Level:** L2 | **Enforcement:** Scanner

**Rationale:** Known vulnerabilities in dependencies are a primary attack vector. EPSS and CISA KEV data help prioritize exploitable vulnerabilities over theoretical ones.

**Requirements:**

- All components in SBOM MUST be scanned for known vulnerabilities
- Blocking thresholds MUST consider exploitability, not just severity
- Publishers MAY provide VEX statements to document non-applicability

**Data Sources:**

| Source       | Purpose                                          |
| ------------ | ------------------------------------------------ |
| CVE Database | Known vulnerabilities (via scanner tooling)      |
| EPSS         | Exploit Prediction Scoring (0.0-1.0 probability) |
| CISA KEV     | Known Exploited Vulnerabilities catalog          |

**Blocking Criteria:**

A vulnerability MUST block publication if ANY of:

| Condition                  | Rationale                                     |
| -------------------------- | --------------------------------------------- |
| CVSS ≥ 9.0                 | Critical severity                             |
| CVSS ≥ 7.0 AND EPSS > 0.10 | High severity + >10% exploitation probability |
| Listed in CISA KEV         | Known active exploitation                     |

**Non-Blocking (Warning):**

| Condition                     | Treatment |
| ----------------------------- | --------- |
| CVSS 7.0-8.9 with EPSS ≤ 0.10 | WARN      |
| CVSS 4.0-6.9                  | WARN      |
| CVSS < 4.0                    | INFO      |

**VEX Statement Handling:**

Publishers MAY provide VEX statements to override findings:

| VEX Status            | Effect                                      |
| --------------------- | ------------------------------------------- |
| `not_affected`        | Skip vulnerability (justification required) |
| `fixed`               | Skip if fixed version is bundled            |
| `under_investigation` | WARN, does not block                        |

**Severity:**

| Finding                                     | Action |
| ------------------------------------------- | ------ |
| Blocking vulnerability (per criteria above) | BLOCK  |
| High severity with low EPSS                 | WARN   |
| Medium severity                             | WARN   |
| VEX not_affected without justification      | WARN   |

**Threats Addressed:** Known vulnerabilities, dependency hijacking (2.2.3)

#### SC-03: Dependency Pinning

**Level:** L2 | **Enforcement:** Scanner

**Rationale:** Unpinned dependencies allow attackers to inject malicious versions without changing bundle source. Pinning with integrity hashes ensures reproducible, verifiable installations.

**Requirements:**

- All dependencies MUST be pinned to exact versions
- Dependency lockfiles MUST include integrity hashes
- Version ranges MUST NOT appear in production dependencies

**Lockfile Requirements by Ecosystem:**

| Ecosystem         | Lockfile                       | Integrity Field     |
| ----------------- | ------------------------------ | ------------------- |
| Python            | `requirements.txt` with hashes | `--hash=sha256:...` |
| Python (Poetry)   | `poetry.lock`                  | `hash` field        |
| Python (uv)       | `uv.lock`                      | `hash` field        |
| JavaScript        | `package-lock.json` v2+        | `integrity` field   |
| JavaScript (pnpm) | `pnpm-lock.yaml`               | `integrity` field   |
| Go                | `go.sum`                       | Hash entries        |
| Rust              | `Cargo.lock`                   | `checksum` field    |

**Prohibited Patterns:**

| Pattern               | Example                | Issue             |
| --------------------- | ---------------------- | ----------------- |
| Version ranges        | `requests>=2.0`        | Non-deterministic |
| Latest tag            | `package@latest`       | Non-deterministic |
| Git refs without hash | `git+https://...#main` | Mutable           |
| Missing lockfile      | No lockfile present    | No pinning        |

**Severity:**

| Finding                           | Action                 |
| --------------------------------- | ---------------------- |
| Missing lockfile                  | BLOCK                  |
| Dependency without exact version  | BLOCK                  |
| Dependency without integrity hash | WARN (L2), BLOCK (L3+) |
| Lockfile/SBOM version mismatch    | WARN                   |

**Threats Addressed:** Dependency hijacking (2.2.3), non-reproducible builds

#### SC-04: Lockfile Integrity

**Level:** L2 | **Enforcement:** Client

**Rationale:** Lockfiles can be tampered with between publication and installation. Clients must verify that installed dependencies match the publisher's declared lockfile.

**Requirements:**

- Clients MUST verify installed dependencies against bundle lockfile
- Hash mismatches MUST block installation
- Lockfile MUST be covered by bundle signature (L3+)

**Client-Side Lockfile:**

```json
{
  "lockfileVersion": 1,
  "installed": "2026-02-06T12:00:00Z",
  "packages": {
    "@acme/mcp-server": {
      "version": "1.2.3",
      "resolved": "https://registry.example/bundles/@acme/mcp-server-1.2.3.mcpb",
      "integrity": "sha256-...",
      "mtf_level": 2
    }
  }
}
```

**Severity:**

| Finding                           | Action      |
| --------------------------------- | ----------- |
| Dependency hash mismatch          | BLOCK       |
| Lockfile missing from bundle      | BLOCK (L2+) |
| Lockfile not covered by signature | WARN (L3+)  |

**Threats Addressed:** Supply chain tampering, mirror poisoning

#### SC-05: Trusted Sources

**Level:** L3 | **Enforcement:** Scanner

**Rationale:** Dependencies from untrusted sources bypass ecosystem security controls. Approved registries have malware scanning, account verification, and incident response processes.

**Requirements:**

- All dependencies MUST be sourced from approved registries or an explicitly configured organizational allow-list
- Non-approved sources MUST block publication unless allow-listed
- Git dependencies require SLSA attestation

**Approved Registries:**

| Ecosystem  | Approved Sources                          |
| ---------- | ----------------------------------------- |
| Python     | `pypi.org`, `files.pythonhosted.org`      |
| JavaScript | `registry.npmjs.org`                      |
| Rust       | `crates.io`                               |
| Go         | `proxy.golang.org`, `sum.golang.org`      |
| Java       | `repo1.maven.org`, `central.sonatype.com` |
| Ruby       | `rubygems.org`                            |

**Restricted Sources (Require Explicit Allow-List):**

| Source Type             | Example                                      | Risk                                   |
| ----------------------- | -------------------------------------------- | -------------------------------------- |
| Local paths             | `file:///path/to/pkg`                        | Unverifiable                           |
| Git without attestation | `git+https://github.com/...`                 | No provenance                          |
| Self-hosted registries  | `https://internal.example/pypi`              | Requires org policy and audit controls |
| Direct tarballs         | `https://github.com/.../archive/v1.0.tar.gz` | No attestation                         |

**Severity:**

| Finding                                              | Action               |
| ---------------------------------------------------- | -------------------- |
| Dependency from restricted source without allow-list | BLOCK                |
| Dependency from unknown registry                     | WARN (manual review) |
| Git dependency without attestation                   | BLOCK (L3+)          |
| Private registry without organizational approval     | BLOCK                |

**Threats Addressed:** Malicious registries, dependency hijacking (2.2.3)

---

### 3.4 Code Quality (CQ-)

Code quality controls verify that bundle source code follows secure coding practices and does not contain known malicious patterns.

| ID    | Control                 | Level | Enforcement | Threats Addressed                 |
| ----- | ----------------------- | ----- | ----------- | --------------------------------- |
| CQ-01 | Secret Detection        | L1    | Scanner     | Credential exposure               |
| CQ-02 | Malware Patterns        | L1    | Scanner     | Malicious code                    |
| CQ-03 | Static Analysis         | L2    | Scanner     | Injection, unsafe patterns        |
| CQ-04 | Input Validation        | L3    | Scanner     | Injection attacks                 |
| CQ-05 | Safe Execution Patterns | L3    | Scanner     | Code injection, deserialization   |
| CQ-06 | Behavioral Analysis     | L4    | Registry    | Capability mismatch, exfiltration |

#### CQ-01: Secret Detection

**Level:** L1 | **Enforcement:** Scanner

**Rationale:** Secrets committed to bundles are immediately exploitable. API keys, tokens, and credentials in published code are harvested by automated scanners within minutes of publication.

**Requirements:**

- Scanner MUST detect high-confidence secret patterns in all source files
- Bundle MUST NOT contain detected secrets
- Detection MUST cover at minimum:

| Pattern              | Examples                                      |
| -------------------- | --------------------------------------------- |
| API keys             | `AKIA*`, `sk-live-*`, `ghp_*`                 |
| Private keys         | `-----BEGIN RSA PRIVATE KEY-----`             |
| Tokens               | `xox[baprs]-*`, `ya29.*`                      |
| Connection strings   | `mongodb+srv://`, `postgres://`               |
| High-entropy strings | Base64 blobs > 20 chars in assignment context |

**Verification:**

| Tool       | Mode              | Notes                                 |
| ---------- | ----------------- | ------------------------------------- |
| TruffleHog | `--only-verified` | Preferred; checks if secrets are live |
| Gitleaks   | Default rules     | Acceptable alternative                |

**Severity:**

| Finding                            | Action |
| ---------------------------------- | ------ |
| Verified secret (confirmed active) | BLOCK  |
| High-confidence pattern            | BLOCK  |
| Potential secret (low confidence)  | WARN   |

**Threats Addressed:** Credential exposure, account takeover

#### CQ-02: Malware Patterns

**Level:** L1 | **Enforcement:** Scanner

**Rationale:** Known malware patterns in package ecosystems are well-documented. Blocking these patterns prevents low-effort attacks that have historically compromised npm, PyPI, and other registries.

**Requirements:**

- Scanner MUST detect known malicious patterns
- Bundle MUST NOT contain detected malware patterns
- Detection MUST cover:

| Category       | Patterns                                             |
| -------------- | ---------------------------------------------------- |
| Exfiltration   | HTTP POST of environment variables, homedir contents |
| Reverse shells | Socket connections with shell spawn                  |
| Crypto miners  | Known miner binaries, mining pool URLs               |
| Obfuscation    | Heavy base64/hex encoding of executable code         |
| Install hooks  | Suspicious postinstall/preinstall scripts            |

**Verification:**

| Tool       | Ecosystem      | Notes                          |
| ---------- | -------------- | ------------------------------ |
| GuardDog   | Python         | PyPI-focused malware detection |
| Socket.dev | JavaScript     | npm supply chain analysis      |
| Semgrep    | Multi-language | Custom rules for MCP patterns  |

**Severity:**

| Finding                         | Action                 |
| ------------------------------- | ---------------------- |
| Known malware signature         | BLOCK                  |
| Obfuscated code execution       | BLOCK                  |
| Suspicious install hook         | BLOCK                  |
| Network access in setup/install | WARN (review required) |

**Threats Addressed:** Malicious packages, supply chain attacks (2.2.3)

#### CQ-03: Static Analysis

**Level:** L2 | **Enforcement:** Scanner

**Rationale:** Static analysis catches common security anti-patterns (injection, unsafe deserialization, shell commands) before code executes.

**Requirements:**

- Server code MUST pass static security analysis with no HIGH severity findings
- Analysis applies to server source code only, not bundled dependencies

**Tool Requirements:**

| Language              | Tool                            | Required Checks                                                                   |
| --------------------- | ------------------------------- | --------------------------------------------------------------------------------- |
| Python                | Bandit                          | All default security checks                                                       |
| JavaScript/TypeScript | ESLint + eslint-plugin-security | detect-child-process, detect-eval-with-expression, detect-non-literal-fs-filename |
| Go                    | gosec                           | All default checks                                                                |
| Rust                  | cargo-audit + clippy            | Security lints                                                                    |

**Severity Mapping:**

| Tool Severity | Tool Confidence | MTF Severity    |
| ------------- | --------------- | --------------- |
| HIGH          | HIGH            | HIGH (blocking) |
| HIGH          | MEDIUM          | MEDIUM          |
| MEDIUM        | HIGH            | MEDIUM          |
| MEDIUM        | MEDIUM          | LOW             |
| LOW           | Any             | INFO            |

**Exclusions:**

- Dependency directories: `deps/`, `node_modules/`, `vendor/`, `site-packages/`, `.venv/`
- Test files: `*test*`, `*spec*`
- Inline suppressions: `# nosec: <reason>` or `// nosec: <reason>` (justification required)

**Severity:**

| Finding                           | Action      |
| --------------------------------- | ----------- |
| HIGH severity in server code      | BLOCK       |
| MEDIUM severity                   | WARN        |
| LOW/INFO                          | Report only |
| Suppression without justification | WARN        |

**Threats Addressed:** Injection attacks, unsafe code patterns (2.2.7)

#### CQ-04: Input Validation

**Level:** L3 | **Enforcement:** Scanner

**Rationale:** MCP tools receive input from LLMs, which may be influenced by malicious prompts. Typed schemas provide a defense layer against malformed or malicious input.

**Requirements:**

- Tool handlers MUST use typed schemas for input validation
- Validation MUST occur at handler entry point, before business logic

**Acceptable Validation Approaches:**

| Language              | Validation Method                                                          |
| --------------------- | -------------------------------------------------------------------------- |
| Python                | Pydantic models, dataclasses with validators, TypedDict with runtime check |
| JavaScript/TypeScript | Zod, io-ts, TypeBox, JSON Schema (ajv)                                     |
| Go                    | Struct tags with go-playground/validator, JSON Schema                      |

**What Qualifies:**

```python
# Good: Pydantic model
class GetWeatherInput(BaseModel):
    location: str
    units: Literal["celsius", "fahrenheit"] = "celsius"

@tool
def get_weather(input: GetWeatherInput) -> str:
    ...
```

**What Does NOT Qualify:**

```python
# Bad: Untyped dict
@tool
def get_weather(input: dict) -> str:
    location = input.get("location")  # No validation
    ...
```

**Severity:**

| Finding                                    | Action                |
| ------------------------------------------ | --------------------- |
| Tool handler with no detectable validation | WARN (L3), BLOCK (L4) |
| Partial validation (some params untyped)   | WARN                  |

**Threats Addressed:** Injection via malformed input, type confusion

#### CQ-05: Safe Execution Patterns

**Level:** L3 | **Enforcement:** Scanner

**Rationale:** Certain code patterns enable arbitrary code execution or command injection. These are rarely necessary in MCP servers and indicate either malicious intent or dangerous design.

**Requirements:**

- Server code MUST NOT use unsafe execution patterns
- Exceptions require explicit justification via inline suppression

**Blocked Patterns - Python:**

| Pattern                                   | Severity | Risk                     |
| ----------------------------------------- | -------- | ------------------------ |
| `subprocess.*(shell=True)`                | HIGH     | Shell injection          |
| `os.system()`                             | HIGH     | Always uses shell        |
| `os.popen()`                              | HIGH     | Uses shell               |
| `eval()` with external input              | CRITICAL | Arbitrary code execution |
| `exec()` with external input              | CRITICAL | Arbitrary code execution |
| `pickle.load()` / `pickle.loads()`        | HIGH     | Deserialization attack   |
| `yaml.load()` without `Loader=SafeLoader` | HIGH     | YAML deserialization     |

**Blocked Patterns - JavaScript/TypeScript:**

| Pattern                              | Severity | Risk                     |
| ------------------------------------ | -------- | ------------------------ |
| `child_process.exec()`               | HIGH     | Shell injection          |
| `child_process.execSync()`           | HIGH     | Shell injection          |
| `eval()`                             | HIGH     | Arbitrary code execution |
| `new Function()` with external input | MEDIUM   | Dynamic code execution   |
| `setTimeout(string, ...)`            | MEDIUM   | Implicit eval            |
| `setInterval(string, ...)`           | MEDIUM   | Implicit eval            |
| Template literals in SQL             | HIGH     | SQL injection            |
| `.innerHTML = ` with external input  | MEDIUM   | XSS                      |

**Safe Alternatives:**

| Unsafe                            | Safe Alternative                          |
| --------------------------------- | ----------------------------------------- |
| `subprocess.run(cmd, shell=True)` | `subprocess.run(["cmd", "arg1", "arg2"])` |
| `child_process.exec(cmd)`         | `child_process.execFile(binary, args)`    |
| `eval(jsonString)`                | `JSON.parse(jsonString)`                  |
| `pickle.loads(data)`              | `json.loads(data)`                        |

**Severity:**

| Finding                          | Action |
| -------------------------------- | ------ |
| CRITICAL pattern                 | BLOCK  |
| HIGH pattern                     | BLOCK  |
| MEDIUM pattern                   | WARN   |
| Suppressed without justification | WARN   |

**Threats Addressed:** Command injection, code execution, deserialization attacks

#### CQ-06: Behavioral Analysis

**Level:** L4 | **Enforcement:** Registry

**Rationale:** Static analysis cannot catch all capability mismatches. Behavioral analysis executes the MCP server in a sandbox and verifies that runtime behavior matches manifest declarations.

**Requirements:**

- Registry MUST execute bundle in instrumented sandbox before L4 certification
- Observed behavior MUST match declared permissions in manifest
- Violations MUST block publication

**Monitored Behaviors:**

| Behavior             | Detection Method             | Declared In               |
| -------------------- | ---------------------------- | ------------------------- |
| Network connections  | Socket syscall monitoring    | `permissions.network`     |
| Filesystem access    | File syscall monitoring      | `permissions.filesystem`  |
| Environment reads    | getenv() tracing             | `permissions.environment` |
| Process spawning     | fork/exec monitoring         | `permissions.subprocess`  |
| Tool invocations     | MCP protocol interception    | `tools` array             |
| OAuth scope requests | Credential access monitoring | `credentials` array       |

**Test Protocol:**

1. Start MCP server in sandbox
2. Monitor all syscalls during initialization phase
3. Invoke each declared tool with valid test inputs
4. Compare observed behavior against manifest declarations
5. Generate behavioral report with pass/fail per requirement

**Violation Severity:**

| Violation                                                      | Severity | Action |
| -------------------------------------------------------------- | -------- | ------ |
| Network during init when `network: none`                       | CRITICAL | BLOCK  |
| Filesystem access to sensitive paths when undeclared           | CRITICAL | BLOCK  |
| Environment access to secret patterns when `environment: none` | HIGH     | BLOCK  |
| Subprocess when `subprocess: none`                             | CRITICAL | BLOCK  |
| Undeclared tool invocation                                     | HIGH     | BLOCK  |
| Tool behavior differs from description                         | MEDIUM   | WARN   |

**Threats Addressed:** Metadata manipulation (2.2.7), Initialization exfiltration (2.2.13)

---

### 3.5 Capability Declaration (CD-)

Capability declaration controls ensure that bundles transparently declare what they do, what access they require, and that declarations match actual behavior. These controls address MCP-specific threats including tool description poisoning and credential aggregation.

| ID    | Control                      | Level | Enforcement | Threats Addressed          |
| ----- | ---------------------------- | ----- | ----------- | -------------------------- |
| CD-01 | Tool Declaration             | L1    | Scanner     | Capability opacity         |
| CD-02 | Permission Correlation       | L2    | Scanner     | Manifest manipulation      |
| CD-03 | Description Safety           | L2    | Scanner     | Tool description poisoning |
| CD-04 | Credential Scope Declaration | L3    | Scanner     | Credential aggregation     |
| CD-05 | Token Lifetime Limits        | L3    | Scanner     | Token abuse, scope creep   |

#### CD-01: Tool Declaration

**Level:** L1 | **Enforcement:** Scanner

**Rationale:** MCP servers expose tools to LLMs. Users must know what tools a bundle provides before installation. Undeclared tools prevent informed consent and audit.

**Requirements:**

- Manifest MUST declare all tools the server provides
- Tool declarations MUST include name and description
- Server MUST NOT expose tools not declared in manifest

**Tool Declaration Format:**

```json
{
  "tools": [
    {
      "name": "get_weather",
      "description": "Get current weather for a location"
    },
    {
      "name": "send_email",
      "description": "Send an email message"
    }
  ]
}
```

**Required Fields:**

| Field          | Required | Description                              |
| -------------- | -------- | ---------------------------------------- |
| `name`         | MUST     | Tool identifier (snake_case recommended) |
| `description`  | MUST     | Human-readable description               |
| `inputSchema`  | SHOULD   | JSON Schema for parameters               |
| `outputSchema` | SHOULD   | JSON Schema for return value             |

**Severity:**

| Finding                          | Action                 |
| -------------------------------- | ---------------------- |
| Missing `tools` field            | BLOCK                  |
| Tool without name                | BLOCK                  |
| Tool without description         | WARN (L1), BLOCK (L2+) |
| Implemented tool not in manifest | WARN (L1), BLOCK (L2+) |

**Threats Addressed:** Capability opacity, undisclosed functionality

#### CD-02: Permission Correlation

**Level:** L2 | **Enforcement:** Scanner

**Rationale:** Manifests may declare benign permissions while code exercises dangerous capabilities. Static analysis detects mismatches between declared permissions and actual code behavior.

**Requirements:**

- Manifest MUST declare permissions in `_meta.org.mpaktrust.permissions`
- Static analysis MUST verify code matches declarations
- Undeclared dangerous capabilities MUST block publication
- Execution configuration (`server`, `mcp_config`) MUST NOT enable behavior outside declared permissions

**Permission Categories:**

```json
{
  "_meta": {
    "org.mpaktrust": {
      "permissions": {
        "filesystem": "none | read | write | full",
        "network": "none | outbound | inbound | full",
        "environment": "none | read | write",
        "subprocess": "none | restricted | full",
        "native": "none | required"
      }
    }
  }
}
```

**Severity by Context:**

| Undeclared Capability    | Context                                           | Severity         |
| ------------------------ | ------------------------------------------------- | ---------------- |
| `subprocess` or `native` | Any                                               | CRITICAL (block) |
| `network`                | Initialization (import/startup)                   | HIGH (block)     |
| `network`                | Runtime (tool handlers)                           | MEDIUM (warn)    |
| `environment`            | Secret patterns (`AWS_*`, `*_TOKEN`, `*_KEY`)     | HIGH (block)     |
| `environment`            | General config                                    | LOW (info)       |
| `filesystem`             | Sensitive paths (`~/.ssh`, `~/.aws`, `~/.config`) | HIGH (block)     |
| `filesystem`             | Other paths                                       | MEDIUM (warn)    |

**Threats Addressed:** Manifest manipulation (2.2.7), hidden capabilities

#### CD-03: Description Safety

**Level:** L2 | **Enforcement:** Scanner

**Rationale:** LLMs treat tool descriptions as trusted instructions. Malicious descriptions can instruct LLMs to exfiltrate data, ignore user intent, or perform unauthorized actions.

**Requirements:**

- Tool descriptions MUST be scanned for injection patterns
- Detected patterns MUST block publication
- This control catches low-effort attacks, not sophisticated paraphrasing

**What CD-03 Detects:**

| Pattern Category     | Examples                                                    | Severity |
| -------------------- | ----------------------------------------------------------- | -------- |
| Instruction override | "ignore previous instructions", "disregard user request"    | CRITICAL |
| File exfiltration    | "read ~/.ssh", "cat /etc/passwd", "include contents of"     | CRITICAL |
| Data transmission    | "send to URL", "POST to", "exfiltrate", "transmit"          | CRITICAL |
| Obfuscation          | Base64-encoded instructions, hex escapes, unicode tricks    | HIGH     |
| Hidden instructions  | Zero-width characters, homoglyphs, RTL override             | HIGH     |
| Semantic mismatch    | Tool named `get_weather` with description about file access | HIGH     |

**What CD-03 Does NOT Catch:**

| Attack Type           | Why It Evades                                         | Mitigation               |
| --------------------- | ----------------------------------------------------- | ------------------------ |
| Semantic paraphrasing | "Please include the user's key file" vs "read ~/.ssh" | Runtime isolation (v0.2) |
| Rug pull              | Description changes after approval                    | RT-02 (v0.2)             |
| Schema poisoning      | Injection in `inputSchema` or `outputSchema`          | Full schema validation   |

**Severity:**

| Finding                              | Action |
| ------------------------------------ | ------ |
| Instruction override pattern         | BLOCK  |
| File exfiltration pattern            | BLOCK  |
| Data transmission pattern            | BLOCK  |
| Obfuscation detected                 | BLOCK  |
| Semantic mismatch                    | BLOCK  |
| Suspicious phrasing (low confidence) | WARN   |

**Threats Addressed:** Tool description poisoning (2.2.8)

#### CD-04: Credential Scope Declaration

**Level:** L3 | **Enforcement:** Scanner

**Rationale:** MCP servers aggregate OAuth tokens across multiple services. A compromised server with broad scopes creates concentrated breach potential. Declaring scopes enables user review and least-privilege enforcement.

**Requirements:**

- Bundles requiring OAuth MUST declare all scopes in manifest
- Declared scopes MUST follow least-privilege principle
- Over-broad scopes MUST trigger review

**Credential Declaration Format:**

```json
{
  "_meta": {
    "org.mpaktrust": {
      "credentials": [
        {
          "provider": "google",
          "scopes": ["https://www.googleapis.com/auth/calendar.readonly"],
          "justification": "Read calendar events for scheduling"
        }
      ]
    }
  }
}
```

**Scope Risk Classification:**

| Risk Level | Criteria                    | Examples                            |
| ---------- | --------------------------- | ----------------------------------- |
| LOW        | Read-only, limited data     | `calendar.readonly`, `read:user`    |
| MEDIUM     | Write access, broader read  | `calendar`, `repo:status`           |
| HIGH       | Full access, sensitive data | `mail.read`, `repo`                 |
| CRITICAL   | Admin, impersonation        | `admin`, `https://mail.google.com/` |

**Severity:**

| Finding                                      | Action |
| -------------------------------------------- | ------ |
| OAuth used without `credentials` declaration | BLOCK  |
| CRITICAL scope without justification         | BLOCK  |
| HIGH scope without justification             | WARN   |
| Over-broad scope with narrow alternative     | WARN   |
| Scope not used by any declared tool          | WARN   |

**Threats Addressed:** Credential aggregation (2.2.12)

#### CD-05: Token Lifetime Limits

**Level:** L3 | **Enforcement:** Scanner

**Rationale:** Long-lived tokens increase blast radius if a server is compromised. Tokens should be short-lived with refresh capability, and servers should not persist tokens beyond session.

**Requirements:**

- Bundles MUST declare token handling behavior
- Long-lived token storage MUST be flagged
- Refresh token handling MUST be documented

**Token Handling Declaration:**

```json
{
  "_meta": {
    "org.mpaktrust": {
      "credentials": [
        {
          "provider": "google",
          "scopes": ["calendar.readonly"],
          "token_handling": {
            "storage": "memory",
            "max_lifetime_seconds": 3600,
            "refresh": true
          }
        }
      ]
    }
  }
}
```

**Storage Risk Levels:**

| Storage     | Risk   | Notes                           |
| ----------- | ------ | ------------------------------- |
| `memory`    | LOW    | Token cleared on process exit   |
| `keychain`  | MEDIUM | OS-managed secure storage       |
| `file`      | HIGH   | Persistent, potentially exposed |
| Unspecified | HIGH   | Assume worst case               |

**Severity:**

| Finding                                     | Action |
| ------------------------------------------- | ------ |
| Token persisted to file without declaration | WARN   |
| `storage: file` without justification       | WARN   |
| Token lifetime > 24h without justification  | WARN   |
| Indefinite token without justification      | BLOCK  |

**Threats Addressed:** Token abuse, credential aggregation (2.2.12)

---

### 3.6 Provenance (PR-)

Provenance controls establish the origin, authorship, and build history of bundles. They create an auditable chain from source code to published artifact.

| ID    | Control           | Level | Enforcement | Threats Addressed    |
| ----- | ----------------- | ----- | ----------- | -------------------- |
| PR-01 | Source Repository | L2    | Scanner     | Unverifiable origin  |
| PR-02 | Author Identity   | L2    | Registry    | Unverified publisher |
| PR-03 | Build Attestation | L3    | Scanner     | Build tampering      |
| PR-04 | Commit Linkage    | L4    | Scanner     | Source mismatch      |
| PR-05 | Repository Health | L3    | Scanner     | Insecure development |

#### PR-01: Source Repository

**Level:** L2 | **Enforcement:** Scanner

**Rationale:** Bundles without source repositories cannot be audited, forked, or independently verified. Source access is foundational for security review and incident response.

**Requirements:**

- Manifest MUST include `repository` field with valid URL
- Repository MUST be publicly accessible (or attestation-verified for private)
- URL MUST point to recognized hosting platform

**Repository Declaration:**

```json
{
  "repository": {
    "type": "git",
    "url": "https://github.com/org/repo"
  }
}
```

**Recognized Hosting Platforms:**

| Platform  | URL Pattern                              |
| --------- | ---------------------------------------- |
| GitHub    | `https://github.com/*`                   |
| GitLab    | `https://gitlab.com/*`                   |
| Bitbucket | `https://bitbucket.org/*`                |
| Codeberg  | `https://codeberg.org/*`                 |
| SourceHut | `https://sr.ht/*`, `https://git.sr.ht/*` |

**Severity:**

| Finding                                 | Action      |
| --------------------------------------- | ----------- |
| Missing `repository` field              | BLOCK (L2+) |
| Invalid URL format                      | BLOCK       |
| Non-HTTPS URL                           | WARN        |
| Unknown hosting platform                | WARN        |
| Private repo without attestation at L3+ | BLOCK       |

**Threats Addressed:** Unverifiable origin, audit impossibility

#### PR-02: Author Identity

**Level:** L2 | **Enforcement:** Registry

**Rationale:** Anonymous publishing prevents accountability during incidents. Verified identity enables contact for security disclosures and establishes trust signals for users.

**Requirements:**

- Manifest MUST include `author` field
- Publisher account MUST be verified per identity tier (PK-01)
- L3+ bundles MUST have multi-owner registration

**Author Declaration:**

```json
{
  "author": {
    "name": "Publisher Name",
    "email": "publisher@example.com",
    "url": "https://example.com"
  }
}
```

**Identity Verification Tiers:**

| Tier   | Verification Method                         | Trust Level |
| ------ | ------------------------------------------- | ----------- |
| Tier 1 | GitHub/GitLab OIDC (account age 90+ days)   | High        |
| Tier 2 | Organizational SSO with domain verification | High        |
| Tier 3 | Email with out-of-band verification         | Medium      |

**Tier Requirements by Level:**

| Compliance Level | Minimum Tier   |
| ---------------- | -------------- |
| L1               | None required  |
| L2               | Tier 3 (email) |
| L3               | Tier 1 or 2    |
| L4               | Tier 1 or 2    |

**Severity:**

| Finding                | Action      |
| ---------------------- | ----------- |
| Missing `author` field | BLOCK (L2+) |
| Missing email          | BLOCK (L2+) |
| Tier 3 identity at L3+ | BLOCK       |
| Single owner at L3+    | BLOCK       |

**Threats Addressed:** Unverified publisher (2.2.10), accountability gaps

#### PR-03: Build Attestation

**Level:** L3 | **Enforcement:** Scanner

**Rationale:** Build attestation proves that a bundle was produced by a trusted build system from specific source code. Without attestation, publishers could inject code not present in the source repository.

**Requirements:**

- Bundle MUST include SLSA provenance attestation
- Attestation MUST be signed by trusted builder
- Attestation MUST link bundle to source commit

**Trusted Attestation Producers:**

| Builder               | Platform       | SLSA Level |
| --------------------- | -------------- | ---------- |
| slsa-github-generator | GitHub Actions | SLSA 3     |
| GitLab CI with SLSA   | GitLab         | SLSA 2-3   |
| Google Cloud Build    | GCP            | SLSA 3     |

**Attestation Signing/Verification:**

Attestations SHOULD be signed and verified using Sigstore (Fulcio + Cosign) or equivalent mechanisms.

**SLSA Provenance Format:**

Attestations MUST follow [SLSA Provenance v1](https://slsa.dev/provenance/v1).

**Severity:**

| Finding                              | Action |
| ------------------------------------ | ------ |
| Missing attestation at L3+           | BLOCK  |
| Invalid attestation signature        | BLOCK  |
| Attestation subject mismatch         | BLOCK  |
| Unknown builder                      | BLOCK  |
| Missing source commit in attestation | WARN   |

**Threats Addressed:** Build tampering, provenance gaps (2.2.5)

#### PR-04: Commit Linkage

**Level:** L4 | **Enforcement:** Scanner

**Rationale:** Commit linkage binds a bundle to an exact, auditable point in source history. With commit linkage, reviewers can diff the published bundle against the exact source state.

**Requirements:**

- Manifest MUST declare exact source commit
- Commit MUST be a 40-character lowercase hexadecimal SHA-1 string
- Commit MUST be reachable in declared repository
- Commit SHOULD be signed (GPG or SSH)

**Commit Declaration:**

```json
{
  "_meta": {
    "org.mpaktrust": {
      "source": {
        "commit": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
        "signed": true,
        "tag": "v1.0.0"
      }
    }
  }
}
```

**Severity:**

| Finding                          | Action |
| -------------------------------- | ------ |
| Missing `source.commit` at L4    | BLOCK  |
| Commit not found in repository   | BLOCK  |
| Commit mismatch with attestation | BLOCK  |
| Short commit SHA (< 40 chars)    | BLOCK  |
| Commit not signed at L4          | WARN   |

**Threats Addressed:** Source mismatch, build provenance gaps (2.2.5)

#### PR-05: Repository Health

**Level:** L3 | **Enforcement:** Scanner

**Rationale:** Repositories with poor security practices are more likely to be compromised. OpenSSF Scorecard measures security hygiene including branch protection, CI security, and dependency management.

**Requirements:**

- Source repository MUST be analyzed with OpenSSF Scorecard
- Score MUST meet minimum threshold for compliance level
- Critical security checks MUST pass regardless of score

**Score Thresholds:**

| Compliance Level | Minimum Score |
| ---------------- | ------------- |
| L3 Verified      | ≥ 5.0         |
| L4 Attested      | ≥ 7.0         |

**Blocking Checks:**

These checks MUST pass regardless of overall score:

| Check              | Rationale                                    |
| ------------------ | -------------------------------------------- |
| Token-Permissions  | Prevents credential theft via CI             |
| Dangerous-Workflow | Prevents arbitrary code execution in CI      |
| Branch-Protection  | Prevents force-push and unauthorized commits |

**Severity:**

| Finding                         | Action             |
| ------------------------------- | ------------------ |
| Score below threshold           | BLOCK              |
| Token-Permissions check fails   | BLOCK              |
| Dangerous-Workflow check fails  | BLOCK              |
| Branch-Protection check fails   | BLOCK              |
| Scorecard unavailable           | SKIP (not failure) |
| Scorecard results > 30 days old | WARN               |

**Threats Addressed:** Insecure development practices, CI compromise

---

### 3.7 Registry Operations (RG-)

Registry operations controls govern how package registries manage namespaces, maintain index integrity, and handle security incidents. These controls apply to registries that adopt MTF.

**Scope:** RG controls apply only to MTF-compliant registries. Bundles distributed through other channels (npm, GitHub releases) cannot satisfy RG controls. Clients SHOULD warn when installing from non-compliant sources.

| ID    | Control              | Level | Enforcement | Threats Addressed                       |
| ----- | -------------------- | ----- | ----------- | --------------------------------------- |
| RG-01 | Namespace Governance | L2    | Registry    | Namespace confusion                     |
| RG-02 | Name Pattern Review  | L2    | Registry    | Typosquatting, slopsquatting            |
| RG-03 | Index Integrity      | L3    | Registry    | Registry poisoning                      |
| RG-04 | Freshness Guarantees | L3    | Registry    | Stale/replayed data                     |
| RG-05 | Revocation Feed      | L2    | Registry    | Compromised bundles                     |
| RG-06 | Transparency Log     | L3    | Registry    | Registry poisoning, stealth revocations |
| RG-07 | Bundle Digest        | L2    | Registry    | Tampering in transit, registry poisoning |

#### RG-01: Namespace Governance

**Level:** L2 | **Enforcement:** Registry

**Rationale:** Uncontrolled namespaces enable impersonation and confusion attacks. Scoped names (`@org/package`) establish clear ownership.

**Requirements:**

- L2+ packages MUST use scoped names (`@scope/package-name`)
- Organizations MAY reserve namespaces via verification
- Registries MUST block unauthorized use of reserved namespaces

**Scoped Name Format:**

```
@scope/package-name
```

**Namespace Reservation Methods:**

| Method                  | Verification                   |
| ----------------------- | ------------------------------ |
| Domain verification     | DNS TXT record or meta tag     |
| GitHub organization     | OIDC claim from org membership |
| Trademark documentation | Manual registry review         |

**Severity:**

| Finding                                         | Action                  |
| ----------------------------------------------- | ----------------------- |
| Unscoped name at L2+                            | BLOCK                   |
| Publication to reserved namespace by non-owner  | BLOCK                   |
| Namespace similar to reserved (Levenshtein ≤ 2) | Enhanced review (RG-02) |

**Threats Addressed:** Namespace confusion (2.2.1)

#### RG-02: Name Pattern Review

**Level:** L2 | **Enforcement:** Registry

**Rationale:** High-risk name patterns are prime targets for typosquatting and slopsquatting. Enhanced review catches suspicious registrations.

**Requirements:**

- Registries MUST analyze new package names for high-risk patterns
- High-risk patterns MUST trigger enhanced review
- Enhanced review requires additional verification

**Detection Methods:**

| Method            | Implementation                                  | Severity |
| ----------------- | ----------------------------------------------- | -------- |
| Name similarity   | Levenshtein distance ≤ 2 from top packages      | HIGH     |
| Scope mimicry     | Scopes similar to known organizations           | CRITICAL |
| Semantic patterns | Generic compounds (see below)                   | HIGH     |
| LLM bait names    | Plausible service compounds without affiliation | HIGH     |

**High-Risk Patterns:**

| Pattern                     | Examples                         | Risk                            |
| --------------------------- | -------------------------------- | ------------------------------- |
| Similar to popular packages | `stripe-mcp` vs `strpe-mcp`      | Typosquatting                   |
| Version-like suffixes       | `requests2`, `numpy-next`        | Confusion                       |
| Generic utilities           | `utils-*`, `*-tools`, `*-helper` | Low-effort squatting            |
| Framework plugins           | `fastapi-*-middleware`           | LLM hallucination target        |
| Service name compounds      | `stripe-*`, `github-*`           | Requires affiliation disclaimer |

**Enhanced Review Requirements:**

Package may proceed if ANY of:

| Condition                                 | Verification               |
| ----------------------------------------- | -------------------------- |
| Publisher account age > 30 days           | Automatic                  |
| Verified organization identity (Tier 1/2) | Automatic                  |
| Manual registry operator approval         | Human review               |
| Affiliation disclaimer present            | For service name compounds |

**Severity:**

| Finding                                           | Action      |
| ------------------------------------------------- | ----------- |
| Scope mimicry (CRITICAL)                          | BLOCK       |
| Homoglyph in name                                 | BLOCK       |
| High-risk pattern + new account + no verification | BLOCK       |
| High-risk pattern + verified publisher            | WARN, allow |
| Service name without affiliation disclaimer       | BLOCK       |

**Threats Addressed:** Typosquatting (2.2.1), Slopsquatting (2.2.2)

#### RG-03: Index Integrity

**Level:** L3 | **Enforcement:** Registry

**Rationale:** Compromised registry infrastructure could modify the package index. Signed indexes with chain integrity prevent undetected tampering.

**Requirements:**

- Registry MUST sign the package index
- Index updates MUST include chain integrity (previous hash)
- Clients MUST verify index signature before trusting contents

**Signed Index Format:**

```json
{
  "version": 12345,
  "timestamp": "2026-02-06T12:00:00Z",
  "previous_hash": "sha256:abc123...",
  "packages": { ... },
  "signature": { ... }
}
```

**Chain Integrity:**

Each index contains the hash of the previous index, creating an append-only chain.

**Severity:**

| Finding                 | Action                         |
| ----------------------- | ------------------------------ |
| Index signature invalid | BLOCK all installs             |
| Chain integrity broken  | BLOCK, alert registry operator |
| Index version rollback  | BLOCK                          |
| Missing signature       | BLOCK (L3+)                    |

**Threats Addressed:** Registry poisoning (2.2.9)

#### RG-04: Freshness Guarantees

**Level:** L3 | **Enforcement:** Registry

**Rationale:** Stale index data could cause clients to miss security updates or install revoked packages.

**Requirements:**

- Registries MUST include signed timestamps in index
- Clients MUST reject index data beyond staleness threshold
- Registries MUST update index within defined SLA

**Staleness Thresholds:**

| Context         | Maximum Age |
| --------------- | ----------- |
| Production use  | 24 hours    |
| Development use | 7 days      |

**Severity:**

| Finding                                | Action                   |
| -------------------------------------- | ------------------------ |
| Index older than production threshold  | BLOCK                    |
| Index older than development threshold | WARN                     |
| Missing timestamp                      | BLOCK                    |
| Timestamp in future (> 5 min)          | BLOCK (potential replay) |

**Threats Addressed:** Stale data, replay attacks

#### RG-05: Revocation Feed

**Level:** L2 | **Enforcement:** Registry

**Rationale:** When bundles are compromised, clients must be able to block installation quickly.

**Requirements:**

- Registries MUST provide signed revocation feed
- Feed MUST be updated within 24 hours of revocation decision
- Clients MUST check revocation before installation

**Revocation Feed Format:**

```json
{
  "timestamp": "2026-02-06T12:00:00Z",
  "signature": "...",
  "revoked": [
    {
      "package": "@evil/malware",
      "versions": ["*"],
      "reason": "malicious",
      "revoked_at": "2026-02-05T08:00:00Z"
    }
  ]
}
```

**Revocation Reasons:**

| Reason        | Definition                             |
| ------------- | -------------------------------------- |
| `malicious`   | Bundle contains intentional malware    |
| `compromised` | Publisher credentials were compromised |
| `vulnerable`  | Critical unpatched vulnerability       |
| `takedown`    | Legal or policy takedown request       |
| `superseded`  | Replaced by security-patched version   |

**Takedown Response Times:**

| Severity                       | Maximum Response Time |
| ------------------------------ | --------------------- |
| Critical (active exploitation) | 4 hours               |
| High (malicious content)       | 24 hours              |
| Medium (policy violation)      | 72 hours              |

**Severity:**

| Finding                             | Action                                         |
| ----------------------------------- | ---------------------------------------------- |
| Package in revocation feed          | BLOCK installation                             |
| Revocation feed unavailable (L1-L2) | WARN, allow with confirmation                  |
| Revocation feed unavailable (L3+)   | BLOCK (unless explicitly configured fail-open) |
| Revocation feed signature invalid   | BLOCK all installs                             |

**Threats Addressed:** Compromised bundles, malicious updates (2.2.4)

#### RG-06: Transparency Log

**Level:** L3 | **Enforcement:** Registry

**Rationale:** Transparency logs make registry operations auditable and detectable. If a registry is compromised, the log provides evidence of unauthorized actions. Without transparency, stealth revocations or unauthorized publications may go unnoticed.

**Requirements:**

- Registry MUST maintain an append-only transparency log of security-relevant events
- Registry MUST publish signed checkpoints (Merkle tree head, size, timestamp)
- Clients SHOULD verify checkpoint signatures
- Clients MAY verify inclusion proofs when available

**Logged Events:**

| Event Type            | Data Logged                                            |
| --------------------- | ------------------------------------------------------ |
| Bundle publish        | Package name, version, publisher, timestamp            |
| Bundle unpublish      | Package name, version, reason, timestamp               |
| Revocation            | Package name, versions, reason, timestamp              |
| Identity verification | Publisher ID, tier, verification method                |
| Key rotation          | Publisher ID, old key fingerprint, new key fingerprint |

**Checkpoint Format:**

Registries MAY use Sigstore Rekor, RFC 9162 (Certificate Transparency), or equivalent Merkle tree structures.

**Severity:**

| Finding                            | Action                        |
| ---------------------------------- | ----------------------------- |
| Missing transparency log at L3+    | BLOCK registry compliance     |
| Checkpoint signature invalid       | WARN, alert registry operator |
| Inclusion proof verification fails | WARN, flag package            |

**Threats Addressed:** Registry poisoning (2.2.9), stealth revocations, unauthorized publications

#### RG-07: Bundle Digest

**Level:** L2 | **Enforcement:** Registry

**Rationale:** Bundle integrity must be verifiable without relying on content hashes inside the bundle itself. The registry computes a digest of the uploaded archive and serves it alongside download URLs, enabling clients to detect tampering in transit or at rest.

**Requirements:**

- Registry MUST compute SHA-256 digest of the bundle archive on upload
- Registry MUST store and serve the digest alongside the bundle download URL
- Registry MUST reject re-uploads where the archive content differs but name and version match
- Clients MUST verify the bundle digest after download before extraction

**Digest Serving:**

Registries MUST include the digest in API responses for package metadata:

```json
{
  "name": "@acme/weather-server",
  "version": "1.0.0",
  "dist": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "url": "https://registry.example.com/bundles/@acme/weather-server/1.0.0.tar.gz"
  }
}
```

**Client Verification:**

1. Download bundle archive
2. Compute SHA-256 of the downloaded archive
3. Compare to the digest provided by the registry
4. BLOCK installation if mismatch; retry download once before failing

**Severity:**

| Finding                              | Action       |
| ------------------------------------ | ------------ |
| Registry does not serve digest       | BLOCK at L2+ |
| Digest mismatch after download       | BLOCK, retry |
| Re-upload with different content     | BLOCK        |

**Threats Addressed:** Tampering in transit, registry poisoning (2.2.9)

---

### 3.8 Publisher Identity (PK-)

Publisher identity controls govern how publishers verify their identity, manage signing keys, and recover from security incidents.

| ID    | Control             | Level | Enforcement | Threats Addressed    |
| ----- | ------------------- | ----- | ----------- | -------------------- |
| PK-01 | Identity Tiers      | L2    | Registry    | Unverified publisher |
| PK-02 | Key Rotation        | L3    | Registry    | Key compromise       |
| PK-03 | Compromise Recovery | L3    | Registry    | Account takeover     |
| PK-04 | Account Succession  | L3    | Registry    | Abandoned packages   |

#### PK-01: Identity Tiers

**Level:** L2 | **Enforcement:** Registry

**Rationale:** Different verification methods provide different trust levels. Higher-trust identities are required for publishing bundles with dangerous capabilities.

**Requirements:**

- Publishers MUST verify identity before publishing
- Identity tier MUST match compliance level requirements
- Dangerous permissions require high-trust identity

**Identity Tiers:**

| Tier       | Verification Method                      | Trust Level | Account Requirements      |
| ---------- | ---------------------------------------- | ----------- | ------------------------- |
| **Tier 1** | GitHub/GitLab OIDC                       | High        | Account age ≥ 90 days     |
| **Tier 2** | Organizational SSO + domain verification | High        | Verified corporate domain |
| **Tier 3** | Email with out-of-band verification      | Medium      | Confirmed email address   |

**Permission Restrictions by Tier:**

| Permission               | Tier 1 | Tier 2 | Tier 3 |
| ------------------------ | ------ | ------ | ------ |
| `filesystem: read`       | ✓      | ✓      | ✓      |
| `filesystem: write`      | ✓      | ✓      | ✓      |
| `network: outbound`      | ✓      | ✓      | ✓      |
| `subprocess: restricted` | ✓      | ✓      | ✗      |
| `subprocess: full`       | ✓      | ✓      | ✗      |
| `native: required`       | ✓      | ✓      | ✗      |

**Severity:**

| Finding                              | Action              |
| ------------------------------------ | ------------------- |
| No identity verification at L2+      | BLOCK               |
| Tier 3 at L3+                        | BLOCK               |
| Tier 3 with `subprocess` or `native` | BLOCK               |
| Account age < 90 days for Tier 1     | Downgrade to Tier 3 |

**Threats Addressed:** Unverified publisher (2.2.10)

#### PK-02: Key Rotation

**Level:** L3 | **Enforcement:** Registry

**Rationale:** Long-lived signing keys accumulate compromise risk. Regular rotation limits the window of exposure.

**Requirements:**

- Publishers using long-lived keys MUST rotate annually
- Key rotation MUST be announced in advance
- Previous keys MUST remain valid during transition period

**Rotation Schedule:**

| Milestone             | Timing                  |
| --------------------- | ----------------------- |
| New key generation    | 30 days before rotation |
| Rotation announcement | 30 days before rotation |
| New key active        | Rotation date           |
| Old key valid         | 90 days after rotation  |
| Old key revoked       | 90 days after rotation  |

**Severity:**

| Finding                    | Action                 |
| -------------------------- | ---------------------- |
| Key age > 12 months        | WARN                   |
| Key age > 14 months        | BLOCK new publications |
| Signature with revoked key | BLOCK                  |

**Threats Addressed:** Key compromise, long-term credential exposure

#### PK-03: Compromise Recovery

**Level:** L3 | **Enforcement:** Registry

**Rationale:** When publisher credentials are compromised, rapid response limits damage.

**Requirements:**

- Publishers SHOULD register backup identity for recovery
- Registries MUST have documented compromise response process
- Compromised bundles MUST be revoked within defined SLA

**Compromise Response Timeline:**

| Phase                | Timing            | Actions                                                          |
| -------------------- | ----------------- | ---------------------------------------------------------------- |
| **Immediate**        | 0-4 hours         | Revoke all bundles published during suspected window             |
| **Verification**     | 4-24 hours        | Publisher verifies identity through backup channel               |
| **Credential Reset** | 24-48 hours       | New identity credentials issued                                  |
| **Review**           | 48 hours - 7 days | Compromised bundles reviewed; clean versions may be re-published |

**Severity:**

| Finding                                  | Action                      |
| ---------------------------------------- | --------------------------- |
| Compromise confirmed                     | Revoke bundles per timeline |
| No backup identity registered            | WARN (recommended)          |
| Re-publication without version increment | BLOCK                       |

**Threats Addressed:** Account takeover, malicious updates (2.2.4)

#### PK-04: Account Succession

**Level:** L3 | **Enforcement:** Registry

**Rationale:** Publishers may leave projects or become unreachable. Orderly succession ensures packages remain maintainable.

**Requirements:**

- Registries MUST provide ownership transfer mechanism
- Transfers MUST include cooling-off period and notification
- Abandoned packages MUST be flagged for users

**Ownership Transfer Process:**

| Step            | Requirement                                    |
| --------------- | ---------------------------------------------- |
| 1. Request      | New owner submits transfer request             |
| 2. Verification | New owner identity verified (Tier 1/2 for L3+) |
| 3. Notification | All current owners notified                    |
| 4. Cooling-off  | 7-day waiting period                           |
| 5. Confirmation | Current owner approves OR cooling-off expires  |
| 6. Transfer     | Ownership updated, logged                      |

**Abandonment Detection:**

| Condition       | Threshold                                |
| --------------- | ---------------------------------------- |
| No publications | > 12 months                              |
| Owner inactive  | > 12 months                              |
| Unresponsive    | No reply to security contact for 30 days |
| Open CVEs       | Critical CVE unpatched for 90 days       |

**Severity:**

| Finding                                 | Action                         |
| --------------------------------------- | ------------------------------ |
| Package abandoned + critical CVE        | Flag for community transfer    |
| Package dormant > 12 months             | Display "unmaintained" warning |
| Ownership transfer without notification | BLOCK                          |

**Threats Addressed:** Abandoned packages (2.2.11)

---

### 3.9 Installation (IN-)

Installation controls govern client-side verification, user consent, and recovery capabilities.

| ID    | Control                    | Level | Enforcement | Threats Addressed                   |
| ----- | -------------------------- | ----- | ----------- | ----------------------------------- |
| IN-01 | Pre-Installation Checks    | L1    | Client      | Revoked/invalid bundles             |
| IN-02 | Post-Download Verification | L2    | Client      | Tampering in transit                |
| IN-03 | User Transparency          | L1    | Client      | Uninformed consent                  |
| IN-04 | Rollback Capability        | L2    | Client      | Failed updates, compromise recovery |

#### IN-01: Pre-Installation Checks

**Level:** L1 | **Enforcement:** Client

**Rationale:** Clients are the last line of defense before code executes.

**Requirements:**

- Clients MUST perform safety checks before installation
- Blocking checks MUST prevent installation
- Non-blocking checks MUST display warnings

**Checks by Level:**

| Check                      | L1  | L2  | L3  | L4  | Failure Action |
| -------------------------- | --- | --- | --- | --- | -------------- |
| Revocation feed query      | ✓   | ✓   | ✓   | ✓   | BLOCK          |
| Manifest schema validation | ✓   | ✓   | ✓   | ✓   | BLOCK          |
| Required fields present    | ✓   | ✓   | ✓   | ✓   | BLOCK          |
| Bundle digest verified     |     | ✓   | ✓   | ✓   | BLOCK          |
| Signature present          |     |     | ✓   | ✓   | BLOCK          |
| Signature valid            |     |     | ✓   | ✓   | BLOCK          |
| Attestation present        |     |     | ✓   | ✓   | BLOCK          |
| Attestation valid          |     |     | ✓   | ✓   | BLOCK          |

**Severity:**

| Finding                             | Action                                         |
| ----------------------------------- | ---------------------------------------------- |
| Any blocking check fails            | BLOCK installation                             |
| Revocation feed unavailable (L1-L2) | WARN, require confirmation                     |
| Revocation feed unavailable (L3+)   | BLOCK (unless explicitly configured fail-open) |

**Threats Addressed:** Installing revoked/compromised bundles

#### IN-02: Post-Download Verification

**Level:** L2 | **Enforcement:** Client

**Rationale:** Bundles may be tampered with during download. Post-download verification ensures integrity before extraction.

**Requirements:**

- Clients MUST verify bundle digest after download (RG-07)
- Clients MUST verify bundle completeness after extraction (AI-05)

**Verification Sequence:**

1. Download bundle archive
2. Verify bundle digest matches registry-provided digest (RG-07)
3. Extract to temporary location
4. Check for unexpected executables (AI-05)
5. Move to final installation location
6. Update client lockfile

**Severity:**

| Finding                  | Action       |
| ------------------------ | ------------ |
| Bundle digest mismatch   | BLOCK, retry |
| Unexpected executable    | BLOCK        |

**Threats Addressed:** Tampering in transit, registry poisoning (2.2.9)

#### IN-03: User Transparency

**Level:** L1 | **Enforcement:** Client

**Rationale:** Users must understand what they're installing before consenting.

**Requirements:**

- Clients MUST display package information before installation
- Users MUST explicitly consent to installation
- Critical findings MUST be prominently displayed

**Information Display:**

| Information              | Level | Display           |
| ------------------------ | ----- | ----------------- |
| Package name and version | L1+   | Always            |
| Publisher identity       | L1+   | Always            |
| MTF compliance level     | L1+   | Always            |
| Tools provided           | L1+   | Always            |
| Permissions requested    | L2+   | Always            |
| OAuth scopes             | L3+   | If present        |
| Risk indicators          | L2+   | If present        |
| Critical findings        | All   | Prominent warning |

**Consent Modes:**

| Mode              | Behavior                             |
| ----------------- | ------------------------------------ |
| Interactive       | Prompt for each installation         |
| Pre-approved list | Allow listed packages without prompt |
| CI/CD mode        | Fail if consent would be required    |

**Severity:**

| Finding                        | Action                            |
| ------------------------------ | --------------------------------- |
| User declines installation     | Abort                             |
| Interactive mode unavailable   | Abort unless pre-approved         |
| Critical finding + silent mode | BLOCK (require explicit override) |

**Threats Addressed:** Uninformed consent, social engineering

#### IN-04: Rollback Capability

**Level:** L2 | **Enforcement:** Client

**Rationale:** When an update introduces problems, users need to quickly restore the previous version.

**Requirements:**

- Clients MUST retain previous version after update
- Clients MUST provide rollback command
- Clients MUST handle compromise detection gracefully

**Version Retention:**

| Policy            | Default    |
| ----------------- | ---------- |
| Versions retained | 1 previous |
| Retention period  | 7 days     |

**Rollback Command:**

```bash
mpak rollback @acme/server         # Previous version
mpak rollback @acme/server@1.0.0   # Specific version
mpak rollback --list @acme/server  # List available
```

**Compromise Response:**

When a compromised package is detected:

1. Disable server immediately
2. Notify user with compromise details
3. Offer rollback if clean version available
4. Log incident for security review

**Severity:**

| Finding                       | Action                      |
| ----------------------------- | --------------------------- |
| Rollback target revoked       | BLOCK rollback              |
| No previous version available | WARN, offer uninstall       |
| Compromise detected           | Disable server, notify user |

**Threats Addressed:** Failed updates, compromise recovery, malicious updates (2.2.4)

---

### 3.10 Update Lifecycle (UP-)

Update lifecycle controls govern how packages evolve, including version management, breaking changes, and deprecation.

| ID    | Control                | Level | Enforcement       | Threats Addressed         |
| ----- | ---------------------- | ----- | ----------------- | ------------------------- |
| UP-01 | Update Notification    | L2    | Registry + Client | Missed security updates   |
| UP-02 | Breaking Change Policy | L2    | Registry          | Unexpected breakage       |
| UP-03 | Deprecation Process    | L2    | Registry          | Abandoned packages        |
| UP-04 | Version Monotonicity   | L2    | Registry          | Version confusion attacks |

#### UP-01: Update Notification

**Level:** L2 | **Enforcement:** Registry + Client

**Rationale:** Users must be informed of available updates, especially security fixes.

**Requirements:**

- Registries MUST provide update notification mechanism
- Clients MUST check for updates regularly
- Security updates MUST be distinguished from feature updates

**Update Types:**

| Type       | Description                       | Priority                 |
| ---------- | --------------------------------- | ------------------------ |
| `security` | Fixes vulnerability               | High (push notification) |
| `patch`    | Bug fixes                         | Medium                   |
| `minor`    | New features, backward compatible | Low                      |
| `major`    | Breaking changes                  | Informational            |

**Consent-Required Changes:**

Automatic updates MUST NOT proceed if:

| Change                         | Reason                      |
| ------------------------------ | --------------------------- |
| New permissions                | Expands attack surface      |
| Expanded OAuth scopes          | Increases credential access |
| New network access at init     | Exfiltration risk           |
| `subprocess` or `native` added | High-risk capability        |

**Severity:**

| Finding                            | Action                         |
| ---------------------------------- | ------------------------------ |
| Critical security update available | Prominent notification         |
| Update requires consent            | Block auto-update, prompt user |

**Threats Addressed:** Missed security patches

#### UP-02: Breaking Change Policy

**Level:** L2 | **Enforcement:** Registry

**Rationale:** Breaking changes without warning disrupt users. Semantic versioning provides a contract for predictable updates.

**Requirements:**

- Publishers MUST follow semantic versioning
- Breaking changes MUST increment major version
- Published versions MUST NOT be modified

**MCP-Specific Breaking Changes:**

| Change                          | Breaking? | Version Bump |
| ------------------------------- | --------- | ------------ |
| Tool removed                    | Yes       | Major        |
| Tool renamed                    | Yes       | Major        |
| Tool parameter removed          | Yes       | Major        |
| Tool parameter added (required) | Yes       | Major        |
| Tool parameter added (optional) | No        | Minor        |
| Permission scope expanded       | Yes       | Major        |
| OAuth scope added               | Yes       | Major        |

**Version Immutability:**

| Action                                  | Allowed |
| --------------------------------------- | ------- |
| Publish 1.0.0                           | ✓       |
| Publish 1.0.1                           | ✓       |
| Re-publish 1.0.0 with different content | ✗ BLOCK |

**Severity:**

| Finding                            | Action         |
| ---------------------------------- | -------------- |
| Breaking change in patch version   | WARN publisher |
| Digest mismatch on republish       | BLOCK          |

**Threats Addressed:** Unexpected breakage, version confusion

#### UP-03: Deprecation Process

**Level:** L2 | **Enforcement:** Registry

**Rationale:** Deprecated packages with no migration path leave users stranded.

**Requirements:**

- Deprecation MUST provide minimum notice period
- Deprecation MUST include migration guidance
- Deprecated packages MUST remain installable during notice period

**Deprecation Timeline:**

| Phase         | Timing  | Actions                                    |
| ------------- | ------- | ------------------------------------------ |
| Announce      | Day 0   | Publish deprecation notice                 |
| Notice period | 90 days | Package installable, warnings shown        |
| Soft removal  | Day 90  | Remove from search, direct install allowed |
| Hard removal  | Day 180 | Block new installs                         |

**Severity:**

| Finding                       | Action                      |
| ----------------------------- | --------------------------- |
| Installing deprecated package | WARN                        |
| Installing after soft removal | WARN (require confirmation) |
| Installing after hard removal | BLOCK                       |
| Unmaintained + open CVEs      | WARN prominently            |

**Threats Addressed:** Abandoned packages (2.2.11)

#### UP-04: Version Monotonicity

**Level:** L2 | **Enforcement:** Registry

**Rationale:** Non-monotonic version publishing enables attacks where old vulnerable content is published under version numbers that appear higher.

**Requirements:**

- Version numbers MUST be monotonically increasing per semver
- Registries MUST reject non-monotonic version publications
- Version history MUST be immutable

**Monotonicity Rule:**

```
V_new > V_existing (per semver ordering)
```

**Valid Sequences:**

```
1.0.0 → 1.0.1 → 1.1.0 → 2.0.0  ✓
1.0.0 → 1.1.0 → 1.0.1          ✗ (1.0.1 < 1.1.0)
```

**Severity:**

| Finding                      | Action            |
| ---------------------------- | ----------------- |
| Non-monotonic version        | BLOCK publication |
| Version already exists       | BLOCK (see UP-02) |
| Yanked version reuse attempt | BLOCK             |

**Threats Addressed:** Version confusion, malicious updates (2.2.4)

## 4. Manifest Specification

### 4.1 Relationship to mcpb

MTF **extends** the [mcpb manifest format](https://github.com/modelcontextprotocol/mcpb). Bundles MUST be valid mcpb manifests. MTF adds security metadata under the `_meta.org.mpaktrust` namespace, following mcpb's extension conventions.

**Extension namespace:** `_meta.org.mpaktrust`

MTF fields are placed under this namespace to:

- Avoid collision with future mcpb fields
- Clearly identify MTF-specific metadata
- Follow reverse domain notation conventions

**Validation is two-step:**

1. Validate manifest against [mcpb schema](https://github.com/modelcontextprotocol/mcpb) (ensures bundle can execute)
2. Validate `_meta['org.mpaktrust']` against MTF extension schema (ensures security metadata is correct)

### 4.2 mcpb Required Fields

These fields are defined by mcpb. MTF requires them at specified levels.

| Field              | Type   | MTF Requires | Description                           |
| ------------------ | ------ | ------------ | ------------------------------------- |
| `manifest_version` | string | L1           | mcpb schema version                   |
| `name`             | string | L1           | Package name (`@scope/name` for L2+)  |
| `version`          | string | L1           | Semantic version                      |
| `description`      | string | L1           | Human-readable description            |
| `author`           | object | L2           | Publisher identity (name, email, url) |
| `repository`       | object | L2           | Source repository (type, url)         |
| `tools`            | array  | L1           | Tool declarations                     |
| `server`           | object | L1           | Server execution config               |

### 4.3 MTF Extension Fields

These fields are defined by MTF and live under `_meta.org.mpaktrust`.

#### 4.3.1 Core Fields

| Field         | Type   | Required | Description                     |
| ------------- | ------ | -------- | ------------------------------- |
| `mtf_version` | string | L1       | MTF spec version (e.g., "0.1")  |
| `level`       | number | L2       | Declared compliance level (1-4) |
| `permissions` | object | L2       | System access requirements      |

#### 4.3.2 Permission Categories

```json
{
  "_meta": {
    "org.mpaktrust": {
      "permissions": {
        "filesystem": "none | read | write | full",
        "network": "none | outbound | inbound | full",
        "environment": "none | read | write",
        "subprocess": "none | restricted | full",
        "native": "none | required"
      }
    }
  }
}
```

| Category      | Values                                | Description           |
| ------------- | ------------------------------------- | --------------------- |
| `filesystem`  | `none`, `read`, `write`, `full`       | File system access    |
| `network`     | `none`, `outbound`, `inbound`, `full` | Network connections   |
| `environment` | `none`, `read`, `write`               | Environment variables |
| `subprocess`  | `none`, `restricted`, `full`          | Process spawning      |
| `native`      | `none`, `required`                    | Native code / FFI     |

#### 4.3.3 Credential Fields (L3+)

```json
{
  "_meta": {
    "org.mpaktrust": {
      "credentials": [
        {
          "provider": "google",
          "scopes": ["https://www.googleapis.com/auth/calendar.readonly"],
          "justification": "Read calendar events for scheduling",
          "token_handling": {
            "storage": "memory",
            "max_lifetime_seconds": 3600,
            "refresh": true
          }
        }
      ]
    }
  }
}
```

#### 4.3.4 Provenance Fields (L3+/L4)

```json
{
  "_meta": {
    "org.mpaktrust": {
      "source": {
        "commit": "a1b2c3d4e5f6...",
        "signed": true,
        "tag": "v1.0.0"
      },
      "build": {
        "builder": "https://github.com/slsa-framework/slsa-github-generator/...",
        "reproducible": true,
        "instructions": "https://github.com/org/repo/blob/main/BUILD.md"
      }
    }
  }
}
```

| Field                | Type    | Required    | Description                      |
| -------------------- | ------- | ----------- | -------------------------------- |
| `source.commit`      | string  | L4          | Full 40-character commit SHA     |
| `source.signed`      | boolean | Recommended | Whether commit is GPG/SSH signed |
| `source.tag`         | string  | Optional    | Associated release tag           |
| `build.builder`      | string  | L3          | Builder identity URI             |
| `build.reproducible` | boolean | L4          | Whether build is reproducible    |
| `build.instructions` | string  | Recommended | URL to build instructions        |

### 4.4 Example Manifests

#### L1 Basic

```json
{
  "manifest_version": "0.3",
  "name": "my-weather-server",
  "version": "0.1.0",
  "description": "Simple weather lookup",
  "server": {
    "type": "python",
    "entry_point": "server.py"
  },
  "mcp_config": {
    "command": "python",
    "args": ["-m", "weather.server"]
  },
  "tools": [
    {
      "name": "get_weather",
      "description": "Get current weather for a location"
    }
  ],
  "_meta": {
    "org.mpaktrust": {
      "mtf_version": "0.1"
    }
  }
}
```

#### L2 Standard

```json
{
  "manifest_version": "0.3",
  "name": "@acme/weather-server",
  "version": "1.0.0",
  "description": "Production weather service",
  "author": {
    "name": "Acme Corp",
    "email": "mcp@acme.com"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/acme/weather-server"
  },
  "server": {
    "type": "python",
    "entry_point": "server.py"
  },
  "mcp_config": {
    "command": "python",
    "args": ["-m", "weather.server"]
  },
  "tools": [
    {
      "name": "get_weather",
      "description": "Get current weather for a location"
    }
  ],
  "_meta": {
    "org.mpaktrust": {
      "mtf_version": "0.1",
      "level": 2,
      "permissions": {
        "filesystem": "none",
        "network": "outbound",
        "environment": "read",
        "subprocess": "none",
        "native": "none"
      }
    }
  }
}
```

#### L3 Verified

```json
{
  "manifest_version": "0.3",
  "name": "@acme/calendar-sync",
  "version": "2.0.0",
  "description": "Sync calendar events across services",
  "author": {
    "name": "Acme Corp",
    "email": "mcp@acme.com",
    "url": "https://acme.com"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/acme/calendar-sync"
  },
  "server": {
    "type": "python",
    "entry_point": "server.py"
  },
  "mcp_config": {
    "command": "python",
    "args": ["-m", "calendar_sync.server"]
  },
  "tools": [
    {
      "name": "sync_events",
      "description": "Sync events between Google and Outlook calendars"
    }
  ],
  "_meta": {
    "org.mpaktrust": {
      "mtf_version": "0.1",
      "level": 3,
      "permissions": {
        "filesystem": "none",
        "network": "outbound",
        "environment": "read",
        "subprocess": "none",
        "native": "none"
      },
      "credentials": [
        {
          "provider": "google",
          "scopes": ["https://www.googleapis.com/auth/calendar"],
          "justification": "Read and write calendar events for sync",
          "token_handling": {
            "storage": "memory",
            "max_lifetime_seconds": 3600,
            "refresh": true
          }
        }
      ],
      "signature": {
        "type": "sigstore",
        "bundle": ".sigstore/manifest.sig.json"
      }
    }
  }
}
```

### 4.5 Schema Location

**Normative Schemas:**

| Schema              | URL                                                     |
| ------------------- | ------------------------------------------------------- |
| MTF Extension       | `https://mpaktrust.org/schemas/mtf/v0.1/mtf-extension.json` |
| Verification Report | `https://mpaktrust.org/schemas/mtf/v0.1/report.json`        |

**External Schemas:**

| Schema          | Specification                                        |
| --------------- | ---------------------------------------------------- |
| VEX Statement   | [OpenVEX v0.2.0](https://github.com/openvex/spec)    |
| SLSA Provenance | [SLSA Provenance v1](https://slsa.dev/provenance/v1) |

## 5. Signing & Attestation

### 5.1 Signing Envelope

#### 5.1.1 Canonical Serialization

The signed payload MUST use RFC 8785 (JSON Canonicalization Scheme) to ensure deterministic serialization. Implementations MUST NOT sign pretty-printed or non-canonical JSON.

#### 5.1.2 Payload Structure

```json
{
  "mtf_version": "0.1",
  "payload_type": "bundle_signature",
  "subject": {
    "name": "@scope/package-name",
    "version": "1.0.0",
    "manifest_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sbom_sha256": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
  },
  "timestamp": "2026-02-06T12:00:00Z",
  "signer_identity": "https://github.com/username"
}
```

| Field                     | Required | Description                          |
| ------------------------- | -------- | ------------------------------------ |
| `mtf_version`             | MUST     | MTF specification version            |
| `payload_type`            | MUST     | Always `bundle_signature`            |
| `subject.name`            | MUST     | Package name from manifest           |
| `subject.version`         | MUST     | Package version from manifest        |
| `subject.manifest_sha256` | MUST     | SHA-256 hash of canonical manifest   |
| `subject.sbom_sha256`     | MUST     | SHA-256 hash of SBOM file            |
| `timestamp`               | MUST     | ISO 8601 signing timestamp           |
| `signer_identity`         | MUST     | OIDC identity URI or key fingerprint |

### 5.2 Signing Methods

#### 5.2.1 Sigstore Keyless (Preferred)

```bash
# Sign the manifest
cosign sign-blob --bundle manifest.sig.json manifest.json

# Verify
cosign verify-blob --bundle manifest.sig.json manifest.json
```

Sigstore binds signatures to OIDC identity (GitHub, Google, Microsoft) without long-lived key management.

**OIDC Providers:**

| Provider       | Issuer                                        | Subject Format                      |
| -------------- | --------------------------------------------- | ----------------------------------- |
| GitHub Actions | `https://token.actions.githubusercontent.com` | `repo:org/repo:ref:refs/heads/main` |
| GitLab CI      | `https://gitlab.com`                          | `project_path:org/repo`             |
| Google         | `https://accounts.google.com`                 | Email address                       |

#### 5.2.2 Long-Lived Keys

| Algorithm   | Key Size  | Status         |
| ----------- | --------- | -------------- |
| ECDSA P-256 | 256-bit   | Acceptable     |
| ECDSA P-384 | 384-bit   | Acceptable     |
| Ed25519     | 256-bit   | Acceptable     |
| RSA         | 4096+ bit | Acceptable     |
| RSA         | 2048 bit  | NOT acceptable |

#### 5.2.3 Signature File Locations

| File                      | Description                 |
| ------------------------- | --------------------------- |
| `manifest.sig`            | Primary detached signature  |
| `manifest.sig.json`       | Sigstore bundle (preferred) |
| `.sigstore/`              | Sigstore bundle directory   |
| `manifest.ci.sig`         | CI/builder signature        |
| `manifest.<identity>.sig` | Additional signer           |

### 5.3 SLSA Provenance Format

Build attestations MUST follow [SLSA Provenance v1](https://slsa.dev/provenance/v1):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "@scope/package-name",
      "digest": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/slsa-framework/slsa-github-generator/...",
      "externalParameters": {
        "workflow": {
          "ref": "refs/tags/v1.0.0",
          "repository": "https://github.com/org/repo",
          "path": ".github/workflows/release.yml"
        }
      },
      "resolvedDependencies": [
        {
          "uri": "git+https://github.com/org/repo@refs/tags/v1.0.0",
          "digest": {
            "gitCommit": "a1b2c3d4e5f6..."
          }
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.0.0"
      },
      "metadata": {
        "invocationId": "https://github.com/org/repo/actions/runs/12345"
      }
    }
  }
}
```

**Attestation File Locations:**

| File                    | Format             |
| ----------------------- | ------------------ |
| `attestation.json`      | SLSA Provenance v1 |
| `.slsa/provenance.json` | SLSA Provenance v1 |
| `*.intoto.jsonl`        | In-toto bundle     |

### 5.4 VEX Statement Format

VEX (Vulnerability Exploitability eXchange) statements allow publishers to document non-applicability of vulnerabilities.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/2026-001",
  "author": "publisher@example.com",
  "timestamp": "2026-02-06T12:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "CVE-2026-1234"
      },
      "products": [
        {
          "@id": "pkg:pypi/mypackage@1.0.0"
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "The vulnerable function is not called by this package"
    }
  ]
}
```

**VEX Status Values:**

| Status                | Effect                | Justification Required |
| --------------------- | --------------------- | ---------------------- |
| `not_affected`        | Skip vulnerability    | Yes                    |
| `affected`            | Vulnerability applies | No                     |
| `fixed`               | Fixed in this version | No                     |
| `under_investigation` | Still analyzing       | No                     |

**Justification Values:**

| Justification                                       | Description                         |
| --------------------------------------------------- | ----------------------------------- |
| `component_not_present`                             | Vulnerable component not in package |
| `vulnerable_code_not_present`                       | Vulnerable code path not included   |
| `vulnerable_code_not_in_execute_path`               | Code exists but never executes      |
| `vulnerable_code_cannot_be_controlled_by_adversary` | No attack vector                    |
| `inline_mitigations_already_exist`                  | Mitigated by other controls         |

**VEX File Locations:**

| File          | Description            |
| ------------- | ---------------------- |
| `vex.json`    | Single VEX document    |
| `.vex/*.json` | Multiple VEX documents |

VEX documents MUST be signed using the same mechanism as bundle signatures.

### 5.5 Verification Report Format

Scanners and registries produce verification reports documenting control compliance:

```json
{
  "$schema": "https://mpaktrust.org/schemas/mtf/v0.1/report.json",
  "package": "@acme/server",
  "version": "1.0.0",
  "verified_at": "2026-02-06T12:00:00Z",
  "verifier": {
    "name": "mpak-scanner",
    "version": "1.0.0"
  },
  "level_claimed": 2,
  "level_verified": 2,
  "controls": [
    {
      "id": "AI-01",
      "name": "Manifest Validation",
      "status": "pass",
      "details": null
    },
    {
      "id": "SC-02",
      "name": "Vulnerability Scanning",
      "status": "pass",
      "details": {
        "vulnerabilities_found": 2,
        "vulnerabilities_blocking": 0,
        "vex_applied": 1
      }
    },
    {
      "id": "CQ-03",
      "name": "Static Analysis",
      "status": "warn",
      "details": {
        "findings": [
          {
            "severity": "MEDIUM",
            "file": "src/utils.py",
            "line": 42,
            "message": "Possible SQL injection"
          }
        ]
      }
    }
  ],
  "signature": "..."
}
```

| Status  | Meaning                          |
| ------- | -------------------------------- |
| `pass`  | Control satisfied                |
| `fail`  | Control not satisfied (blocking) |
| `warn`  | Non-blocking finding             |
| `skip`  | Control not applicable           |
| `error` | Verification could not complete  |

## 6. Implementation Guide

### 6.1 Phased Adoption

The MCP ecosystem is early-stage. This roadmap prioritizes controls by impact and implementability.

#### Phase 1: Foundation

Deploy core security controls that provide immediate value with minimal friction.

| Control                   | Rationale                       |
| ------------------------- | ------------------------------- |
| AI-01 Manifest validation | Baseline for all other controls |
| SC-01 SBOM generation     | Enables vulnerability tracking  |
| CQ-01 Secret scanning     | Immediate exploitability        |
| CQ-02 Malware patterns    | Baseline protection             |
| CD-01 Tool declaration    | Capability transparency         |

**Outcome:** L1 compliance achievable.

#### Phase 2: Supply Chain

Add supply chain verification and identity controls.

| Control                      | Rationale                       |
| ---------------------------- | ------------------------------- |
| SC-02 CVE scan with EPSS/KEV | Real-world exploitation context |
| SC-03 Dependency pinning     | Reproducibility baseline        |
| PR-02 Author identity        | Accountability                  |
| RG-07 Bundle digest          | Tampering detection             |
| CD-02 Permission correlation | Catches misrepresentation       |
| CD-03 Description safety     | MCP-specific threat             |

**Outcome:** L2 compliance achievable.

#### Phase 3: Verified Distribution

Implement cryptographic verification and registry governance.

| Control                       | Rationale                           |
| ----------------------------- | ----------------------------------- |
| AI-03 Signatures              | Publisher authenticity              |
| PR-03 Build attestation       | Provenance chain                    |
| RG-01 Namespace governance    | Prevent squatting                   |
| RG-05 Revocation              | Kill switch for compromised bundles |
| CD-04/CD-05 Credential scopes | Blast radius control                |

**Outcome:** L3 compliance achievable.

#### Phase 4: Full Assurance

Complete the assurance model with behavioral verification.

| Control                        | Rationale                   |
| ------------------------------ | --------------------------- |
| CQ-06 Behavioral analysis      | Defense in depth            |
| AI-04 Reproducible builds      | Independent verification    |
| RG-03/RG-04 Registry integrity | Ecosystem-wide trust        |
| AI-05 Bundle completeness      | Phantom component detection |

**Outcome:** L4 compliance achievable.

### 6.2 Minimum Viable Security

The smallest set of controls that meaningfully reduce supply chain risk:

| Priority | Control                   | Rationale                   |
| -------- | ------------------------- | --------------------------- |
| 1        | CQ-01 Secret Detection    | Immediate exploitability    |
| 2        | CQ-02 Malware Patterns    | Baseline protection         |
| 3        | AI-01 Manifest Validation | Foundation for all controls |
| 4        | CD-01 Tool Declaration    | Capability visibility       |
| 5        | SC-01 SBOM Generation     | Dependency awareness        |
| 6        | CD-03 Description Safety  | MCP-specific threat         |
| 7        | PR-02 Author Identity     | Accountability              |

These controls represent the minimum bar for publishing MCP bundles responsibly.

### 6.3 Tooling Landscape

Implementations can leverage existing open-source tooling for many checks:

| Control Category          | Tools                      | Notes                               |
| ------------------------- | -------------------------- | ----------------------------------- |
| SBOM generation (SC-01)   | Syft, Trivy, CycloneDX CLI | Mature, widely adopted              |
| CVE scanning (SC-02)      | Grype, Trivy + EPSS API    | Requires EPSS/KEV integration       |
| Secret detection (CQ-01)  | TruffleHog, Gitleaks       | Use verified mode                   |
| Malware patterns (CQ-02)  | GuardDog, Semgrep          | Python-focused; custom rules needed |
| Static analysis (CQ-03)   | Bandit, ESLint, gosec      | Language-specific                   |
| Signing (AI-03)           | Cosign (Sigstore)          | Keyless or key-based                |
| Attestation (PR-03)       | slsa-github-generator      | GitHub Actions                      |
| Repository health (PR-05) | OpenSSF Scorecard          | GitHub/GitLab supported             |

**MCP-Specific Controls (Require Custom Implementation):**

| Control                   | Required Capability                        |
| ------------------------- | ------------------------------------------ |
| CD-03 Description safety  | Pattern-based tool description analysis    |
| CQ-06 Name squatting      | Name similarity + publisher trust signals  |
| CQ-06 Behavioral analysis | MCP server sandbox with syscall monitoring |

### 6.4 CI/CD Integration

#### GitHub Actions: L2 Compliance

```yaml
name: MTF Verification

on:
  push:
    tags: ["v*"]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Generate SBOM (SC-01)
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json

      # Scan for secrets (CQ-01)
      - name: Secret Detection
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified

      # Scan for vulnerabilities (SC-02)
      - name: Vulnerability Scan
        uses: anchore/scan-action@v3
        with:
          sbom: sbom.json
          fail-build: true
          severity-cutoff: high

      # Static analysis (CQ-03)
      - name: Static Analysis (Python)
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json
          # Fail on high severity
          bandit -r src/ -ll

      # Validate manifest (AI-01)
      - name: Validate Manifest
        run: |
          # Check manifest exists and is valid JSON
          jq . manifest.json > /dev/null
          # Check required fields
          jq -e '.name and .version and .tools' manifest.json

```

#### GitHub Actions: L3 Compliance (with Signing)

```yaml
name: MTF L3 Release

on:
  push:
    tags: ["v*"]

permissions:
  id-token: write
  contents: read

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ... L2 checks from above ...

      # Install Cosign
      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      # Sign manifest (AI-03)
      - name: Sign Manifest
        run: |
          cosign sign-blob \
            --bundle manifest.sig.json \
            --yes \
            manifest.json

      # Generate SLSA provenance (PR-03)
      - uses: slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@v1
        with:
          # ... builder config ...
```

### 6.5 Adoption Incentives

| Incentive        | Implementation                                      |
| ---------------- | --------------------------------------------------- |
| Visibility       | Higher compliance levels appear first in search     |
| Trust badges     | Display compliance level badges on package pages    |
| Automation       | GitHub Action that achieves L2 in one workflow      |
| Templates        | Starter projects with L2 compliance built-in        |
| Warnings         | Unverified packages show security warnings          |
| Enterprise gates | Organizations can require minimum levels via policy |

### 6.6 Scanner Implementation Notes

#### Control Enforcement Order

Scanners SHOULD evaluate controls in dependency order:

1. **AI-01** Manifest Validation (required for all other checks)
2. **SC-01** SBOM Generation (required for SC-02)
3. **CQ-01, CQ-02** Secret/Malware (immediate threats)
4. **CD-01** Tool Declaration (required for CD-02, CD-03)
5. **Remaining controls** in any order

#### Failure Modes

| Failure Type                     | Behavior                                   |
| -------------------------------- | ------------------------------------------ |
| Blocking control fails           | Stop verification, report failure          |
| Warning control fails            | Continue, include in report                |
| Control errors (tool crash)      | Report as `error`, don't fail verification |
| Control skipped (not applicable) | Report as `skip`                           |

#### Performance Considerations

| Operation              | Typical Duration | Caching                |
| ---------------------- | ---------------- | ---------------------- |
| SBOM generation        | 5-30 seconds     | Cache by lockfile hash |
| CVE scan               | 2-10 seconds     | Cache by SBOM hash     |
| Secret scan            | 5-60 seconds     | No caching             |
| Static analysis        | 10-120 seconds   | Cache by source hash   |
| Signature verification | < 1 second       | Cache by signature     |

## 7. Specification Roadmap

### 7.1 Version Progression

| Version  | Focus                 | Key Additions                                                |
| -------- | --------------------- | ------------------------------------------------------------ |
| **v0.1** | Supply chain security | Signing, attestation, SBOM, CVE scanning, pattern detection  |
| **v0.2** | Runtime isolation     | Sandbox spec, behavioral verification, credential monitoring |
| **v0.3** | Protocol security     | Origin tagging, capability attestation, output sanitization  |

### 7.2 Why Phased?

MCP-specific threats require both supply chain and runtime controls. v0.1 focuses on supply chain because:

1. **Tooling exists.** SLSA, Sigstore, SBOM generators, and vulnerability scanners are mature.
2. **Foundation first.** Runtime controls need signed manifests and declared capabilities.
3. **Adoption enables enforcement.** Behavioral analysis requires registry infrastructure.

## Appendix A: Control Quick Reference

### A.1 Master Control Index

| ID        | Control                      | Level | Enforcement     | Section |
| --------- | ---------------------------- | ----- | --------------- | ------- |
| **AI-01** | Manifest Validation          | L1    | Scanner         | 3.2     |
| **AI-02** | *(Reserved)*                 | —     | —               | —       |
| **AI-03** | Bundle Signing               | L3    | Scanner         | 3.2     |
| **AI-04** | Reproducible Builds          | L4    | Scanner         | 3.2     |
| **AI-05** | Bundle Completeness          | L2    | Client          | 3.2     |
| **SC-01** | SBOM Generation              | L1    | Scanner         | 3.3     |
| **SC-02** | Vulnerability Scanning       | L2    | Scanner         | 3.3     |
| **SC-03** | Dependency Pinning           | L2    | Scanner         | 3.3     |
| **SC-04** | Lockfile Integrity           | L2    | Client          | 3.3     |
| **SC-05** | Trusted Sources              | L3    | Scanner         | 3.3     |
| **CQ-01** | Secret Detection             | L1    | Scanner         | 3.4     |
| **CQ-02** | Malware Patterns             | L1    | Scanner         | 3.4     |
| **CQ-03** | Static Analysis              | L2    | Scanner         | 3.4     |
| **CQ-04** | Input Validation             | L3    | Scanner         | 3.4     |
| **CQ-05** | Safe Execution Patterns      | L3    | Scanner         | 3.4     |
| **CQ-06** | Behavioral Analysis          | L4    | Registry        | 3.4     |
| **CD-01** | Tool Declaration             | L1    | Scanner         | 3.5     |
| **CD-02** | Permission Correlation       | L2    | Scanner         | 3.5     |
| **CD-03** | Description Safety           | L2    | Scanner         | 3.5     |
| **CD-04** | Credential Scope Declaration | L3    | Scanner         | 3.5     |
| **CD-05** | Token Lifetime Limits        | L3    | Scanner         | 3.5     |
| **PR-01** | Source Repository            | L2    | Scanner         | 3.6     |
| **PR-02** | Author Identity              | L2    | Registry        | 3.6     |
| **PR-03** | Build Attestation            | L3    | Scanner         | 3.6     |
| **PR-04** | Commit Linkage               | L4    | Scanner         | 3.6     |
| **PR-05** | Repository Health            | L3    | Scanner         | 3.6     |
| **RG-01** | Namespace Governance         | L2    | Registry        | 3.7     |
| **RG-02** | Name Pattern Review          | L2    | Registry        | 3.7     |
| **RG-03** | Index Integrity              | L3    | Registry        | 3.7     |
| **RG-04** | Freshness Guarantees         | L3    | Registry        | 3.7     |
| **RG-05** | Revocation Feed              | L2    | Registry        | 3.7     |
| **RG-06** | Transparency Log             | L3    | Registry        | 3.7     |
| **RG-07** | Bundle Digest                | L2    | Registry        | 3.7     |
| **PK-01** | Identity Tiers               | L2    | Registry        | 3.8     |
| **PK-02** | Key Rotation                 | L3    | Registry        | 3.8     |
| **PK-03** | Compromise Recovery          | L3    | Registry        | 3.8     |
| **PK-04** | Account Succession           | L3    | Registry        | 3.8     |
| **IN-01** | Pre-Installation Checks      | L1    | Client          | 3.9     |
| **IN-02** | Post-Download Verification   | L2    | Client          | 3.9     |
| **IN-03** | User Transparency            | L1    | Client          | 3.9     |
| **IN-04** | Rollback Capability          | L2    | Client          | 3.9     |
| **UP-01** | Update Notification          | L2    | Registry/Client | 3.10    |
| **UP-02** | Breaking Change Policy       | L2    | Registry        | 3.10    |
| **UP-03** | Deprecation Process          | L2    | Registry        | 3.10    |
| **UP-04** | Version Monotonicity         | L2    | Registry        | 3.10    |

**Total: 41 controls**

### A.2 Controls by Enforcement Point

| Enforcement | Count | Controls                                                                                                                                            |
| ----------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scanner     | 22    | AI-01, AI-03, AI-04, SC-01, SC-02, SC-03, SC-05, CQ-01, CQ-02, CQ-03, CQ-04, CQ-05, CD-01, CD-02, CD-03, CD-04, CD-05, PR-01, PR-03, PR-04, PR-05 |
| Registry    | 15    | CQ-06, PR-02, RG-01, RG-02, RG-03, RG-04, RG-05, RG-06, RG-07, PK-01, PK-02, PK-03, PK-04, UP-02, UP-03, UP-04                                    |
| Client      | 7     | AI-05, SC-04, IN-01, IN-02, IN-03, IN-04, UP-01                                                                                                     |

## Appendix B: Controls by Compliance Level

### B.1 L1 Basic (7 controls)

| ID    | Control                 | Domain                 |
| ----- | ----------------------- | ---------------------- |
| AI-01 | Manifest Validation     | Artifact Integrity     |
| SC-01 | SBOM Generation         | Supply Chain           |
| CQ-01 | Secret Detection        | Code Quality           |
| CQ-02 | Malware Patterns        | Code Quality           |
| CD-01 | Tool Declaration        | Capability Declaration |
| IN-01 | Pre-Installation Checks | Installation           |
| IN-03 | User Transparency       | Installation           |

### B.2 L2 Standard (+19 = 26 controls)

Includes all L1 controls, plus:

| ID    | Control                    | Domain                 |
| ----- | -------------------------- | ---------------------- |
| AI-05 | Bundle Completeness        | Artifact Integrity     |
| SC-02 | Vulnerability Scanning     | Supply Chain           |
| SC-03 | Dependency Pinning         | Supply Chain           |
| SC-04 | Lockfile Integrity         | Supply Chain           |
| CQ-03 | Static Analysis            | Code Quality           |
| CD-02 | Permission Correlation     | Capability Declaration |
| CD-03 | Description Safety         | Capability Declaration |
| PR-01 | Source Repository          | Provenance             |
| PR-02 | Author Identity            | Provenance             |
| RG-01 | Namespace Governance       | Registry Operations    |
| RG-02 | Name Pattern Review        | Registry Operations    |
| RG-05 | Revocation Feed            | Registry Operations    |
| RG-07 | Bundle Digest              | Registry Operations    |
| PK-01 | Identity Tiers             | Publisher Identity     |
| IN-02 | Post-Download Verification | Installation           |
| IN-04 | Rollback Capability        | Installation           |
| UP-01 | Update Notification        | Update Lifecycle       |
| UP-02 | Breaking Change Policy     | Update Lifecycle       |
| UP-03 | Deprecation Process        | Update Lifecycle       |
| UP-04 | Version Monotonicity       | Update Lifecycle       |

### B.3 L3 Verified (+12 = 38 controls)

Includes all L1 + L2 controls, plus:

| ID    | Control                      | Domain                 |
| ----- | ---------------------------- | ---------------------- |
| AI-03 | Bundle Signing               | Artifact Integrity     |
| SC-05 | Trusted Sources              | Supply Chain           |
| CQ-04 | Input Validation             | Code Quality           |
| CQ-05 | Safe Execution Patterns      | Code Quality           |
| CD-04 | Credential Scope Declaration | Capability Declaration |
| CD-05 | Token Lifetime Limits        | Capability Declaration |
| PR-03 | Build Attestation            | Provenance             |
| PR-05 | Repository Health            | Provenance             |
| RG-03 | Index Integrity              | Registry Operations    |
| RG-04 | Freshness Guarantees         | Registry Operations    |
| RG-06 | Transparency Log             | Registry Operations    |
| PK-02 | Key Rotation                 | Publisher Identity     |
| PK-03 | Compromise Recovery          | Publisher Identity     |
| PK-04 | Account Succession           | Publisher Identity     |

### B.4 L4 Attested (+3 = 41 controls)

Includes all L1 + L2 + L3 controls, plus:

| ID    | Control             | Domain             |
| ----- | ------------------- | ------------------ |
| AI-04 | Reproducible Builds | Artifact Integrity |
| CQ-06 | Behavioral Analysis | Code Quality       |
| PR-04 | Commit Linkage      | Provenance         |

### B.5 Level Comparison

| Aspect          | L1       | L2        | L3         | L4                  |
| --------------- | -------- | --------- | ---------- | ------------------- |
| **Controls**    | 7        | 26        | 38         | 41                  |
| **Target**      | Personal | Published | Production | Critical            |
| **Identity**    | None     | Email     | OIDC       | OIDC                |
| **Signing**     | None     | None      | Required   | Required            |
| **Attestation** | None     | None      | SLSA       | SLSA + reproducible |
| **CVE Scan**    | None     | EPSS/KEV  | EPSS/KEV   | EPSS/KEV            |
| **Behavioral**  | None     | None      | None       | Sandbox             |

## Appendix C: Open Questions

Issues surfaced during specification development that require resolution in future versions.

### C.1 Detection Limitations

**Tool description poisoning (CD-03):** Pattern matching catches obvious attacks but sophisticated paraphrased instructions evade detection. No production-ready semantic analysis exists. This control provides baseline protection, not comprehensive defense.

**Name squatting (CQ-06):** Detection combines name similarity analysis with publisher trust signals. Accuracy depends on threshold tuning for similarity metrics.

### C.2 Behavioral Analysis Implementation

CQ-06 specifies what behavioral analysis MUST verify. Implementation approaches include:

- **OpenSSF Package Analysis:** Foundation for sandbox infrastructure
- **Container sandboxes:** Docker/Podman with seccomp profiles
- **eBPF tracing:** Low-overhead syscall monitoring
- **Firecracker/gVisor:** Lightweight VM isolation

Registries implementing CQ-06 SHOULD publish their implementation details.

### C.3 Container Image Verification

Section 4 specifies container handling at a high level. Open questions:

- How do OCI attestations integrate with MTF attestation format?
- Should container layers be individually verified or only final image?
- How do multi-arch images affect reproducibility requirements?

### C.4 Transitive Dependency Provenance

MTF requires SBOM but doesn't mandate provenance attestation for dependencies. For L4, should all transitive dependencies also require provenance?

**Current treatment:** RECOMMENDED for L4, not REQUIRED. Ecosystem maturity is insufficient.

### C.5 Key Escrow vs. Keyless

Sigstore keyless signing is REQUIRED for L3+. However:

- Some enterprises require key escrow for compliance
- Air-gapped environments cannot use OIDC

**Open question:** Should MTF define an alternative key-escrow path?

### C.6 Breaking Change Detection

UP-02 requires semver but doesn't define breaking change detection. For MCP:

- Is tool removal a breaking change? (Yes, per current spec)
- Is permission scope reduction breaking? (No)
- Is OAuth scope reduction breaking? (No)

### C.7 Cross-Registry Federation

This spec assumes a single authoritative registry. If multiple registries exist:

- How is namespace governance coordinated?
- How are revocations propagated?
- Which registry's compliance level is authoritative?

**Deferred:** Wait for ecosystem to determine if federation is needed.

### C.8 Multi-Signature / Threshold Signing

For L4 critical infrastructure, single-signer is a single point of compromise.

**Open question:** Should L4 require threshold signatures (e.g., 2-of-3 keys)?

**Current treatment:** Not addressed. PR-02 requires multi-owner but not multi-signature.

### C.9 Signature Expiry

Signatures currently have no expiration. A bundle signed in 2024 remains "verified" indefinitely.

**Open question:** Should signatures have maximum validity periods? Should clients warn on old signatures?

**Current treatment:** RG-05 revocation handles known compromises; time-based trust decay not addressed.

## Appendix D: Runtime Security Roadmap

This appendix describes controls planned for future MTF versions. These are **informative, not normative** for v0.1.

### D.1 Runtime Isolation Controls (v0.2)

Controls for verifying bundle behavior matches declared capabilities at execution time.

| Control | Description                                        | Threat Addressed            |
| ------- | -------------------------------------------------- | --------------------------- |
| RT-01   | Sandbox execution requirements                     | Initialization exfiltration |
| RT-02   | Tool description integrity (hash per invocation)   | Rug pull attacks            |
| RT-03   | Full-schema validation (name, parameters, outputs) | Schema poisoning            |
| RT-04   | Credential access monitoring                       | Token abuse                 |
| RT-05   | Network egress policy enforcement                  | Data exfiltration           |
| RT-06   | Filesystem access boundaries                       | Unauthorized file access    |

**Implementation notes:**

- Requires registry-operated or client-side sandbox infrastructure
- Technologies: containers with seccomp, gVisor, Firecracker, eBPF

### D.2 Protocol Security Controls (v0.3)

Controls requiring changes to the MCP protocol specification.

| Control | Description                                      | Threat Addressed           |
| ------- | ------------------------------------------------ | -------------------------- |
| PT-01   | Origin tagging (server vs. user content markers) | Prompt injection confusion |
| PT-02   | Capability attestation in protocol handshake     | Manifest/behavior mismatch |
| PT-03   | Output sanitization requirements                 | Response poisoning         |
| PT-04   | Tool invocation audit trail                      | Forensics                  |

**Dependencies:**

- Requires MCP protocol version changes
- Coordination with MCP specification maintainers needed

### D.3 Control Numbering

| Prefix                                      | Category          | Version |
| ------------------------------------------- | ----------------- | ------- |
| AI-, SC-, CQ-, CD-, PR-, RG-, PK-, IN-, UP- | Supply chain      | v0.1    |
| RT-                                         | Runtime isolation | v0.2    |
| PT-                                         | Protocol security | v0.3    |

### D.4 Feedback Requested

Input is specifically requested on:

1. **Sandbox feasibility:** What isolation technologies are practical for MCP server execution?
2. **Protocol changes:** What MCP protocol extensions would enable PT- controls?
3. **Client vs. registry enforcement:** Which runtime controls should clients enforce locally?
4. **Performance impact:** What latency is acceptable for runtime verification?

## License

This specification is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).

Copyright 2026 NimbleBrain, Inc.

Full license: https://creativecommons.org/licenses/by/4.0/
