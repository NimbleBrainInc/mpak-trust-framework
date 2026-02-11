# mpak Trust Framework (MTF)

Security standard for MCP server bundles.

## Structure

- `MTF-0.1.md` - The specification (source of truth)
- `website/` - Astro site for mpaktrust.org

## Development Workflow

**IMPORTANT:** After editing `MTF-0.1.md`, always sync before committing:

```bash
cd website && npm run sync-spec
```

This copies the spec to `website/src/spec/` for rendering. The file is gitignored there to maintain single source of truth.

## Website Commands

```bash
cd website
npm run dev      # Start dev server (auto-syncs spec)
npm run build    # Build for production
npm run preview  # Preview production build
```

## Schemas

JSON schemas live in `schemas/`, synced to `website/public/schemas/{spec}/{version}/`:

| File | Spec | Published URL |
|------|------|---------------|
| `mcpb-manifest-v0.4.schema.json` | MCPB | `https://mpaktrust.org/schemas/mcpb/v0.4/manifest.json` |
| `mtf-extension.schema.json` | MTF | `https://mpaktrust.org/schemas/mtf/v0.1/mtf-extension.json` |
| `report.schema.json` | MTF | `https://mpaktrust.org/schemas/mtf/v0.1/report.json` |

VEX statements use [OpenVEX](https://github.com/openvex/spec), not a custom schema.

Published at: https://mpaktrust.org/schemas/
