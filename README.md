# GuardSpine CodeGuard

**AI-aware code governance with cryptographically verifiable evidence bundles**

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GuardSpine%20CodeGuard-blue?logo=github)](https://github.com/marketplace/actions/guardspine-codeguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## The Problem

GitHub shows *that* someone clicked "Approve."
GuardSpine proves *what* they reviewed.

When an auditor asks "How did this payment logic change get approved?", GitHub gives you a green checkmark. GuardSpine gives you:
- The exact diff they saw
- The risk tier at approval time
- Cryptographic proof nothing changed after review
- A hash-chained evidence bundle you can verify independently

## Install (1 minute)

**1. Add one secret** (pick any AI provider, or skip for rules-only mode):

| Provider | Secret name | Notes |
|----------|-------------|-------|
| OpenRouter | `OPENROUTER_API_KEY` | Recommended - single key, 100+ models |
| Anthropic | `ANTHROPIC_API_KEY` | Direct Claude access |
| OpenAI | `OPENAI_API_KEY` | Direct GPT access |
| Ollama | *(none needed)* | Self-hosted, air-gapped |

`GITHUB_TOKEN` is provided automatically by GitHub.

**2. Create `.github/workflows/codeguard.yml`:**

```yaml
name: CodeGuard
on: [pull_request]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DNYoussef/codeguard-action@v1
        id: guard
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}  # optional
          risk_threshold: L3          # L0-L4, default L3
          # rubric: soc2              # or: hipaa, pci-dss, default
          # fail_on_high_risk: false  # true = exit 1 on L3+, false = warn only
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: evidence-bundle
          path: ${{ steps.guard.outputs.bundle_path }}
```

**3. Open a PR.** You'll see a Diff Postcard comment with risk tier + findings, and the evidence bundle in workflow artifacts.

**Verify a bundle locally** (optional):
```bash
pip install guardspine-verify && guardspine-verify .guardspine/bundles/*.json
```

> **Troubleshooting**: Missing artifact? Ensure `bundle_dir` matches upload path. Hard fail on L4? Set `fail_on_high_risk: false` (default). No AI review? Provide at least one API key and set `ai_review: true` (default).

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GUARDSPINE CODEGUARD FLOW                           │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐
  │ PR Open  │
  │ /Update  │
  └────┬─────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                           1. DIFF ANALYSIS                                │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  • Parse unified diff (unidiff)                                     │ │
│  │  • Extract file changes, hunks, line-level modifications            │ │
│  │  • Detect 8 sensitive zones:                                        │ │
│  │    [auth] [payment] [crypto] [database] [security] [pii] [config]   │ │
│  │    [infra]                                                          │ │
│  │  • Generate SHA-256 diff hash for integrity                         │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    2. TIER-BASED MULTI-MODEL AI REVIEW                   │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Models scale with risk tier (not fallback - actual multi-review):  │ │
│  │                                                                     │ │
│  │   L0 (Trivial)  → 0 models  (rules-based only, no AI)              │ │
│  │   L1 (Low)      → 1 model   (single model review)                  │ │
│  │   L2 (Medium)   → 2 models  + rubric scoring                       │ │
│  │   L3 (High)     → 3 models  + rubric scoring                       │ │
│  │   L4 (Critical) → 3 models  + rubric scoring + human approval      │ │
│  │                                                                     │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                             │ │
│  │  │ Model 1 │  │ Model 2 │  │ Model 3 │  ← Run in PARALLEL          │ │
│  │  │ Claude  │  │  GPT    │  │ Gemini  │                             │ │
│  │  └────┬────┘  └────┬────┘  └────┬────┘                             │ │
│  │       │            │            │                                   │ │
│  │       └────────────┼────────────┘                                   │ │
│  │                    ▼                                                │ │
│  │            ┌──────────────┐                                         │ │
│  │            │  CONSENSUS   │  Majority vote + rubric aggregation    │ │
│  │            │  CALCULATOR  │  Agreement score + dissent tracking    │ │
│  │            └──────────────┘                                         │ │
│  │                                                                     │ │
│  │  Flexible model selection:                                          │ │
│  │   • All 3 from Ollama (air-gapped)                                 │ │
│  │   • All 3 from OpenRouter (100+ models)                            │ │
│  │   • Mix of direct APIs (Claude + GPT + Gemini)                     │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        3. RISK CLASSIFICATION                             │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Three scoring dimensions → Final risk tier:                        │ │
│  │                                                                     │ │
│  │   File Patterns ──────┐                                             │ │
│  │   (auth/payment/pii)  │                                             │ │
│  │                       ├──→ max(scores) ──→ ┌────────────────────┐   │ │
│  │   Sensitive Zones ────┤                    │   L0 │ Trivial     │   │ │
│  │   (8 zone types)      │                    │   L1 │ Low         │   │ │
│  │                       │                    │   L2 │ Medium      │   │ │
│  │   Change Size ────────┘                    │   L3 │ High    ⚠️  │   │ │
│  │   (lines added/removed)                    │   L4 │ Critical ⛔ │   │ │
│  │                                            └────────────────────┘   │ │
│  │                                                                     │ │
│  │  Rubric boost: SOC2/HIPAA/PCI-DSS rules can escalate tier          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
       │
       ├──────────────────────────────────────┐
       ▼                                      ▼
┌────────────────────┐              ┌────────────────────┐
│ L0-L2: Auto-pass   │              │ L3-L4: Block merge │
│ ✓ PR check passes  │              │ ⚠ Requires review  │
│ ✓ Comment posted   │              │ ⛔ Human approval  │
└────────────────────┘              └────────────────────┘
       │                                      │
       └──────────────────┬───────────────────┘
                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      4. EVIDENCE BUNDLE GENERATION                        │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Hash-chained event sequence (tamper-evident):                      │ │
│  │                                                                     │ │
│  │   Event 1           Event 2            Event 3          Event 4     │ │
│  │  ┌─────────┐       ┌─────────┐        ┌─────────┐      ┌─────────┐  │ │
│  │  │   PR    │──H1──▶│Analysis │──H2───▶│  Risk   │─H3──▶│Approval │  │ │
│  │  │Submitted│       │Complete │        │Classify │      │(if L3+) │  │ │
│  │  └─────────┘       └─────────┘        └─────────┘      └─────────┘  │ │
│  │       │                                                     │       │ │
│  │       └───────────────── Final Hash ────────────────────────┘       │ │
│  │                                                                     │ │
│  │  Bundle includes: diff snapshot, risk drivers, findings, rationale │ │
│  │  Supports: Ed25519, RSA, ECDSA, or HMAC-SHA256 signatures          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                           5. OUTPUT ARTIFACTS                             │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐  │
│  │  Diff Postcard │  │ Evidence Bundle│  │     SARIF Export           │  │
│  │  (PR Comment)  │  │  (JSON file)   │  │  (GitHub Security Tab)     │  │
│  │                │  │                │  │                            │  │
│  │ • Risk tier    │  │ • Hash chain   │  │ • Findings as alerts       │  │
│  │ • Top drivers  │  │ • Event log    │  │ • File locations           │  │
│  │ • Findings     │  │ • Signatures   │  │ • Severity mapping         │  │
│  │ • AI summary   │  │ • Snapshot     │  │                            │  │
│  └────────────────┘  └────────────────┘  └────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### Tier-Based Multi-Model Review

CodeGuard uses **escalating AI review** - more models review higher-risk changes:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     TIER-BASED MODEL ESCALATION                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   L0 (Trivial)   →  0 models   Rules-based only (docs, formatting)      │
│   L1 (Low)       →  1 model    Single model review                      │
│   L2 (Medium)    →  2 models   Dual review + rubric scoring             │
│   L3 (High)      →  3 models   Triple review + rubric + approval req    │
│   L4 (Critical)  →  3 models   Triple review + rubric + HUMAN approval  │
│                                                                          │
│   ┌──────────────────────────────────────────────────────────────────┐  │
│   │  CONSENSUS OUTPUT:                                               │  │
│   │   • consensus_risk: "approve" | "request_changes" | "comment"    │  │
│   │   • agreement_score: 0.0 - 1.0 (model agreement %)               │  │
│   │   • combined_concerns: deduplicated from all models              │  │
│   │   • rubric_summary: averaged scores per dimension                │  │
│   │   • dissenting_opinions: models that disagreed                   │  │
│   └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Flexible Model Configuration

Configure **any combination** of models - same provider or mixed:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     EXAMPLE CONFIGURATIONS                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Option 1: All OpenRouter (recommended - single API)                     │
│    model_1: anthropic/claude-4.5-sonnet                                  │
│    model_2: openai/gpt-5.2                                               │
│    model_3: google/gemini-3-flash                                        │
│                                                                          │
│  Option 2: All Ollama (air-gapped)                                       │
│    model_1: llama4                                                       │
│    model_2: mistral-large                                                │
│    model_3: codellama-70b                                                │
│                                                                          │
│  Option 3: Mixed direct APIs                                             │
│    model_1: claude-4.5-haiku    (anthropic_api_key)                      │
│    model_2: gpt-5.2-mini        (openai_api_key)                         │
│    model_3: llama4              (ollama_host)                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

| Provider | Data Residency | Default Models | Best For |
|----------|----------------|----------------|----------|
| **Ollama** | Your infrastructure | llama4, mistral-large, codellama-70b | Air-gapped/regulated |
| **OpenRouter** | OpenRouter servers | Claude 4.5, GPT 5.2, Gemini 3 | Flexibility, diversity |
| **Anthropic** | Anthropic servers | Claude 4.5 Haiku | Direct Claude access |
| **OpenAI** | OpenAI servers | GPT 5.2 Mini | Existing OpenAI users |

### Risk Tiers

| Tier | Label | AI Models | Rubric | Description | Default Action |
|------|-------|-----------|--------|-------------|----------------|
| **L0** | Trivial | 0 (none) | No | Docs, comments, formatting | Auto-approve |
| **L1** | Low | 1 | No | Tests, non-critical code | Auto-approve |
| **L2** | Medium | 2 | Yes | Feature code, minor changes | Auto-approve |
| **L3** | High | 3 | Yes | Auth, config, sensitive areas | Requires approval |
| **L4** | Critical | 3 | Yes | Payments, PII, security, crypto | Requires HUMAN approval |

---

### Diff Analysis Output

![CodeGuard Diff Analysis](docs/diff-analysis-demo.png)

*Sensitive zones automatically detected in auth and payment code with risk tier assignment*

---

## Features

### Diff Postcard (PR Comment)

Every PR gets a summary comment showing:
- Risk tier with visual indicator
- Top risk drivers (why this tier?)
- Findings from policy evaluation
- Approval requirements

### Evidence Bundles

Cryptographically verifiable JSON bundles containing:
- Hash-chained event sequence
- Diff snapshot at analysis time
- Risk assessment details
- Approval records (when applicable)

Verify any bundle independently - see [Verification](#verification) section below.

### Evidence Mappings for Audit Support

Pre-built rule sets that map findings to audit frameworks:
- **SOC 2** - CC6, CC7, CC8 control evidence
- **HIPAA** - 164.312 safeguard documentation
- **PCI-DSS** - Requirement 3, 6, 8 evidence exports

> **Note**: These are *evidence mappings* that help document your existing controls - they don't make you compliant by themselves. Always work with your auditors.

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    rubric: hipaa  # or: soc2, pci-dss, default
```

### SARIF Integration

Export findings to GitHub Security tab:

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    upload_sarif: true

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: guardspine-results.sarif
```

## Configuration

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `risk_threshold` | Tier at which to require approval (L0-L4) | `L3` |
| `rubric` | Policy rubric (soc2, hipaa, pci-dss, default) | `default` |
| `github_token` | GitHub token for PR operations | Required |
| `post_comment` | Post Diff Postcard comment | `true` |
| `generate_bundle` | Create evidence bundle artifact | `true` |
| `upload_sarif` | Upload to GitHub Security tab | `false` |
| `fail_on_high_risk` | Block merge if over threshold (exit 1) | `false` |
| `rubrics_dir` | Directory containing rubric YAML files | `.guardspine/rubrics` |
| `risk_policy` | Path to YAML that overrides risk patterns/thresholds | - |
| `bundle_dir` | Directory to write evidence bundles | `.guardspine/bundles` |
| **Model Configuration** | | |
| `model_1` | First model (L1+). Format: `provider/model` or just `model` | Auto-detect |
| `model_2` | Second model (L2+). Format: `provider/model` or just `model` | Auto-detect |
| `model_3` | Third model (L3+). Format: `provider/model` or just `model` | Auto-detect |
| **API Keys** | | |
| `openai_api_key` | OpenAI key for GPT models (optional) | - |
| `anthropic_api_key` | Anthropic key for Claude models (optional) | - |
| `openrouter_api_key` | OpenRouter key (access 100+ models) (optional) | - |
| `ollama_host` | Ollama server URL for local AI (optional) | - |

### Outputs

| Output | Description |
|--------|-------------|
| `risk_tier` | Assessed risk tier (L0-L4) |
| `risk_drivers` | JSON array of top risk drivers |
| `bundle_path` | Path to evidence bundle |
| `findings_count` | Number of policy findings |
| `requires_approval` | Whether approval needed (true/false) |
| `models_used` | Number of AI models that reviewed |
| `consensus_risk` | Multi-model consensus: approve/request_changes/comment |
| `agreement_score` | How much models agreed (0.0-1.0) |

## Advanced Usage

### Custom Risk Threshold per Branch

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    risk_threshold: ${{ github.base_ref == 'main' && 'L2' || 'L3' }}
```

### Multi-Model AI Configuration

Configure up to 3 AI models for tier-based review. Models are used based on risk tier (L1: 1 model, L2: 2 models, L3+: 3 models).

#### Option 1: OpenRouter (Recommended - 3 diverse models via single API)

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
    model_1: anthropic/claude-4.5-sonnet   # Used for L1+
    model_2: openai/gpt-5.2                 # Used for L2+
    model_3: google/gemini-3-flash          # Used for L3+
```

**Popular OpenRouter models (Jan 2026):**
| Model | ID | Best For |
|-------|-----|----------|
| Claude 4.5 Sonnet | `anthropic/claude-4.5-sonnet` | Fast + quality (default) |
| Claude 4.5 Opus | `anthropic/claude-4.5-opus` | Best reasoning |
| GPT 5.2 | `openai/gpt-5.2` | Good balance |
| Gemini 3 Flash | `google/gemini-3-flash` | Fast, multimodal |
| Llama 4 70B | `meta-llama/llama-4-70b-instruct` | Open source |

#### Option 2: Ollama (Air-Gapped - 3 local models)

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    ollama_host: http://localhost:11434
    model_1: llama4
    model_2: mistral-large
    model_3: codellama-70b
```

#### Option 3: Mixed Providers (diversity of opinion)

```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
    ollama_host: http://localhost:11434
    model_1: claude-4.5-haiku    # Uses Anthropic
    model_2: gpt-5.2-mini        # Uses OpenAI
    model_3: llama4              # Uses Ollama
```

#### Option 4: Single Provider (legacy/simple)

Just provide one API key - CodeGuard will use default models:

```yaml
# Anthropic only (uses Claude 4.5 Haiku for all tiers)
- uses: DNYoussef/codeguard-action@v1
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}

# OpenAI only (uses GPT 5.2 Mini for all tiers)
- uses: DNYoussef/codeguard-action@v1
  with:
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

#### Ollama Setup (Local/On-Prem - Air-Gapped)

Ollama runs models locally - no data leaves your infrastructure. Perfect for enterprises with strict data residency requirements.

**Step 1: Install Ollama on your runner**

For self-hosted runners:
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.3
```

**Step 2: Start Ollama service**

Add a service step before CodeGuard:
```yaml
jobs:
  analyze:
    runs-on: self-hosted  # or ubuntu-latest with Ollama installed
    services:
      ollama:
        image: ollama/ollama
        ports:
          - 11434:11434
    steps:
      - uses: actions/checkout@v4

      # Pull model (one-time setup)
      - name: Pull Ollama model
        run: |
          curl -X POST http://localhost:11434/api/pull -d '{"name": "llama3.3"}'

      - uses: DNYoussef/codeguard-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          ollama_host: http://localhost:11434
          ollama_model: llama4
```

**Popular Ollama models (Jan 2026):**
| Model | ID | Size | Best For |
|-------|-----|------|----------|
| Llama 4 70B | `llama4` | 40GB | Best quality |
| Llama 4 8B | `llama4:8b` | 5GB | Fast, balanced |
| CodeLlama 70B | `codellama-70b` | 40GB | Code-focused |
| Mistral Large | `mistral-large` | 12GB | Good reasoning |
| Mixtral 8x22B | `mixtral-8x22b` | 80GB | MoE architecture |
| Phi-4 | `phi4` | 4GB | Microsoft's compact |
| Qwen 3 | `qwen3` | 8GB | Multilingual |

**Remote Ollama server:**
```yaml
- uses: DNYoussef/codeguard-action@v1
  with:
    ollama_host: http://your-ollama-server.internal:11434
    ollama_model: llama4
```

### Archive Evidence Bundles

```yaml
- uses: DNYoussef/codeguard-action@v1
  id: codeguard

- uses: actions/upload-artifact@v4
  with:
    name: evidence-bundle
    path: ${{ steps.codeguard.outputs.bundle_path }}
    retention-days: 2555  # 7 years for compliance
```

### Matrix Testing with Rubrics

```yaml
strategy:
  matrix:
    rubric: [soc2, hipaa, pci-dss]

steps:
  - uses: DNYoussef/codeguard-action@v1
    with:
      rubric: ${{ matrix.rubric }}
```

## Evidence Bundle Format

Bundles follow the [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) v0.2.0.
For backward compatibility, legacy `events` + `hash_chain` fields are still emitted:

```json
{
  "version": "0.2.0",
  "guardspine_spec_version": "0.2.0",
  "bundle_id": "gsb_abc123def456",
  "created_at": "2024-01-15T10:30:00Z",
  "context": {
    "repository": "acme/payments",
    "pr_number": 42,
    "commit_sha": "abc123..."
  },
  "events": [
    {"event_type": "pr_submitted", "hash": "..."},
    {"event_type": "analysis_completed", "hash": "..."},
    {"event_type": "risk_classified", "hash": "..."}
  ],
  "hash_chain": {
    "algorithm": "sha256",
    "final_hash": "...",
    "event_count": 3
  },
  "summary": {
    "risk_tier": "L3",
    "requires_approval": true
  }
}
```

## Verification

Anyone can verify a bundle without trusting GuardSpine.

### Install Options

```bash
# Option 1: From Git (always works)
pip install git+https://github.com/DNYoussef/guardspine-verify

# Option 2: From PyPI (when available)
pip install guardspine-verify

# Option 3: Docker (zero dependencies)
docker run --rm -v $(pwd):/data ghcr.io/dnyoussef/guardspine-verify /data/bundle.json
```

### Verify a Bundle

![GuardSpine Verifier](docs/verifier-demo.png)

*Cryptographic verification with evidence summary - no trust required*

```bash
guardspine-verify evidence-bundle.json

# Output:
# [OK] Hash chain verified (3 events)
# [OK] Final hash matches: abc123...
# [OK] Bundle integrity confirmed
```

## For AI Coding Agents

This section is for AI agents (Claude Code, Codex CLI, Gemini CLI, Aider, etc.) that are asked to set up code governance.

### Agent Installation Instructions

When a user asks you to "add code governance" or "set up GuardSpine", execute these steps:

```bash
# Step 1: Create workflow file
mkdir -p .github/workflows

# Step 2: Write the workflow
cat > .github/workflows/codeguard.yml << 'EOF'
name: CodeGuard
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DNYoussef/codeguard-action@v1
        id: codeguard
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          risk_threshold: L3
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: evidence-bundle
          path: ${{ steps.codeguard.outputs.bundle_path }}
EOF

# Step 3: Commit
git add .github/workflows/codeguard.yml
git commit -m "Add GuardSpine CodeGuard for PR governance"
```

### Agent Configuration Options

| User Request | Configuration |
|--------------|---------------|
| "strict governance" | `risk_threshold: L2` |
| "only block critical" | `risk_threshold: L4` |
| "we're SOC 2" | `rubric: soc2` |
| "we handle health data" | `rubric: hipaa` |
| "we process payments" | `rubric: pci-dss` |
| "use local AI only" | Add `ollama_host: http://localhost:11434` |
| "use Claude for analysis" | Add `anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}` |

### Agent Behavior Guidelines

1. **Always commit workflow files** - Don't just show the YAML, actually create the file
2. **Use appropriate rubric** - If the codebase has `/auth`, `/payment`, or health-related code, suggest the matching rubric
3. **Explain outputs** - Tell the user they'll see PR comments and can find bundles in workflow artifacts
4. **Don't overclaim** - Say "evidence mappings for audit support" not "makes you compliant"

### Detecting Existing Installation

Before installing, check:
```bash
# Check if already installed
if [ -f .github/workflows/codeguard.yml ]; then
  echo "CodeGuard already installed"
  cat .github/workflows/codeguard.yml
fi
```

---

## FAQ

**Q: Does this replace code review?**
A: No. CodeGuard adds *evidence* to your existing review process. Humans still review; GuardSpine proves what they saw.

**Q: What if I disagree with the risk tier?**
A: The tier is based on file patterns and content analysis. You can adjust the threshold or create custom rubrics.

**Q: Is my code sent anywhere?**
A: Diffs are analyzed locally in the GitHub runner. AI features (optional) send truncated diffs to your configured AI provider.

**Q: How long should I keep bundles?**
A: SOC 2 typically requires 1 year, HIPAA 6 years, PCI-DSS varies. Consult your compliance team.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**GuardSpine** - Evidence infrastructure for AI-mediated work.

[Website](https://guardspine.io) | [Docs](https://docs.guardspine.io) | [Support](mailto:support@guardspine.io)
