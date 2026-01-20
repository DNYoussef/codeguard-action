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

## How It Works

```
PR Opened -> CodeGuard analyzes diff -> Risk tier assigned (L0-L4)
                                              |
                   L0-L2: Auto-approved       |       L3-L4: Human review required
                                              v
                            Evidence bundle generated (hash-chained, verifiable)
```

### Risk Tiers

| Tier | Label | Description | Default Action |
|------|-------|-------------|----------------|
| **L0** | Trivial | Docs, comments, formatting | Auto-approve |
| **L1** | Low | Tests, non-critical code | Auto-approve |
| **L2** | Medium | Feature code, minor changes | Auto-approve |
| **L3** | High | Auth, config, sensitive areas | Requires approval |
| **L4** | Critical | Payments, PII, security, crypto | Requires approval |

## Quick Start

Add to your workflow (`.github/workflows/codeguard.yml`):

```yaml
name: CodeGuard

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: GuardSpine CodeGuard
        uses: guardspine/codeguard-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          risk_threshold: L3
          rubric: soc2
```

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

Verify any bundle independently:
```bash
pip install guardspine-verify
guardspine-verify bundle.json
```

### Compliance Rubrics

Built-in support for:
- **SOC 2** - CC6, CC7, CC8 controls
- **HIPAA** - 164.312 safeguards
- **PCI-DSS** - Requirements 3, 6, 8

```yaml
- uses: guardspine/codeguard-action@v1
  with:
    rubric: hipaa  # or: soc2, pci-dss, default
```

### SARIF Integration

Export findings to GitHub Security tab:

```yaml
- uses: guardspine/codeguard-action@v1
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
| `fail_on_high_risk` | Block merge if over threshold | `true` |
| `openai_api_key` | OpenAI key for AI summary (optional) | - |
| `anthropic_api_key` | Anthropic key for AI summary (optional) | - |
| `openrouter_api_key` | OpenRouter key for AI summary (optional) | - |
| `openrouter_model` | Model to use with OpenRouter | `anthropic/claude-sonnet-4` |
| `ollama_host` | Ollama server URL for local AI (optional) | - |
| `ollama_model` | Model to use with Ollama | `llama3.3` |

### Outputs

| Output | Description |
|--------|-------------|
| `risk_tier` | Assessed risk tier (L0-L4) |
| `risk_drivers` | JSON array of top risk drivers |
| `bundle_path` | Path to evidence bundle |
| `findings_count` | Number of policy findings |
| `requires_approval` | Whether approval needed (true/false) |

## Advanced Usage

### Custom Risk Threshold per Branch

```yaml
- uses: guardspine/codeguard-action@v1
  with:
    risk_threshold: ${{ github.base_ref == 'main' && 'L2' || 'L3' }}
```

### AI-Powered Analysis

Add an AI API key for intelligent diff summarization. You have three options:

#### Option 1: OpenRouter (Recommended - 100+ models)

OpenRouter gives you access to Claude, GPT-4, Gemini, Llama, and 100+ other models through a single API.

**Step 1: Get your API key**
1. Go to [openrouter.ai](https://openrouter.ai/)
2. Sign up or log in
3. Navigate to **Keys** in the dashboard
4. Click **Create Key**
5. Copy your key (starts with `sk-or-...`)

**Step 2: Add the secret to your GitHub repository**
1. Go to your repository on GitHub
2. Click **Settings** > **Secrets and variables** > **Actions**
3. Click **New repository secret**
4. Name: `OPENROUTER_API_KEY`
5. Value: Paste your OpenRouter API key
6. Click **Add secret**

**Step 3: Use in your workflow**
```yaml
- uses: guardspine/codeguard-action@v1
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
    openrouter_model: anthropic/claude-sonnet-4  # or any model below
```

**Popular OpenRouter models:**
| Model | ID | Best For |
|-------|-----|----------|
| Claude Opus 4.5 | `anthropic/claude-opus-4.5` | Best reasoning |
| Claude Sonnet 4 | `anthropic/claude-sonnet-4` | Fast + quality (default) |
| GPT-4o | `openai/gpt-4o` | Good balance |
| Gemini 3 | `google/gemini-3` | Google's latest |
| Codex 5.2 | `openai/codex-5.2` | Code-focused |
| Llama 3.3 70B | `meta-llama/llama-3.3-70b-instruct` | Open source |

#### Option 2: Anthropic Direct

```yaml
- uses: guardspine/codeguard-action@v1
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

#### Option 3: OpenAI Direct

```yaml
- uses: guardspine/codeguard-action@v1
  with:
    openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

#### Option 4: Ollama (Local/On-Prem - Air-Gapped)

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

      - uses: guardspine/codeguard-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          ollama_host: http://localhost:11434
          ollama_model: llama3.3
```

**Popular Ollama models:**
| Model | ID | Size | Best For |
|-------|-----|------|----------|
| Llama 3.3 70B | `llama3.3` | 40GB | Best quality |
| Llama 3.2 | `llama3.2` | 2GB | Fast, small |
| CodeLlama | `codellama` | 7GB | Code-focused |
| Mistral | `mistral` | 4GB | Good balance |
| Mixtral | `mixtral` | 26GB | MoE architecture |
| Phi-3 | `phi3` | 2GB | Microsoft's compact |
| Qwen 2.5 | `qwen2.5` | 4GB | Multilingual |

**Remote Ollama server:**
```yaml
- uses: guardspine/codeguard-action@v1
  with:
    ollama_host: http://your-ollama-server.internal:11434
    ollama_model: llama3.3
```

### Archive Evidence Bundles

```yaml
- uses: guardspine/codeguard-action@v1
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
  - uses: guardspine/codeguard-action@v1
    with:
      rubric: ${{ matrix.rubric }}
```

## Evidence Bundle Format

Bundles follow the [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) v1.0:

```json
{
  "guardspine_spec_version": "1.0.0",
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

Anyone can verify a bundle without trusting GuardSpine:

```bash
# Install verifier
pip install guardspine-verify

# Verify bundle integrity
guardspine-verify evidence-bundle.json

# Output:
# [OK] Hash chain verified (3 events)
# [OK] Final hash matches: abc123...
# [OK] Bundle integrity confirmed
```

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
