# CodeGuard Action - Phase 0 Eval Results

**Date**: 2026-02-06
**Harness Version**: v3.0
**Models**: Claude 4.5 Sonnet, GPT-5.2, Gemini 3 Flash (via OpenRouter)
**Target Thresholds**: FP < 5%, FN < 5%, Noise < 10%

## Executive Summary

**85 total samples** across 2 datasets. CodeGuard achieves 52.9% accuracy at L0 (rules-only).
All four tiers (L0-L3) produce identical results due to a critical architecture gap:
AI model reviews run but never feed into the decision path.

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Accuracy | 52.9% | -- | -- |
| False Positive Rate | 42.4% (14/33) | < 5% | FAIL |
| False Negative Rate | 50.0% (26/52) | < 5% | FAIL |
| Detection Rate | 50.0% (26/52) | > 95% | FAIL |

## Results by Tier (Hand-Crafted, 15 samples)

| Tier | Models | Detection Rate | FP Rate | FN Rate | Time |
|------|--------|---------------|---------|---------|------|
| L0 (dry-run) | 0 | 70.0% (7/10) | 40.0% (2/5) | 30.0% (3/10) | 0.0s |
| L1 | 1 | 70.0% (7/10) | 40.0% (2/5) | 30.0% (3/10) | 8.5s |
| L2 | 2 + rubric | 70.0% (7/10) | 40.0% (2/5) | 30.0% (3/10) | 9.7s |
| L3 | 3 + rubric | 70.0% (7/10) | 40.0% (2/5) | 30.0% (3/10) | 9.8s |

## Results by Dataset (L0)

| Dataset | Samples | Accuracy | FP Rate | FN Rate |
|---------|---------|----------|---------|---------|
| hand-crafted | 15 (10v/5c) | 66.7% | 40.0% | 30.0% |
| python-cwe | 70 (42v/28c) | 50.0% | 42.9% | 54.8% |
| **Combined** | **85 (52v/33c)** | **52.9%** | **42.4%** | **50.0%** |

## Results by CWE (Python-CWE Dataset, L0)

| CWE | Name | Vuln | Clean | Detection | FP Rate | FN Rate | Accuracy |
|-----|------|------|-------|-----------|---------|---------|----------|
| CWE-89 | SQL Injection | 6 | 4 | 100% (6/6) | 75.0% (3/4) | 0% | 70% |
| CWE-79 | XSS | 6 | 4 | 16.7% (1/6) | 0% (0/4) | 83.3% | 50% |
| CWE-78 | Command Injection | 6 | 4 | 16.7% (1/6) | 25.0% (1/4) | 83.3% | 40% |
| CWE-502 | Deserialization | 6 | 4 | 0% (0/6) | 0% (0/4) | 100% | 40% |
| CWE-798 | Hardcoded Creds | 6 | 4 | 100% (6/6) | 100% (4/4) | 0% | 60% |
| CWE-22 | Path Traversal | 6 | 4 | 0% (0/6) | 0% (0/4) | 100% | 40% |
| CWE-327 | Broken Crypto | 6 | 4 | 83.3% (5/6) | 100% (4/4) | 16.7% | 50% |

### Pattern: Two Distinct Failure Modes

**High Detection / High FP** (keyword-heavy zones):
- CWE-89 (SQLi): Detects ALL vulnerable, but also flags parameterized queries (3/4 FP)
- CWE-798 (Creds): Detects ALL hardcoded creds, but also flags env-var/vault usage (4/4 FP)
- CWE-327 (Crypto): Detects 5/6 weak crypto, but also flags bcrypt/AES/argon2 (4/4 FP)

**Low Detection / Low FP** (no SENSITIVE_PATTERNS):
- CWE-79 (XSS): Only 1/6 detected (the one with `render_template_string` matching `database` zone)
- CWE-78 (CmdI): Only 1/6 detected (the one with `subprocess` matching `infra` zone)
- CWE-502 (Deser): 0/6 detected (pickle/marshal/shelve match nothing)
- CWE-22 (Path): 0/6 detected (open/os.path.join match nothing)

## Critical Finding: AI Reviews Don't Influence Decisions

All four tiers produce identical accuracy. The AI models run successfully and provide
excellent analysis (SQL injection identified with 0.99 confidence, correct remediation
advice), but the pipeline architecture doesn't feed AI findings into the RiskClassifier
or DecisionEngine.

**Current decision flow**:
```
DiffAnalyzer (zone detection via regex) -> RiskClassifier (zone + file pattern scoring)
-> DecisionEngine (finding severity thresholds) -> merge/conditions/block
```

**AI reviews** are stored as metadata in `multi_model_review` but:
- `RiskClassifier._collect_findings()` only uses `sensitive_zones` (regex matches)
- `RiskClassifier._apply_rubric()` only uses file patterns
- AI consensus, concerns, and rubric scores are not consulted

## Root Cause Analysis

### FP Root Cause: Zone detection is keyword-only

The classifier cannot distinguish safe vs unsafe usage of the same API:
- `bcrypt.hashpw()` and `md5(password)` both trigger `crypto` zone
- `cursor.execute(sql, params)` and `cursor.execute(f"SELECT {user_input}")` both trigger `database` zone
- `os.environ.get("SECRET_KEY")` and `SECRET_KEY = "hardcoded"` both trigger `auth`/`security` zones

### FN Root Cause: Missing SENSITIVE_PATTERNS

Current zones (8): auth, payment, crypto, database, security, pii, config, infra

Missing detection for:
- `os.system()`, `subprocess.call()`, `eval()`, `exec()` (command injection)
- `pickle.loads()`, `yaml.load()`, `marshal.loads()`, `shelve.open()` (deserialization)
- `render_template_string()`, `Markup()`, `|safe` filter (template injection)
- `open(user_input)`, `os.path.join(base, user_input)` (path traversal)
- `Popen(cmd, shell=True)` (command injection variant)

Additionally: medium-severity findings don't trigger `merge-with-conditions` or `block`.

## Failure Inventory

### False Positives (14 total)

| # | Dataset | Sample | Why Flagged | Why Safe |
|---|---------|--------|-------------|----------|
| 1 | hand-crafted | auth_01_safe_bcrypt | auth+crypto zone (11 zones) | bcrypt 12 rounds |
| 2 | hand-crafted | db_01_parameterized | database zone (4 zones) | `?` placeholder params |
| 3 | python-cwe | sqli_safe_named | database zone (5 zones) | `:name` parameterized |
| 4 | python-cwe | sqli_safe_orm | database zone (2 zones) | SQLAlchemy ORM |
| 5 | python-cwe | sqli_safe_param | database zone (5 zones) | `%s` parameterized |
| 6 | python-cwe | cmdi_safe_shlex | infra zone (1 zone) | shlex.split() |
| 7 | python-cwe | creds_safe_config_file | auth zone (2 zones) | config file reader |
| 8 | python-cwe | creds_safe_env | auth zone (3 zones) | os.environ.get() |
| 9 | python-cwe | creds_safe_keyring | auth zone (4 zones) | keyring library |
| 10 | python-cwe | creds_safe_vault | auth zone (9 zones) | HashiCorp Vault |
| 11 | python-cwe | crypto_safe_aes | crypto zone (2 zones) | AES-256-GCM |
| 12 | python-cwe | crypto_safe_argon2 | crypto zone (12 zones) | argon2 hash |
| 13 | python-cwe | crypto_safe_bcrypt | crypto zone (8 zones) | bcrypt hash |
| 14 | python-cwe | crypto_safe_secrets | crypto zone (3 zones) | secrets.token_hex() |

### False Negatives (26 total)

| # | Dataset | Sample | CWE | Why Missed |
|---|---------|--------|-----|------------|
| 1 | hand-crafted | cmdi_01_os_system | 78 | infra zone medium only |
| 2 | hand-crafted | deser_01_pickle | 502 | config zone medium only |
| 3 | hand-crafted | xss_02_template | 79 | 0 zones |
| 4 | python-cwe | xss_direct_response | 79 | 0 zones |
| 5 | python-cwe | xss_django_safe | 79 | 0 zones |
| 6 | python-cwe | xss_json_response | 79 | 0 zones |
| 7 | python-cwe | xss_markup_safe | 79 | 0 zones |
| 8 | python-cwe | xss_template_string | 79 | 0 zones |
| 9 | python-cwe | cmdi_eval | 78 | 0 zones |
| 10 | python-cwe | cmdi_exec | 78 | 0 zones |
| 11 | python-cwe | cmdi_flask_os | 78 | 0 zones |
| 12 | python-cwe | cmdi_os_system | 78 | 1 zone, medium sev |
| 13 | python-cwe | cmdi_popen | 78 | 0 zones |
| 14 | python-cwe | deser_jsonpickle | 502 | 0 zones |
| 15 | python-cwe | deser_marshal | 502 | 0 zones |
| 16 | python-cwe | deser_pickle_file | 502 | 0 zones |
| 17 | python-cwe | deser_pickle_loads | 502 | 0 zones |
| 18 | python-cwe | deser_shelve | 502 | 0 zones |
| 19 | python-cwe | deser_yaml_load | 502 | 2 zones, medium sev |
| 20 | python-cwe | path_flask_directory | 22 | 0 zones |
| 21 | python-cwe | path_open_direct | 22 | 0 zones |
| 22 | python-cwe | path_open_format | 22 | 0 zones |
| 23 | python-cwe | path_os_join | 22 | 0 zones |
| 24 | python-cwe | path_symlink | 22 | 0 zones |
| 25 | python-cwe | path_zipfile | 22 | 0 zones |
| 26 | python-cwe | crypto_random_seed | 327 | 0 zones |

## Recommendations for Phase 1

### P0: Wire AI reviews into decisions (fixes FP problem)
- `RiskClassifier` should consume `multi_model_review.consensus`
- If AI consensus is "approve" and findings are zone-only, downgrade to advisory
- If AI consensus is "request_changes", upgrade medium findings to high
- Expected impact: eliminates 12/14 FPs (safe crypto, safe SQL, safe credentials)

### P1: Add security-specific SENSITIVE_PATTERNS (fixes FN problem)
```python
"command_injection": r"(os\.system|subprocess\.call|subprocess\.run|eval\(|exec\(|Popen\(.*shell=True)",
"deserialization": r"(pickle\.loads|pickle\.load|yaml\.load|marshal\.loads|shelve\.open|jsonpickle\.decode)",
"template_injection": r"(render_template_string|Markup\(|jinja2\.Template|Template\(.*\+|\.safe\b)",
"path_traversal": r"(open\(.*\+|os\.path\.join\(.*request|send_from_directory\(.*request|\.\.\/)",
"weak_crypto": r"(random\.seed|random\.randint.*token|random\.choice.*password)",
```
Expected impact: eliminates 23/26 FNs

### P2: Severity-aware zone mapping
- `command_injection` -> critical (currently no zone or medium)
- `deserialization` -> critical (currently no zone or medium)
- `template_injection` -> high (currently no zone)
- `path_traversal` -> high (currently no zone)
- `weak_crypto` -> high (currently no zone)

### P3: Additional eval datasets
- CVEFixes: fetch script ready (`eval/datasets/fetch_cvefixes.py`), needs 391MB Kaggle CSV
- Juliet (NIST SARD): C/C++/Java only, no Python equivalent available
- CASTLE: C only
- LiveCVEBench / SEC-bench: Docker-heavy, future work

## Datasets

### hand-crafted (15 samples)
10 vulnerable + 5 clean. Manually written patches covering SQLi, XSS, SSTI, command injection,
deserialization, hardcoded secrets, weak auth, payment validation.

### python-cwe (70 samples)
42 vulnerable + 28 clean. Generated benchmark covering 7 CWEs with 6 vulnerable variants
and 4 safe variants each. Script: `eval/datasets/generate_python_cwe.py`.

CWEs: 89 (SQLi), 79 (XSS), 78 (OS Command Injection), 502 (Deserialization),
798 (Hardcoded Credentials), 22 (Path Traversal), 327 (Broken Crypto).

## Sample Breakdown (Hand-Crafted)

### Vulnerable (10)
| # | Sample | Tier | Zones | Decision | Result |
|---|--------|------|-------|----------|--------|
| 1 | sqli_01_raw_format | L2->L3 | 5 (database) | merge-with-conditions | OK |
| 2 | sqli_02_fstring | L2->L3 | 4 (database) | merge-with-conditions | OK |
| 3 | sqli_03_concat | L2->L3 | 4 (database) | merge-with-conditions | OK |
| 4 | xss_01_direct | L2->L3 | 2 (database) | merge-with-conditions | OK |
| 5 | xss_02_template | L2->L2 | 0 | merge | FN |
| 6 | secrets_01_hardcoded | L4->L4 | 7 (auth,infra,payment,security) | block | OK |
| 7 | cmdi_01_os_system | L2->L2 | 2 (infra) | merge | FN |
| 8 | auth_01_weak_session | L4->L4 | 10 (auth,crypto) | block | OK |
| 9 | deser_01_pickle | L2->L2 | 3 (config) | merge | FN |
| 10 | payment_01_no_validation | L4->L4 | 5 (auth,payment) | block | OK |

### Clean (5)
| # | Sample | Tier | Zones | Decision | Result |
|---|--------|------|-------|----------|--------|
| 1 | docs_01_readme | L0->L0 | 0 | merge | OK |
| 2 | test_01_unit | L1->L1 | 0 | merge | OK |
| 3 | feature_01_safe_utility | L2->L2 | 4 (config) | merge | OK |
| 4 | auth_01_safe_bcrypt | L4->L4 | 11 (auth,crypto) | block | FP |
| 5 | db_01_parameterized | L2->L3 | 4 (database) | merge-with-conditions | FP |
