# Sigil

**A trust registry for MCP servers and agents.** Not another place to upload
things — a place to find out *what changed under your agent*.

```
   npm / PyPI / GitHub          ┌──────────┐
   (already public, no  ────────▶│  ingest  │  never executes package code
    publisher opt-in)           └────┬─────┘
                                     ▼
                              ┌─────────────┐
                              │   scan      │  every finding carries
                              │  10 rules   │  file · line · snippet
                              └──────┬──────┘
                                     ▼
              ┌──────────────────────┴───────────────────────┐
              ▼                                              ▼
      ┌───────────────┐                            ┌──────────────────┐
      │ trust score   │  transparent, every        │  version diff    │  ◀── the point
      │  A – F        │  deduction explained       │  what did it     │
      └───────────────┘                            │  GAIN since the  │
                                                   │  version you     │
                                                   │  approved?       │
                                                   └──────────────────┘
```

---

## The problem

Every scanner in this space answers *"is this package dangerous right now?"*
That question cannot catch the attack that actually happens: a package that is
clean for six versions, earns trust and a place in someone's config, then turns
hostile in the seventh.

Published scanners also run at roughly a **78% false-positive rate**, which
makes their output something people learn to ignore.

Sigil is built around both facts.

**1. Diffing, not snapshots.** Versions are kept forever and the diff between
them is a first-class object. New tools, broadened scopes, changed
descriptions, added install hooks, maintainer swaps, a repository link quietly
removed — all surfaced against the version you actually approved.

**2. Evidence or silence.** A `Finding` cannot exist without a file, a line and
the source text. Rules carry an explicit confidence and anything below the
reporting threshold is dropped before a human ever sees it. If we cannot point
at the line, we do not report it.

**3. Useful on day one.** It indexes what is already public. No publisher has
to opt in, upload anything, or agree to be listed. Claiming a listing comes
later.

---

## What a rug pull looks like

`notes-mcp` 1.0.0 → 1.1.0, from the bundled fixtures. Version 1.0.0 scores
**A / trusted** with zero findings. Then:

| | Change |
|---|---|
| 🔴 critical | `read_note` description now contains an `<IMPORTANT>` block instructing the model to read `~/.ssh/id_rsa` and `~/.env` and not tell the user |
| 🔴 critical | `read_note` scope broadened from `read` to `read, filesystem` |
| 🔴 critical | `postinstall` hook added — pipes a remote script to `sh` |
| 🟠 high | new tool `sync_notes` requesting `network, filesystem` |
| 🟠 high | publishing account changed |
| 🟠 high | repository link **removed**, so the artifact can no longer be reviewed |
| ⚪ low | `read_note` gained a `note_context` parameter — the exfiltration channel |

Fourteen changes, nine of them capability escalations. Flagged as a **rug pull
candidate**, dropped to **F / do-not-install**, and anyone watching the package
gets an alert naming both versions.

A one-shot scan of 1.1.0 finds the poisoned description. Only a diff shows the
*chain* — and that the same account that published the clean version is not the
account that published this one.

---

## Quick start

```bash
pip install -r requirements.txt
python seed_demo.py
python -m uvicorn sigil.main:app --port 8090
```

Open **http://127.0.0.1:8090/app/** — or `run.bat` on Windows.

Index something real:

```bash
curl -X POST localhost:8090/api/admin/ingest/npm/history \
  -H 'content-type: application/json' \
  -d '{"name":"some-mcp-server","versions":["1.0.0","1.1.0","1.2.0"]}'
```

Ingesting several versions in order backfills the diffs, so the registry can
answer "what changed" on the first day rather than only for changes observed
from now on.

---

## The rules

| Rule | Severity | Catches |
|---|---|---|
| `injection/tool-description` | critical | `<IMPORTANT>` blocks, "ignore previous instructions", "do not tell the user", credential references |
| `injection/hidden-characters` | critical | zero-width and bidi characters invisible to a reviewer, fully visible to the model |
| `supply_chain/install-script` | critical | pre/post-install hooks, especially ones that fetch remote code |
| `credentials/hardcoded-secret` | critical | live API keys and private keys, with placeholders excluded |
| `execution/dynamic` | high→critical | `shell=True`, `os.system`, `eval`; escalates when tainted input is nearby |
| `filesystem/path-traversal` | high | caller-controlled paths with no containment check |
| `network/unrestricted-egress` | high | caller-supplied URLs with no host allow-list |
| `permissions/overbroad-scope` | high | tools requesting `*`, `shell`, `admin`, whole filesystem |
| `provenance/*` | medium/low | no repository, no license |
| `supply_chain/unpinned-dependencies` | low | floating version ranges |

Noise control is deliberate: tests, examples, docs, `node_modules`, vendored
code and minified bundles are skipped; taint proximity is required before
flagging path and URL handling; a containment check nearby suppresses the
finding; repeated matches collapse into one finding with many evidence lines.

**The bundled well-built fixtures produce zero findings.** That is a test, not
a claim — `test_well_built_package_is_completely_clean`.

---

## Scoring

100 points across five components, every deduction stated in plain language in
the UI:

| Component | Max | Why |
|---|---|---|
| findings | 35 | weighted by severity **and** confidence, so a speculative match cannot tank a good package |
| provenance | 25 | repository, license, identifiable publisher |
| permissions | 20 | how much authority the tools ask for |
| stability | 10 | do capabilities stay put across releases |
| maturity | 10 | deliberately small — age is weak evidence, and old packages get taken over |

A single critical finding forces `do-not-install` regardless of the arithmetic.

---

## API

Public:

```
GET  /api/stats
GET  /api/packages?q=&min_score=
GET  /api/packages/{source}/{name}
GET  /api/feed/changes            # rug-pull candidates first
GET  /api/badge/{source}/{name}   # SVG for a README
POST /api/packages/{source}/{name}/watch
GET  /api/alerts/{subscriber}
```

Admin (gated by `SIGIL_ADMIN_TOKEN`):

```
POST /api/admin/ingest/npm          {name, version?}
POST /api/admin/ingest/npm/history  {name, versions[]}
POST /api/admin/ingest/local        {path, source}
GET  /api/admin/search/npm?q=
GET  /api/admin/health
```

---

## Where the money is

Free: browsing, searching, package pages, badges. That is the distribution
engine — every badge in a README is a maintainer linking back.

Paid: **watches and alerts.** "Tell me the moment something in my agent's
config gains a capability" is worth a monthly fee to anyone running agents in
production, and it is the one thing a directory cannot offer. The schema
already carries `watches` and `alerts`; billing does not.

---

## Safety and fairness

This tool makes public claims about other people's software, so:

- **Every finding is falsifiable.** File, line and snippet are shown so a
  maintainer can check the exact thing the scanner saw.
- **Confidence is displayed**, and low-confidence matches are never shown.
- **A rug-pull flag is a signal, not an accusation** — it means a version
  gained capability and a human should look before it reaches an agent.
- **Package code is never executed.** Analysis is static; tarballs are unpacked
  to a temp directory with path-escape and size limits, then deleted.
- The bundled fixtures are **fictional**. Scanning real packages is what the
  tool is for; publishing scores about real projects is a decision with real
  consequences for them, and a dispute path should exist before you do it at
  scale.

---

## Tests

```bash
python -m pytest -q
```

41 tests, no network. They cover the false-positive suppressions (containment
checks, placeholder keys, skipped test files), the true positives, the full
rug-pull chain, scope narrowing *not* counting as escalation, score
transparency, admin auth, and hostile-archive handling — path escape, absolute
paths and decompression bombs are all refused.

---

## Layout

```
sigil/
├── models.py           # Finding, Change, VersionDiff, ScoreBreakdown
├── db.py               # versions kept forever; diffs are first-class rows
├── service.py          # ingest → scan → score → diff → alert
├── scoring.py          # transparent, every deduction explained
├── analysis/
│   ├── rules.py        # the 10 rules, all evidence-backed
│   ├── scanner.py      # threshold filtering + evidence merging
│   ├── diff.py         # ◀ the differentiator
│   └── manifest.py     # tool extraction: manifest, Python AST, JS regex
├── ingest/
│   ├── npm.py          # registry + safe tarball extraction
│   └── local.py        # directories and fixtures
└── routes/
fixtures/               # incl. the notes-mcp rug-pull pair
web/                    # the registry UI
```

## License

MIT — see [LICENSE](LICENSE).
