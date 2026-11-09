# triage-agent

Turns a Snyk scan into reviewed, verified pull requests.

A scanner tells you there are 265 vulnerabilities. It does not tell you which
ones to fix this afternoon. This does: it groups findings by the dependency
they arrive through, asks [Cohere](https://cohere.com) to bucket each group,
applies rules the model cannot override, opens a pull request for the groups
that qualify, and posts a re-scan back to the PR as proof.

Run against [Snyk's `goof`](https://github.com/snyk/goof), a deliberately
vulnerable Node app:

| | result |
|---|---|
| findings in | 265 (9 critical, 136 high, 105 medium, 15 low) |
| groups out | 20 |
| PRs opened | 2 — [#4](https://github.com/BuildAgentic/goof/pull/4), [#5](https://github.com/BuildAgentic/goof/pull/5) |
| findings cleared | 31 |
| findings introduced | 0 |

Both PRs carry a verification comment the agent posted itself.

## What the model decides, and what it does not

This split is the whole design.

**Cohere decides** which groups to act on — reading severities, fix
availability, scope, and dependency paths, then bucketing each group as
`act_now`, `batch_later` or `needs_human`, with a one-sentence reason.

**Code decides** everything that touches the repository: which version to
upgrade to, whether that version is a breaking change, and whether to open a
PR at all. The model's bucket is an input to that, not a verdict.

A wrong bucket costs someone a review. A wrong version number ships broken
code. Those failures are not the same size, so they are not handled by the
same mechanism.

The guardrail runs after every model call and can only ever be more
conservative:

```python
# a group with a breaking upgrade or no fix can't be act_now
# a group with no high or critical finding can't be act_now
```

On the real run it overrode the model three times. One of those was express:
Cohere said `act_now`, but the upgrade drags `cookie` 0.3.1 → 0.7.2 along, and
below version 1.0 a minor bump can break an API. Held for review. A human
approved it, and the re-scan confirmed the call — 15 findings cleared, none
introduced.

## Pipeline

```
snyk test --json
   │
   ▼
ingest_snyk.py      deduplicate on (package, version, advisory id)
   │                 921 raw rows → 265 findings
   ▼
triage_cohere.py    group by direct dependency, bucket with Cohere,
   │                 then apply the guardrail
   ▼
open_pr.py          pick a version by rule, bump, branch, open a draft PR
   │
   ▼
open_pr.py --verify re-scan, diff, comment the result on the PR
```

## Usage

```bash
pip install cohere
export COHERE_API_KEY=...        # a free trial key is enough
snyk test --json > snyk.json

python3 ingest_snyk.py snyk.json -o findings.json
python3 triage_cohere.py findings.json -o triage.json --manifest package.json

# see what it would do; writes nothing
python3 open_pr.py findings.json triage.json --repo ~/project

# branch, commit, push, open a draft PR
python3 open_pr.py findings.json triage.json --repo ~/project \
    --gh-repo owner/name --push

# after re-scanning the branch, post the proof
python3 open_pr.py --verify 5 --repo ~/project \
    --baseline findings-base.json --after findings-branch.json \
    --gh-repo owner/name --push
```

Nothing is written without `--push`. PRs open as drafts.

Triage is batched 8 groups per call and cached in `triage.json`, so an
interrupted run resumes without repeating calls. The full 20-group run costs 3
API calls.

## Measure before and after the same way

This is the part that is easy to get wrong, and the first run of this project
got it wrong.

Snyk builds its dependency graph differently depending on how the project is
laid out. A v1 lockfile and a v3 lockfile produce different trees. An
installed `node_modules` and a bare lockfile produce different trees. Compare
across either boundary and you get findings that look new and are not.

The first comparison here reported 3 new high-severity findings from the
express bump. They did not exist. The baseline had been scanned from a v3
lockfile and the branch from a v1 lockfile. Rebuilt consistently, the same
bump showed 15 fixed and 0 new.

So: scan the baseline and the branch in separate checkouts, regenerate both
lockfiles the same way, and leave `node_modules` out of both.

```bash
git clone <repo> project-base && cd project-base
npm install --package-lock-only --ignore-scripts --lockfile-version 1
snyk test --json > base.json
```

Deduplicating on `(package, version, advisory id)` matters for the same
reason. Drop the version and two installed copies of a package collapse into
one row, which quietly changes every count.

## Limitations

- **Verification covers advisories, not behaviour.** The re-scan proves the
  findings are gone. It does not prove the application still works. `goof` has
  no test suite, so the express bump was validated by a smoke test over the
  surface it touches — body-parser, cookie-parser, static files, POST routing
  — and the lodash bump was not validated at runtime at all.
- **Only direct dependencies can be bumped.** A finding reachable only through
  a transitive package needs an `overrides` entry, which this does not
  generate.
- **The version floor comes from the npm registry**, so `open_pr.py` needs
  network access and will fall back to the advisory's fix version without it.
- **Cohere's trial key is non-commercial** and rate-limited. The batching and
  the 3-second pause exist for that reason.

## Files

| file | what it does |
|---|---|
| `ingest_snyk.py` | normalize and deduplicate `snyk test --json` |
| `triage_cohere.py` | group, bucket with Cohere, apply the guardrail |
| `open_pr.py` | choose a version, open the PR, verify the result |
| `tests/test_open_pr.py` | version rules, diff logic, guardrail behaviour |

```bash
python3 -m unittest discover tests -v
```

Standard library only, apart from `cohere`.
