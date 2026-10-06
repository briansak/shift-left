# First success: a gate decision on a change you made

This walkthrough is for someone who has just finished `./shift-left up` and wants to see Shift-Left block, then pass, a configuration change they wrote themselves. Budget **10–15 minutes**. Every command below is copy-pasteable; each step says what success looks like.

Do not start here if the stack is not up. Install is in the [README](../README.md#install). This tutorial does not cover Docker, Python, or model downloads.

You will use **one ASA example** for the change you create. The bundled sample PR is Azure Terraform — walk it first so you know the shape of the UI, then switch to ASA for the rest.

## 1. Confirm the stack is healthy

From the repository root:

```bash
./shift-left status
```

**Healthy:**

```
Overall: HEALTHY — All critical pipeline prerequisites are satisfied.
```

No extra lines. Exit code 0.

Antares is optional and off by default. A missing Antares server does **not** fail this check (advisory only).

**If you see something else:**

| Output | Meaning |
|--------|---------|
| `Overall: DEGRADED — System degraded: …` | Non-critical checks failed. Lines below name them. Config review may still work; fix the named check before trusting the gate. |
| `Overall: FAILED — System failed: …` | A critical prerequisite is down. Do not continue. |
| `Orchestrator not reachable — run ./shift-left up or ./shift-left doctor` | The API on `:8080` is not answering. Resume `./shift-left up`. |
| `Setup incomplete — run ./shift-left up` | `config/shift-left.yaml` is missing. |

Failed and degraded lines look like:

```
  [critical] forgejo: …
  [degraded_config] foundation_sec_weights: …
```

Use `./shift-left doctor` and [troubleshooting.md](troubleshooting.md) if the overall line is not `HEALTHY`.

## 2. Authenticate to the UI

The UI is at [http://127.0.0.1:8080/ui/login](http://127.0.0.1:8080/ui/login). It does not use the Forgejo password.

**Token source (one of these):**

1. **Preferred.** The `Operator UI/API token` printed at the end of `./shift-left up` (a `slt_…` value, shown once with the Forgejo admin credentials). The bootstrap token has `admin`, `review`, `triage`, `approve`, and `override`.
2. **If you did not save it.** Mint a new one:

```bash
./shift-left token mint --label tutorial --actor reviewer --capabilities review,triage,approve,admin
```

**Expected mint output:**

```
Token minted (store this value — it cannot be retrieved again):
slt_<long secret>
Token id: <uuid>
```

Store the `slt_…` value. `./shift-left token list` never reprints plaintext.

**Where to paste it.** On the login page, the field labeled **API token (slt_…)**. Submit **Continue**.

**Success:** the shell loads (sidebar: Targets, Config changes, Findings). The top-right name is the token **actor** (`admin` for the bootstrap token, or `reviewer` if you minted as above). A failed paste redisplays the form with `Invalid or revoked token`.

Forgejo itself is [http://127.0.0.1:3000](http://127.0.0.1:3000) (`.env` may list `http://localhost:3000`). Sign in there with the **Forgejo admin user** and **Forgejo admin password** from `up` — you will need that session in step 5. The Forgejo API token is the git-HTTPS password, not the UI `slt_` token.

## 3. Walk the bundled sample PR

`up` created `sample-firewall` (usually `shift-left/sample-firewall`) and opened a pull request titled **Sample: unrestricted any/any permit**.

That PR is **Azure Terraform**, rule **TF-001**, not ASA. Use it only to learn the screens. Your own change in the next steps is ASA.

In the Shift-Left UI, open **Config changes** ([http://127.0.0.1:8080/ui/changes](http://127.0.0.1:8080/ui/changes)).

**Expected row:**

| Column | Looks like |
|--------|------------|
| Repository | `shift-left/sample-firewall` (owner may be your Forgejo admin login if the `shift-left` org was not created) |
| PR | `PR-<n> — Sample: unrestricted any/any permit` |
| Validation | `blocked_by_policy` |
| Gate | `blocked` |

Click the repository link into the change page (`/ui/pr/{owner}/sample-firewall/{n}`).

**Expected on that page:**

- Workflow state **blocked_by_policy**. Next action tells you to resolve findings or obtain an override.
- **Current vs proposed** shows `terraform/insecure.tf` with the inbound `azurerm_network_security_rule` highlighted.
- **Validation → Policy decision (deterministic):** `BLOCK`.
- **Findings (handler-asserted):** title `Deterministic rule: TF-001`, badge `BLOCK`, `handler CWE-284`, description about internet-wide ingress.
- **Gate and approval:** **Non-allowing**, reason starting with `Block policy decision is active`.
- **Open in Forgejo** (top of the page) — same PR. The Actions job **Shift-Left Security Review** should already have run. A PR comment lists handler findings. The commit status context **`shift-left/gate`** on the head SHA is **failure**.

If Validation says there is no recorded review yet, wait for the Forgejo Actions run to finish and refresh. The self-hosted runner must be online (`./shift-left status` would have failed otherwise).

## 4. Create a repo, clone it, commit a permissive ASA rule

```bash
./shift-left new-repo edge-asa
```

**Expected:**

```
Created Forgejo repo with review workflow and SHIFT_LEFT_TOKEN: shift-left/edge-asa
```

The slug may use a different owner (same rule as the sample). Copy it. You will also see lines about creating the repo and configuring the `SHIFT_LEFT_TOKEN` Actions secret if this is the first time.

The scaffolded workflow only watches `terraform/**` (and the workflow file itself). This tutorial places the ASA file under `terraform/` so Actions runs without editing CI. The parser keys off the **`.rules` extension**, not the directory — `**/*.rules` maps to `cisco_secure_firewall` with no managed target required.

Clone (replace the owner if your slug differed):

```bash
git clone http://127.0.0.1:3000/shift-left/edge-asa.git
cd edge-asa
git checkout -b add-permissive-acl
mkdir -p terraform
cat > terraform/edge.rules <<'EOF'
access-list OUTSIDE_IN extended permit ip any any
EOF
git add terraform/edge.rules
git commit -m "Add unrestricted ASA any/any ACE"
git push -u origin add-permissive-acl
```

**HTTPS credentials when git asks:**

- Username: Forgejo admin user from `up` (default `shiftleft-admin`)
- Password: the **Forgejo API token** from `up`, not the `slt_` UI token and not the Forgejo login password

**Expected:** clone contains `README.md` and `.forgejo/workflows/shift-left-review.yml`. Commit succeeds. Push creates `add-permissive-acl` on Forgejo.

The ACE is the labeled ASA-001 violation from the test corpus: unrestricted `permit ip any any`.

## 5. Open a PR in Forgejo

In Forgejo: [http://127.0.0.1:3000/shift-left/edge-asa](http://127.0.0.1:3000/shift-left/edge-asa) (adjust owner). After the push, use **Compare & pull request**, or **Pull Requests → New Pull Request**.

- Base: `main`
- Compare: `add-permissive-acl`
- Title: anything you will recognize (for example `Permit any/any on OUTSIDE_IN`)

Create the pull request.

**What you should see, in this order:**

1. **Actions.** Tab **Actions** (or the checks area on the PR). Job **Shift-Left Security Review** / `sovereign-review` runs on `self-hosted`. The last step prints `Review triggered. Findings will appear as a PR comment.` A red or missing job usually means the path did not match `terraform/**`, or `SHIFT_LEFT_TOKEN` is unset — `new-repo` sets that secret.
2. **Commit status.** On the head SHA, context **`shift-left/gate`**, state **failure**. Description starts with `Block policy decision is active`.
3. **PR comment.** Posted after review. Shape:

```
## A. Policy decision (deterministic)

**Policy decision:** `block` (advisory gate signal — **not a compliance verdict**)

_PR policy decision 'block' from … matched finding(s) …_

## B. Handler findings (deterministic)

**1 handler finding(s) for review:**

### 1. Deterministic rule: ASA-001
- **Source:** `handler` | … | **Policy severity:** `block` | …
- **Location:** `terraform/edge.rules:1-1`
- **CWE (handler rule):** `CWE-284`
- **Description (model):** ASA ACL permit ACE allows any source to any destination.
```

`trace` in the comment is `handler:ASA-001`. Advisory model prose is omitted from the comment by default.

Back in Shift-Left **Config changes**, a new row appears for `edge-asa` with Validation `blocked_by_policy` and Gate `blocked`.

## 6. Read the finding in the UI

Open the `edge-asa` change (`/ui/pr/{owner}/edge-asa/{n}`).

| What to look for | Where it is | Expected |
|------------------|-------------|---------|
| Rule ID | Finding title | `Deterministic rule: ASA-001` |
| CWE | Line under the title | `handler CWE-284` |
| Policy | Same panel | `BLOCK` |
| Resolved values | Finding description, plus the highlighted ACE in **Current vs proposed** | Description: `ASA ACL permit ACE allows any source to any destination.` The parser already resolved `any` / `any` (this ACE has no object-groups). The line `access-list OUTSIDE_IN extended permit ip any any` is highlighted. |
| Remediation | Registry text (not a separate field on this page) | Restrict source and destination to required networks and ports. Full platform table: [supported-platforms.md](supported-platforms.md). |

The finding panel also has a **Waiver reason** textarea (needed in step 8) and, if your token includes `triage`, a status form. Do not waive yet.

**Separation of duties.** Recording an approval or a BLOCK-level waiver normally requires a **second actor**: the token actor must not match the git commit author (compared case-insensitively). The bootstrap operator token uses actor `admin`; commits you push are usually attributed to your git `user.name` or `shiftleft-admin`, so they often do not collide.

If the page shows `Separation of duties: you are the commit author for this SHA` and you are the only operator:

1. Mint a token with a different `--actor` and log in as that actor, **or**
2. Open **System → Config** ([http://127.0.0.1:8080/ui/system/config](http://127.0.0.1:8080/ui/system/config)), check **Allow self-approval (development only)**, type `ENABLE SELF APPROVAL`, and apply.

`rbac.allow_self_approval` disables separation of duties. A persistent banner appears. Unsuitable for production. To turn it off, uncheck the box and type `DISABLE SELF APPROVAL`.

## 7. Fix the config and watch BLOCK become PASS

Replace the ACE with a scoped permit (corpus clean example):

```bash
cat > terraform/edge.rules <<'EOF'
access-list INSIDE_OUT extended permit tcp 10.20.30.0 255.255.255.0 host 8.8.8.8 eq 443 log
EOF
git add terraform/edge.rules
git commit -m "Restrict OUTSIDE_IN any/any to scoped permit"
git push
```

Forgejo Actions runs again on `synchronize`.

**Expected after refresh:**

| Surface | Before fix | After fix |
|---------|------------|-----------|
| Policy decision | `BLOCK` | `PASS` |
| Handler findings | ASA-001 listed | **No findings recorded for this change.** |
| Workflow state | `blocked_by_policy` | `awaiting_approval` |
| Next action | Resolve findings… | A different authorized reviewer must approve this commit SHA. |
| `shift-left/gate` | failure, policy block | still **failure**, description `Human approval required for deployment — none recorded for this commit SHA.` |
| Gate panel | Non-allowing (policy block) | Non-allowing (approval required) |

A policy **PASS** is not a merge allow. The commit status stays red until a human with `approve` records approval **for this SHA**. That is intentional.

Click **Record human approval for \<short sha\>** (requires `approve`, and a non-author actor unless self-approval is on).

**Expected after approval:**

- Gate: **Approved path — gate allowing**
- Reason: `Approval recorded for this commit SHA and policy gate satisfied.`
- Workflow state: `approved`

The Forgejo check `shift-left/gate` is rewritten when a **review** runs (each push). Approving in the UI does not by itself republish that check. **Commit status — Forgejo vs orchestrator** on the same page shows both; a discrepancy after UI-only approval is expected. To republish without another commit:

```bash
curl -sS "http://127.0.0.1:8080/api/v1/gate/OWNER/edge-asa/PRN?commit_sha=HEADSHA" \
  -H "Authorization: Bearer $SHIFT_LEFT_UI_TOKEN"
```

Set `SHIFT_LEFT_UI_TOKEN` to the same `slt_` token you signed in with. Use the owner, PR number, and full head SHA from the change page. Success JSON has `"allowed": true` and `"reason": "Approval recorded for this commit SHA and policy gate satisfied."`

A later commit on the same PR invalidates that approval. The commit table marks the new head as invalidating the bound SHA.

## 8. Reintroduce the violation and waive it

Restore the permissive ACE and push:

```bash
cat > terraform/edge.rules <<'EOF'
access-list OUTSIDE_IN extended permit ip any any
EOF
git add terraform/edge.rules
git commit -m "Reintroduce any/any for waiver walkthrough"
git push
```

Review runs again. Policy is **BLOCK**, ASA-001 is back, `shift-left/gate` is **failure** (policy block). The previous approval does not apply to this SHA.

On the finding, the reason field is **required** (browser `required`, and the API rejects an empty reason with `Waiver requires a non-empty reason.`). BLOCK waivers need the **`approve`** capability. Enter a real sentence — for example `Lab fixture; scoped permit follows in the next change.` — and **Grant waiver for this finding**.

**Expected:**

- Finding remains on the page with a **WAIVED** badge, the reason, and the actor. Waiver does not hide the defect.
- Effective policy becomes **PASS** (explanation notes that 1 finding was waived for this commit).
- Gate is still **Non-allowing** until someone approves this SHA (`Human approval required…`), same as step 7. Waiver is not a substitute for SHA-bound approval. Forgejo `shift-left/gate` may still describe the pre-waiver policy block until the next review or a `GET /api/v1/gate/…` republish.

Push one more commit so the SHA changes:

```bash
echo "! waived ACE still present — new SHA" >> terraform/edge.rules
git add terraform/edge.rules
git commit -m "Touch file to invalidate waiver"
git push
```

**Expected:** the waiver bound to the prior SHA expires (`New commit <sha> landed — waiver bound to prior SHA expired.`). ASA-001 is **not** waived on the new head. The grant form is back. Policy is **BLOCK** again.

That is the full loop: block on a finding you introduced, pass after a real fix, then waive with a reason and see the waiver die on the next commit.

## What next

- **Existing tree.** `./shift-left import-config <path>` prints which files match `routing.config_globs` and which would be skipped. It is a **preview**, not an import — copy the tree into a Forgejo repo that already has the review workflow (`./shift-left new-repo` or the files `new-repo` installs).
- **Code investigation.** After Antares is installed, launch from **Investigations** in the UI (repo, ref, CWE). Setup and behavior: [antares-triage.md](antares-triage.md). Not part of the merge gate.
- **Platforms and rules.** [supported-platforms.md](supported-platforms.md) (ASA, FTD/FMC, IOS-XE, NX-OS, generic Terraform) and [writing-rules.md](writing-rules.md). Gate semantics: [gate-enforcement.md](gate-enforcement.md). Tokens: [auth-tokens.md](auth-tokens.md).

Foundation-Sec can annotate findings with advisory prose. It is off the path above: extra latency, and on this ASA fixture it does not add handler findings.
