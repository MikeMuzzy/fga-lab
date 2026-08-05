# Container Admission Authorization — Design & Operating Guide

**Status:** design baseline · **Audience:** platform engineering, security engineering, access-review owners, and AI agents asked to modify this model.

**Files in this directory**

| File | Purpose |
|---|---|
| `model.fga` | The authorization model (types, relations, conditions) |
| `tuples/prod.yaml` | Reference tuple set — one worked example per relation |
| `store.fga.yaml` | CI assertion suite (`fga model test --tests store.fga.yaml`) |
| `README.md` | This document |

---

## 1. Problem

Users hold SSH access to a fleet of bare-metal hosts and create Podman containers on them. SSH access control is out of scope. What is in scope: constraining **what a user may run and how**, along seven axes.

| Axis | Value space | Mechanism | Why |
|---|---|---|---|
| Container image | unbounded | condition + anchored regex, or exact digest | cannot enumerate |
| Host mount source | unbounded | condition + prefix match, ro/rw | cannot enumerate |
| Linux capabilities | ~40, fixed by the kernel | first-class objects | enumerable |
| Devices | finite per host, physical | first-class objects | enumerable, host-bound |
| Sysctls | namespaced key space | condition + prefix / exact pin | large but structured |
| Namespace sharing (`pid`/`ipc`/`user`/`net` = host) | 4 booleans | one relation each | distinct approvals |
| Confinement removal (seccomp, AppArmor, SELinux, privileged) | 4 booleans | one relation each | distinct approvals |

The financial-industry constraints that shaped the answer: entitlements must be **time-boxed by default**, changes must be **reviewable and attributable**, authoring and granting authority must be **separable**, and a quarterly access review must be answerable from the store rather than from a spreadsheet.

---

## 2. The organizing principle

> **Relationships answer "who, on what, until when." Conditions answer "does this specific value match." Enumerable things become objects; unbounded things become conditions.**

OpenFGA cannot evaluate regex in the relationship graph — but its **Conditions** are CEL (cel-go), and CEL's `matches()` is Go's RE2. That gives the split above. Two RE2 facts govern everything downstream:

- **`matches()` is a search, not a full match.** An unanchored `registry.corp.example/base/ubi9` happily matches `evil.example/x/registry.corp.example/base/ubi9-backdoor`. Every pattern is `^…$`-anchored, and CI test **T-04** exists solely to catch a future edit that forgets.
- **RE2 has no backtracking.** ReDoS from policy-authored patterns is not a concern — a real advantage over PCRE for a system where patterns are configuration.

The counterpart rule is why capabilities and devices are *not* condition lists. A `list<string>` of capability names cannot answer "what can Alice use on this host?" without a full tuple scan plus client-side evaluation. As objects, `capability:prod/SYS_NICE` supports `ListObjects`, needs no CEL review, re-verifies host access on the same edge, and shows up in a recert report as a row.

---

## 3. Model shape and why

### 3.1 Two planes

Every relation belongs to exactly one of:

- **Data plane** — `may_*`, `can_*`, and the `grants_*` / `allows_*` / `holds` helpers they compose from. Queried by the broker on every container start. High volume, latency-sensitive.
- **Control plane** — `owner`, `approver`, `admin`. Queried by the policy-admin service before it writes tuples. Low volume, human-scale.

They are named differently on purpose so a call site cannot confuse them. Grep for `can_` and you have found every enforcement point.

### 3.2 `runtime_profile` is the unit of entitlement

The central decision: capabilities, sysctls and escalations attach to a **profile**, never directly to `host` or `environment`.

`CAP_NET_BIND_SERVICE` on a curated, digest-pinned base image is routine. The same capability on an arbitrary image is a primitive an attacker can compose with. Binding both to the same object keeps them welded together — you cannot grant the capability without also constraining the image it runs in.

The profile also gives the escalations a natural home: profile `lon-capture` means *this toolbox image, with these namespaces, for this incident window*, which is a reviewable sentence. "Team X has `--privileged` in prod" is not.

### 3.3 Why a named policy object instead of inlining conditions on the grant

You could write `group:payments-devs#member subject environment:prod` with `image_allowed` inline. Legitimate, and right for a one-off exception. Four reasons it is wrong as the default:

1. **One condition per tuple** — the hard constraint. Inline, you cannot have both `active_grant` (time-boxing *this grantee*) and `image_allowed` (matching *this image*) on the same tuple; you would weld expiry and pattern semantics into one condition. The `subject and image_pattern` intersection exists precisely so the two vary independently: revoke Alice without touching patterns, rotate patterns without re-issuing everyone's expiry.
2. **Writes are read-modify-write on the whole list.** Migrating `registry.corp.example` → `registry2.corp.example` across 200 groups inline is 200 non-atomic writes with partially-applied intermediate states, racing against concurrent edits (OpenFGA has no CAS on tuples). With policy objects it is one write — or better, a new object and a repoint, which is reversible.
3. **Impact analysis.** "Who can run `temurin-21` in prod?" is `ListUsers(runtime_profile:payments-web, subject)`. Inline, it is a full scan plus client-side regex over every group's list. Reviewers ask this quarterly, in writing.
4. **SoD.** The object carries an `owner` relation distinct from `subject`. Inline, whoever can write the grant can write the patterns — entitlement-granting authority silently implies pattern-authoring authority, which is exactly what an access-review finding looks like.

A profile can serve exactly one team; the indirection does not force sharing. The practical split: curated catalog profiles for the standing 90%, one team-scoped profile per team for their own images, inline conditions only on explicitly time-boxed exceptions.

### 3.4 The `subject and <rule>` intersection

`image_pattern` is a single `user:*` tuple carrying the pattern list. It evaluates to "everyone" when the image matches and "nobody" when it does not. Intersecting with `subject` yields *this user holds the profile **and** the image satisfies it*, without duplicating the pattern list per grantee.

Same shape for `sysctl_rule`, every `f_*` flag, and `mount_policy`'s `ro_rule`/`rw_rule`.

### 3.5 Guardrails always win

`guardrail` is attached at `environment:global`, owned by security, and applied through `but not`. Nothing downstream can override it. It is the CVE-recall and never-allowed mechanism: floating tags, the podman socket, `kernel.core_pattern`, quarantined digests.

The three former denylist types were merged into one `guardrail` type — identical shape, one owner, one attach point, so three attach relations collapse to one.

### 3.6 Two gates, not one

`may_create_container` (coarse, ambient context only) and `can_create_container` (enforcing, request context) are separate relations because **OpenFGA does not treat a missing context parameter as `false`** — the Check errors. You cannot reuse one relation with thinner context and hope it degrades.

The coarse gate is a sound fast-reject: it shares the `operator` edge and the same profile set, so a coarse `false` guarantees a fine `false`. It is also `ListObjects`-safe, which the enforcing relations are not (wildcard + intersection + exclusion expands badly).

**Never make the image condition tolerate a missing image** to unify them. One caller forgetting to populate context would become an authz bypass.

### 3.7 Escalations: eight relations, not one flag

Each of the eight is separately approved, separately revoked, separately visible in a review. Collapsing them into a `danger: bool` would make "who can share the host PID namespace?" unanswerable.

`grants_privileged` is not a peer of the others — it *subsumes* seccomp and LSM confinement, so it requires those grants. It deliberately does **not** require the namespace grants: `--privileged` in Podman does not change namespaces, and pretending otherwise would be factually wrong. The broker expands `--privileged` into the full capability set and checks each capability individually, so `banned` capabilities still apply.

`grants_lsm_off` is `apparmor_off OR selinux_off` because a host runs one LSM. AND-ing them would make `privileged` ungrantable on either distro.

### 3.8 Time-boxing by default

`subject`, `operator`, and every `f_*` are typed to admit a conditioned form. Escalations are typed **only** as `[user:* with escalation_window]` — there is no unconditioned way to grant one. `escalation_window` also shape-validates a `change_ticket`.

Consequence for the access review: standing entitlements get recertified quarterly; escalations do not need recertifying because they expire on their own, and each carries its ticket reference in the tuple. That pairing usually satisfies a reviewer who would otherwise demand a manual attestation per privileged container.

### 3.9 Ownership is typed `[group#member]`, never `[user]`

- **Leavers.** `user:alice owner ...` survives offboarding as a dangling tuple that no JML process knows to look for. Group membership is IdP-driven over SCIM, so removal is automatic and already audited.
- **Recertification asks about roles.** "platform-security owns the capability denylist" is certifiable. "alice owns it" is a fact about staffing, stale by next quarter.
- **Nesting.** `group#member` composes; a `user:` tuple is a leaf.
- **Bus factor.** Single-owner objects block on PTO, so someone adds a second individual "temporarily," permanently.
- **Blast-radius asymmetry.** `subject` is a scoped entitlement; `owner` is the right to *redefine* it for everyone holding it. Higher-privilege relations get the stricter type.

Break-glass is still a group — one with a single member and an alerting hook on membership change.

---

## 4. Request context semantics

Read this before touching any condition.

**Context is a flat, request-scoped bag.** It is not bound to the relation you asked about. OpenFGA walks the graph and, at each conditioned tuple, merges `tuple context ⊕ request context` into a CEL activation; the condition resolves only the identifiers it declares.

Three asymmetries:

| | Behaviour |
|---|---|
| **Undeclared keys** | Inert at Check. **Rejected at Write** — persisted state is validated strictly. |
| **Missing required key** | Evaluation **error**, not denial. The PEP fails closed and alerts: it means caller and model have drifted. |
| **Key collision** | **Tuple context wins.** A caller stuffing `allowed_patterns: ["^.*$"]` into the request cannot widen their own grant. |

That last row is load-bearing enough to be pinned by **T-13**, which must never be deleted.

**The hazard the flat namespace creates:** two conditions declaring `patterns` would both receive whatever single `patterns` value was sent — the mount check silently evaluating image patterns. Nothing in the model catches this. Hence the domain-prefix rule (§6, R4).

---

## 5. How to use it

### 5.1 Gate 1 — coarse, at session start

```go
c := map[string]any{"request_time": now.UTC().Format(time.RFC3339)}
r, err := fga.Check(ctx).Body(fga.ClientCheckRequest{
    User: "user:alice.chen", Relation: "may_create_container",
    Object: "host:hv-lon-01", Context: &c,
}).Options(fga.ClientCheckOptions{AuthorizationModelId: &pinnedModelID}).Execute()
```

Cacheable session-scoped for tens of seconds (round `request_time` — nanosecond precision destroys the cache hit rate). **A pass is never authorization.** Gate 2 runs on every create regardless.

### 5.2 Gate 2 — enforcing, at container create

Derive the requested feature set from the **resolved OCI spec**, not the CLI string: Compose files, Kube YAML and `containers.conf` defaults all inject these fields.

Then one `BatchCheck` with correlation IDs, so a denial says *which* thing was denied — useful to the user, required by the auditor.

```go
items := []fga.ClientBatchCheckItem{{
    CorrelationId: "image",
    User: req.User, Relation: "can_create_container", Object: req.Host,
    Context: &map[string]any{
        "request_time": now, "image_repo": req.ImageRepo,
        "image_tag": req.ImageTag, "image_digest": req.ImageDigest,
    },
}}
// + one item per mount   (can_mount_ro / can_mount_rw,  mount_source)
// + one item per sysctl  (can_set_sysctl,               sysctl_key, sysctl_value)
// + one item per cap     (can_add on capability:<env>/<CAP>)
// + one item per device  (can_use_ro / can_use_rw on device:<host>/<name>)
// + one item per requested escalation flag

res, err := fga.BatchCheck(ctx).Body(fga.ClientBatchCheckRequest{Checks: items}).
    Options(fga.ClientBatchCheckOptions{
        AuthorizationModelId: &pinnedModelID,
        Consistency:          &higherConsistency,   // revocations must bite immediately
    }).Execute()
```

Decision rules, in order:

1. **Shape-validate before any Check.** Absolute paths, no `..`, no NUL, capability names in the kernel's known set, device names `[a-z0-9_-]+`, bounded list lengths. CEL must never see adversarial input, and an unknown capability name must be *rejected*, not silently no-op'd.
2. **Expand `--privileged`** into the full bounding set and check each capability individually — never as one opaque flag, or `banned` stops applying.
3. **Any `false` → deny. Any evaluation error → deny.** Fail closed.
4. **Count the results.** `len(results) != len(items)` → deny; never infer allow from a partial response.
5. **Log the full allow/deny vector**, not just the verdict.
6. **Then apply the combination denies** (§5.3).

### 5.3 Combinations OpenFGA cannot express

A Check answers one question; "at most N of these together" is not one question. These are hard denies in broker code regardless of individual grants:

| Combination | Why |
|---|---|
| `host_pid` + `CAP_SYS_PTRACE` | read any host process's memory and environment — env-var secrets are gone |
| LSM off + rw host mount | labelling was the thing constraining the mount |
| `host_user` + rw host mount | writes land as the real uid; rootful broker means uid 0 |
| seccomp off + `CAP_SYS_ADMIN` | `mount`, `bpf`, `keyctl`, `userfaultfd` all reachable — treat as escape |
| `host_net` + any `net.*` sysctl | container does not own the netns; also a runtime error, better caught at admission |
| `host_net` + host loopback reachable | every unauthenticated admin port on the box is now in-container |
| `host_ipc` | attach to host shm segments — databases and JVMs keep live data there |

### 5.4 What is safe to enumerate

| Safe for `ListObjects` | Check-only |
|---|---|
| `may_create_container` | `can_create_container` |
| `holds` on `runtime_profile` | `can_mount_ro` / `can_mount_rw` |
| `can_add` (per capability, small fan-out) | `can_set_sysctl`, all eight escalations |

For a preflight UX — *"here's what you could run here"* — pair `ListObjects(user, may_create_container, host)` with `ListObjects(user, holds, runtime_profile)` and `Read` the `image_pattern` tuples to display the patterns. Rendering the allowed set from the same tuples that enforce it keeps the UI honest.

---

## 6. Rules for extending this model

For humans and for AI agents. Numbered so a PR review can cite them. Violating one requires an ADR in the PR description explaining why.

### Modelling

- **R1 — Enumerable → object; unbounded → condition.** If you can list every legal value and it changes rarely, make it a type. Only reach for `list<string>` when you genuinely cannot enumerate.
- **R2 — Anchor every regex `^…$`.** `matches()` is a search. CI rejects unanchored patterns; do not disable that lint.
- **R3 — Every path prefix ends in `/`.** The slash is the component boundary. Without it, `/srv/data` matches `/srv/data-of-someone-else`.
- **R4 — Prefix every condition parameter with its domain** (`image_*`, `mount_*`, `sysctl_*`). Request context is a flat namespace shared across all conditions on the path. Two conditions declaring `patterns` will silently cross-feed.
- **R5 — Never make a condition tolerate a missing value.** No `""` defaults that pass, no `require_x: bool` escape hatches on the enforcing path. Add a separate relation instead.
- **R6 — One relation per escalation.** Never a shared `danger` flag, never a `list<string>` of enabled escalations. Each must be independently grantable, revocable, and countable in a review.
- **R7 — Attach privilege to `runtime_profile`, not to `host` or `environment`.** Capabilities and escalations are only tolerable *because* of the image constraint they sit beside. Attaching them at scope "for convenience" decouples them from it.
- **R8 — New privilege gets a `guardrail` counterpart** if there is any value of it that must never be allowed anywhere.
- **R9 — Ownership relations are `[group#member]`.** Never `[user]`, never `user:*`.
- **R10 — Higher-privilege relations get stricter type restrictions,** not looser. If you are adding `user` to an `owner` type restriction, stop.
- **R11 — Do not add a relation that requires unbounded fan-out** (wildcard × intersection × exclusion) if anything will call `ListObjects` on it.

### Naming

- **R12 — `can_*` / `may_*` = data plane; `owner` / `approver` / `admin` = control plane.** `may_*` is a coarse pre-check that must never be treated as authorization; `can_*` is enforcing. Do not name a coarse relation `can_`.
- **R13 — Helper relations are `grants_*` (profile-side), `allows_*` (policy-side), `forbids_*` (guardrail-side), `f_*` (raw escalation flag).** They are composition intermediates and are never checked directly by the broker.
- **R14 — Object IDs are structured and stable:** `capability:<env>/<CAP>`, `device:<host>/<name>`, `runtime_profile:<team>-<purpose>`. IDs appear in audit records; do not encode mutable facts in them.

### Process

- **R15 — Every new relation ships with three tests:** an allow case, a deny case, and a **boundary** case (the near-miss that a naive implementation would let through). See T-04 and T-09 for the shape.
- **R16 — Never delete T-13.** It pins tuple-context precedence, the property the design rests on.
- **R17 — Pin `authorization_model_id` at every call site.** A model write is otherwise a silent global semantics change.
- **R18 — Separate store per environment.** Prod tuples and prod model rollouts must not share a blast radius with dev.
- **R19 — Model and tuples are code.** PR + CODEOWNERS + `fga model test` in CI. That review record is the four-eyes evidence.
- **R20 — Escalations must be time-boxed and ticketed.** If you add an `f_*` relation, type it `[user:* with escalation_window]` and nothing else.

### Things that are *not* this model's job

- **R21 — Four-eyes is a workflow property.** OpenFGA answers "may this one principal do it," has no notion of a pending change or of counting distinct approvers. Maker-checker lives in the admin service or the PR pipeline; `owner`/`approver` only define the eligible pools. Do not let a design review conclude the model gives dual control on its own.
- **R22 — Combination limits live in broker code** (§5.3), not the model.
- **R23 — Do not encode registry trust or signature verification here.** That is `policy.json` + sigstore. The condition cannot confirm a digest belongs to a repo; it only decides whether the policy permits a digest the broker vouches for.

---

## 7. Operating the model

**Separation of duties.** OpenFGA's Write API has no per-tuple authorization: anyone holding a store token can write anything. `owner` / `approver` / `admin` are controls **only if** every mutation funnels through the policy-admin service (or the GitOps pipeline's CODEOWNERS) and the raw store credential is held by nothing else. If engineers have direct store access, these relations are documentation.

Concretely:

| Who | May write |
|---|---|
| `runtime_profile.owner` (platform-eng) | `image_pattern`, `sysctl_rule` |
| `runtime_profile.approver` (platform-sec) | `f_*` — and only via the change pipeline, which verifies the ticket is open |
| team leads | `subject` on their own profiles |
| `mount_policy.owner` (storage-eng) | `ro_rule`, `rw_rule` |
| `environment.admin` (platform-sec) | `guardrail:*`, `capability:*` `banned` |

Four owners, four CODEOWNERS paths, four approval chains — which means the quarterly review produces four reports that four different people actually understand, rather than one nobody reads.

**Evidence.** Stream `/changes` to WORM storage; that is the entitlement change log for SOX / DORA. Recertification is `ListObjects(user, holds, runtime_profile)` plus a `Read` of the pattern tuples. Escalations are excluded from recert because `not_after` retires them automatically and each carries its ticket.

**Rollout.** Model changes go: dev store → assertion suite → UAT store → shadow-mode in prod (evaluate and log, do not enforce) → enforce. Pinning the model ID at call sites is what makes shadow mode possible: run the new ID alongside the old and diff the verdicts.

---

## 8. What this model does *not* secure

Stated plainly, because a design review will ask.

**The model is not the enforcement boundary.** Under rootless Podman, a user with a shell bypasses any wrapper — an OCI hook in their own `~/.config/containers` is advisory, not a control. The controls that actually hold:

1. **A broker daemon** holding the only Podman access, exposed over a unix socket, running these checks and invoking Podman under a service account. Users do not get direct Podman.
2. **The same entitlement enforced at the registry** (Harbor / Artifactory pull authz), with egress firewalled so no other registry is reachable.
3. **Sigstore verification** in `/etc/containers/policy.json`, plus `short-name-mode = "enforcing"` and empty `unqualified-search-registries` so nothing resolves ambiguously.
4. **Mount sources whose every path component is root-owned**, to close the symlink race between the broker's `realpath` and Podman's own resolution. `:O` overlay and `ro` reduce blast radius but do not close it.
5. **Resolve tag → digest before the check, create by `repo@sha256:…` after it.** Otherwise a tag can be repointed between Check and pull. `require_digest: true` makes this explicit in prod.

**Image canonicalization is part of the trust boundary.** `nginx`, `docker.io/nginx` and `docker.io/library/nginx` are the same image and only one form matches the pattern. Normalize with `containers/image/docker/reference`, lowercase, then check.

**Rootless bounds you today, not tomorrow.** Under rootless Podman the container's capabilities are bounded by the invoking user's set and device access by their DAC permissions, so a mistaken grant is often inert. Do not rely on it: with a rootful broker — which point 1 implies — that bound disappears and this model becomes the only control.
