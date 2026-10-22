# Team collaboration for n8n Community 2.28.6: feasibility audit

Author / Agent: Claude Code (Sonnet 5.5)
Timestamp: 2026-10-22
Scope: read-only audit. Nothing was implemented, deployed, pushed, or written to n8n. No Secret values, cookies, or API keys were read.

Evidence labels used throughout:
- **[OBSERVED]**: seen in this audit (repo, Helm, public unauthenticated GETs of the dev host, the editor's public JS bundle, the public OpenAPI spec).
- **[INFERRED]**: follows from observed facts plus general n8n behaviour, not tested here.
- **[UNVERIFIED]**: needs a test or a licensed/authenticated check (see §12).

Method for [OBSERVED] n8n facts: `GET https://n8n.dev.btn.co.id/rest/settings` (public, unauthenticated), `GET /api/v1/openapi.yml` (public), and static GETs of the editor bundle `/assets/*.js` (838 chunks, version 2.28.6). No authenticated call was made.

---

## 1. Executive conclusion

**CONDITIONAL GO, but not with the architecture the task hypothesised.**

| Approach | Verdict |
|---|---|
| **A. Control-plane only**: the service manages membership of a native n8n *team project* through the public API (`/projects`, `/projects/{id}/users`, `/workflows/{id}/transfer`). n8n itself enforces every permission. No browser traffic goes through the service for editing. | **Recommended. GO only if n8n's team-project feature with the Editor role is available on this instance (gate G1, §12 T0).** |
| **B. Data-plane proxy**: the service mediates the editor's private `/rest/*` calls so B can reach A's personal workflow. | **NO-GO.** n8n authorises each call against the session user, so the service would have to replace n8n's whole authorization layer, and several editor operations (manual run, push channel, credential/parameter lookups) cannot be performed on a user's behalf with the public API or a service key. |
| **C. Shared team login** (one n8n user per team) | Technically trivial, but loses individual identity. Fails the stated goal. Only a stop-gap. |

Decision path:
1. Run the read-only licence probe (T0). If team projects + Editor role work → build Approach A (small, low risk, native enforcement).
2. If they are unavailable → Approach A is impossible and B is unsafe → the feature is a **NO-GO on unmodified Community**; the options are a licence for the project feature, or accepting C.

The key reason A beats B: collaboration needs *n8n to believe B may touch A's workflow*. Only n8n's own sharing model can do that without impersonation. The service's job becomes "keep that model in sync with a reviewed team config", not "re-implement it".

---

## 2. n8n Community limitations (evidence)

| Fact | Label |
|---|---|
| Version 2.28.6, email/password login only. `oidc`, `saml`, `ldap` are `false` in the public settings. `authCookie.secure = true`. | [OBSERVED] |
| Public `/rest/settings` for unauthenticated callers returns only 8 keys; licence-dependent flags (projects, sharing, advanced permissions) are **not** visible without a session. | [OBSERVED] |
| The frontend has native workflow `share` (`PUT /workflows/{id}/share`), `transfer` (`PUT /workflows/{id}/transfer`), project membership (`POST/PATCH/DELETE /projects/{id}/users`) and `GET /projects/sharing-candidates`. Whether the *backend* allows them without a licence is not visible from the bundle. | [OBSERVED] routes, [UNVERIFIED] licensing |
| Public API v1 exposes `/projects`, `/projects/{id}/users` (POST/PATCH/DELETE/GET), `/workflows/{id}/transfer`, `/credentials/{id}/transfer`, `/users`, `/users/{id}/role`. The spec does not mention a licence requirement for projects (it does for source-control and n8n-packages). | [OBSERVED] |
| Community has only the global roles owner and member; granting "admin" to everyone is licensed and is forbidden by this task anyway. | [INFERRED] |
| Native isolation between users (workflow in a *personal* project is invisible to others, `GET /rest/workflows/{id}` is refused for non-members) is what the existing history proxy already relies on. | [OBSERVED] in `internal/historyproxy/proxy.go` (authorize = n8n answers 200) |
| The editor uses `GET /rest/workflows/{id}/collaboration/write-lock`, i.e. n8n has its own single-writer lock. Two members cannot edit the same workflow at the same moment; the second sees a lock. | [OBSERVED] route, [UNVERIFIED] behaviour on Community |

---

## 3. Editor endpoints and authorization behaviour

Routes below are extracted from the 2.28.6 editor bundle (prefix `/rest`). Auth for all of them is the `n8n-auth` cookie bound to the `browser-id` header. "Native check" is [INFERRED] from n8n's scope model (project role → scope) unless marked; confirm in T-tests.

| # | Need | Method and route | Native permission check | Needed for MVP |
|---|---|---|---|---|
| 1 | List workflows | `GET /workflows` (query: filter, select, sort, paging) | list is filtered to projects the user belongs to | yes |
| 2 | Search / filter | same route, `filter` JSON (`name`, `projectId`, `tags`, `parentFolderId`) | same | yes |
| 3 | Open workflow | `GET /workflows/{id}` | `workflow:read` via project role; refused otherwise | yes |
| 4 | Editor metadata | `GET /workflows/{id}/exists`, `/workflows/with-node-types`, `POST /node-types`, `GET /credentials/for-workflow?workflowId=`, `GET /active-workflows` | read scope | yes |
| 5 | Save draft | `PATCH /workflows/{id}` (carries `versionId`/checksum for optimistic locking) [bundle shows `updateWorkflow`; verb not extracted] | `workflow:update` | yes |
| 6 | Publish / unpublish | `POST /workflows/{id}/activate` (body: `versionId`, `name`, `description`), `POST /workflows/{id}/deactivate` (`expectedChecksum`) | `workflow:publish` / activate scope | yes |
| 7 | Run | `POST /workflows/{id}/run`; result delivered over the **push channel** tied to the session `push-ref` | `workflow:execute` | yes |
| 8 | Executions | `GET /executions`, `GET /executions/{id}`, `GET /workflows/{id}/executions/last-successful`, `POST /executions/{id}/stop|retry` | `workflow:read` on the workflow | nice to have |
| 9 | Credentials used by nodes | `GET /credentials/for-workflow`, `GET /credentials/{id}` | `credential:read` via credential's project/share | yes (blocker, §8) |
| 10 | Credential pickers | `GET /credentials?filter=...`, `POST /credentials/test`, `POST /dynamic-node-parameters/*` | credential scope; dynamic params *use the credential on the server* | yes |
| 11 | Tags, folders, projects | `GET /tags`, `GET /projects/{id}/folders*`, `GET /projects/my-projects`, `/projects/personal`, `/projects/count` | project membership | yes |
| 12 | Collaboration | `GET /workflows/{id}/collaboration/write-lock`, push channel | n/a | yes |
| 13 | Identity | `GET /login`, `PATCH /me`, `POST /logout` | session only | yes |
| 14 | History | `/workflow-history/workflow/{id}...` | native 200 on `GET /workflows/{id}` (service-enforced today) | already served |

Is access to another user's personal workflow natively rejected? Expected yes for non-members [INFERRED]; **to be confirmed by T-N1**. Public API endpoints are **not** interchangeable with these private routes: different auth (API key vs session cookie), different response shapes (the private `GET /workflows/{id}` carries editor-only fields, `checksum`, `homeProject`, `scopes`), and the public API has **no run endpoint and no push channel** [OBSERVED: spec path list].

---

## 4. Session and user identity

- **[OBSERVED]** `GET /rest/login` is the editor's "who am I / is my session valid" call. It needs only cookie plus `browser-id`; it is independent of any workflow. It returns the current user (id, email, role) [INFERRED shape, T-I1 verifies].
- Stable identifier: n8n user **id** (UUID). Email is also unique but can be edited by the user via `PATCH /me` [INFERRED]. Team config should key on the user **id** (resolved once from email via the public `GET /users`), and the reconciler should re-resolve when an id is unknown.
- Forwarding: only `Cookie: n8n-auth=<value>` and `browser-id`. The existing proxy already does exactly this and drops everything else ([OBSERVED] `upstream()`).
- 401/403 from `/rest/login` = expired or invalid session → deny, never fall back to a service identity.
- CSRF/origin: n8n relies on the SameSite cookie plus the `browser-id` binding [INFERRED]; any state-changing route added to the service must reject missing `browser-id`, validate `Origin` equals the n8n host, and never use GET for writes.
- Redirects: the existing client disables redirects (`ErrUseLastResponse`) [OBSERVED]; keep that.
- No blocking identity issue was found. Under Approach A the service does not need browser identity at all (membership is managed server-side from config).

---

## 5. Ingress-compatible proxy feasibility (Approach B)

[OBSERVED] today: a second Ingress on host `n8n.dev.btn.co.id` with `pathType: Prefix` path `/rest/workflow-history` (`helm-values/.../n8n-git-service/values-env-dev.yaml`), snippets disabled, `proxy-body-size: 1m`, `proxy-read-timeout: 60`. n8n's own Ingress owns `/`. Longest prefix wins.

| Question | Finding |
|---|---|
| Route precedence | Works only for **prefixes**. Editor routes are `/rest/workflows/{id}/...` mixed with routes that must stay on n8n. To intercept `/rest/workflows/{id}/activate` alone you need regex paths (`use-regex`), which makes every `/rest/workflows*` request depend on the service. [INFERRED] |
| Same host / cookie | Yes, same host, cookie is retained. |
| Would native checks reject B on A's workflow? | Yes [INFERRED]. So the service would have to call n8n as someone else. |
| Mediate with the public API? | Possible for list/get/save/activate. **Impossible for run, push, dynamic-node-parameters, credential tests** (no public equivalent, and they execute *as the session user*). |
| Privileged identity | Using the service API key for browser-originated operations makes the service the sole authorizer; forwarding an admin cookie is forbidden. Result: re-implement list, search, get, save, activate, deactivate, executions, credentials, folders, tags, projects, push, node-types with a response shape the frontend accepts, and re-verify on each n8n upgrade. |
| Response/request formats | Private shapes (`checksum`, `homeProject`, `scopes`, `sharedWithProjects`) must be synthesised; a wrong `scopes` array breaks the UI. |
| Unrelated `/rest/*` | Fail-open pass-through to n8n is possible (done today), but a regex Ingress adds a failure domain to every editor save. |
| History proxy still works? | Yes in both approaches; today it authorises via native `GET /workflows/{id}` and keeps doing so. |

Conclusion: B is **not feasible safely**. It would need 15 or more private routes, a WebSocket/SSE path, and a complete authorization layer to avoid privilege escalation. Rejected.

---

## 6. Proposed architecture and request flow (Approach A)

```
 config TEAMS (ConfigMap)           n8n public API (X-N8N-API-KEY, in-cluster)
   team -> n8n project, members     GET /users, GET /projects/{id}/users
        |                           POST/PATCH/DELETE /projects/{id}/users
        v                           PUT /workflows/{id}/transfer (optional, explicit)
 n8n-git-service: reconciler  ---->
   (runs next to the poller, dry-run first, audit-logged)

 Browser A/B/C  ---------------->  n8n editor (unchanged)  -- native RBAC on every /rest/* call
                                    \--> /rest/workflow-history/* -> service (unchanged)
```

Flow:
1. Admin creates the team project once in n8n (UI) and records its id in config.
2. Reconciler resolves member emails to n8n user ids, then diffs against `GET /projects/{id}/users` and applies: add as `project:editor`, remove users not listed, never touch the project owner/admin.
3. A creates workflows directly in the team project (or moves an existing personal workflow with the native "Move" action, or the service transfers it on explicit request).
4. B and C open it natively. List, open, edit, save, run, publish, executions, folders, tags are all n8n's own behaviour.
5. No new public Ingress, no browser-facing endpoint, no API key exposure.

---

## 7. Team model and storage

Recommended: **static configuration**, same mechanism as `OWNER_MAPPINGS` (ConfigMap env, validated at start, no database).

```json
TEAMS=[{"id":"team-1","projectId":"<n8n team project id>",
        "members":["a@btn.co.id","b@btn.co.id","c@btn.co.id"],
        "role":"project:editor"}]
```

- One team per user in the MVP (config validation rejects an email in two teams). n8n itself supports multi-project membership, so this is a policy choice, not a platform limit.
- A workflow lives in exactly one project; "share across teams" means native workflow share, which is **[UNVERIFIED]** licensing and out of MVP scope.
- Membership changes = ConfigMap change → ArgoCD → pod restart → reconcile. Revocation latency is one reconcile; add `TEAMS_RECONCILE_INTERVAL` (e.g. 60s) for drift repair.
- No DB: audience is tens of users, changes are rare and reviewed in git. Revisit only if teams must be self-service.
- Roles: all members `project:editor` (can edit, run, publish per n8n's editor role); membership administration stays with the config owners (git review) and the service key, never with members. Stricter option if publishing needs control: keep `project:editor` for edit/run and restrict publish to a listed subset (only expressible if n8n's role scopes allow it, [UNVERIFIED]); otherwise accept.

---

## 8. Credentials and execution

| Question | Finding |
|---|---|
| Can B open A's workflow? | Yes once in the same project [INFERRED]. |
| Do credential references render? | References are `{id, name}` only. If the credential lives in A's **personal** project, B sees it as inaccessible/unknown and the node shows an error [INFERRED, T-C1]. |
| Credential picker lists? | Only credentials B can access (own, or in the team project) [INFERRED]. |
| Does save preserve references? | Yes, ids are kept in node JSON; n8n may still reject save for inaccessible ones [UNVERIFIED]. |
| Does run use the intended credentials? | Execution uses credentials by id on the server; if B cannot access them the run fails. If they are moved to the team project, **every editor can exercise them**, including by editing a node (HTTP Request to an arbitrary URL, Code node) [INFERRED]. |
| Execution data | Visible to all project members, including input/output data of nodes. Pinned data lives in the workflow JSON and is also visible. |
| Safe credential sharing without n8n changes? | Partially. Credentials intended for the team must be **created in or transferred to the team project** (`PUT /credentials/{id}/transfer`, native). The service never sees secret values. |

**Blocker to flag (B-CRED):** a powerful personal credential (production DB admin, cloud key) must **not** be moved to a team project that contains people who should not be able to use it. Team projects imply "every editor can use every credential in the project, and can read data it fetches". This is a policy decision, not something the service can mitigate. Mitigation: dedicated least-privilege team credentials, separate team projects for sensitive credentials, Portal/n8n audit review.

---

## 9. Publisher identity for Git (investigation only)

| Source | Finding |
|---|---|
| Public API `activeVersion.authors` / `GET /workflows/{id}/{versionId}` `authors` | [OBSERVED in spec] lists authors of the *version* (editors), not necessarily who pressed Publish. |
| `GET /rest/workflow-history/workflow/{id}/publish-timeline` and `workflowPublishHistory[]` | [OBSERVED route and shape in the bundle and in `Merge()`]; entries carry `event`, `versionId`, `userId`, `createdAt`. Best candidate: the exact actor. Needs a user session (not available to the poller). |
| `POST /rest/workflows/{id}/activate` request | Contains the session but proxying it requires the regex Ingress risk described in §5. Not recommended. |
| n8n audit / log streaming | `POST /audit` in the public API is a *security risk report*, not an event log. Log streaming is not exposed here. [INFERRED] |

Recommendation (later phase, least invasive): write the publisher as a **git commit trailer** (`Published-By: <email>`) next to the existing `N8n-Version-Id` trailer, so the JSON format and version semantics stay unchanged. Source order: (1) publish-timeline `userId` captured **opportunistically** when any member opens the Versions panel (the history proxy already holds a valid session at that moment; map `userId` to email via the public `GET /users`, and attach by amend-free follow-up note/GitLab commit comment since commits are immutable); (2) fall back to `activeVersion.authors` labelled "last editor". Verify with test T-P1 whether `userId` is populated on Community before committing to this.

---

## 10. Threat model and required controls

| Threat | A (control-plane) | Required control |
|---|---|---|
| Cross-team enumeration / guessing a workflow id | n8n enforces; service adds nothing | T-N1, T-N3 |
| Unauthorised edit/publish/run/delete/credential use | native RBAC | T-N-series |
| Privileged API key abuse | key stays in the pod, no browser route uses it | keep key out of logs; consider a dedicated owner-scoped key for the reconciler; audit every membership mutation |
| Config tampering (adding a user to a team) | config in git, ArgoCD | MR approval for `TEAMS`; reconciler dry-run diff logged |
| Over-removal (bad config empties a team) | reconciler could remove everyone | guardrails: refuse a diff that removes more than N users, never remove project owner/admin, `TEAMS_DRY_RUN=true` first |
| Session replay/fixation, cookie leakage | unchanged (n8n's) | service never stores cookies (existing rule) |
| CSRF / route confusion / header spoofing | no new browser-facing writes | none in A; mandatory `Origin`+`browser-id` check if any is added |
| Cache isolation | existing authz cache is keyed `sha256(cookie|browser-id|workflowId)` ([OBSERVED]) | keep; TTL 30s bounds revocation lag |
| Membership change / revoked access | next reconcile removes; native session continues until removal is applied | reconcile interval; also deactivate user if leaving the company |
| Exposure of workflow and execution data | all editors see all team data | §8 policy |
| Git history split | see risk R3 | mapping decision before rollout |

A negative check is enforced by n8n for every operation because every operation stays a native n8n request; this is the main security argument for A over B.

---

## 11. Can the native editor remain unchanged? Risks and unsupported items

- Editor: **unchanged** under A. No Ingress change, no image change, no n8n config change.
- Risks and unsupported:
  - **R1 Licence gate (G1).** Whole approach depends on project membership with the Editor role being enabled. [UNVERIFIED] Highest uncertainty.
  - **R2 Credentials (B-CRED).** See §8.
  - **R3 Git mapping breaks for team projects.** `OWNER_MAPPINGS` matches the *owner project name*. A workflow moved to "Team 1" has owner project "Team 1", which is not mapped, so the poller **skips it** and `GitHistory` returns *unmapped* ([OBSERVED] `owner.go`, `history.go`). Fix is configuration only (add a mapping for the team project name plus a GitLab repo), but the commits made before the move stay in the old repo and are not shown in the Versions panel afterwards. Decide the repo per team before moving workflows.
  - **R4 Single writer.** n8n's write-lock limits simultaneous editing.
  - **R5 Workflow in one project only**; cross-team sharing unsupported in MVP.
  - **R6 Private route dependence** stays as today (history proxy only).
  - **R7 Project-membership drift** if admins also edit members in the UI: define the service as source of truth or run in report-only mode.
- Operational complexity: low (one reconcile loop, one env var, no new infra).

---

## 12. Test plan (dedicated test users, disposable workflow; every write test needs your approval first)

Accounts: `test-a`, `test-b`, `test-c` (Team 1), `test-x` (not in any team). Disposable team project `test-team-1`. Disposable workflow "ZZ collab test" with a Manual Trigger and a Set node, **no credentials** for the first pass.

**Read-only gate (safe now, no approval needed):**

- **T0 licence probe.** As the instance owner, in the UI check *Projects → Add project* and, in the project settings, whether a member can be added with role **Editor**. Or with a key (key never printed): `curl -s -o /dev/null -w '%{http_code}\n' -H "X-N8N-API-KEY: $KEY" https://n8n.dev.btn.co.id/api/v1/projects`. 200 plus the Editor role selectable = G1 passed. A "licence required" or 403 = G1 failed, stop (see §1).
- **T-I1 identity.** In a logged-in browser's DevTools, copy only the JSON *shape* of `GET /rest/login` (no cookie) to confirm `id`/`email`.

**Positive tests (after approval, team project exists and reconciler or UI added B and C as Editor):**
1. A creates the workflow inside `test-team-1`.
2. B lists workflows and sees it (the same id as A).
3. B opens it in the editor (T-open).
4. B edits a node, saves (T-edit/save). A reloads and sees B's change.
5. B publishes (T-publish). Check n8n shows it active and the Git poller (if `test-team-1` mapped) commits.
6. C runs it manually and sees the execution; B sees the execution too.
7. B opens the Versions panel: it works through the existing history proxy (no change).
8. Concurrent edit: A and B open the same workflow; confirm the write-lock behaviour.

**Negative tests:**
- **T-N1** `test-x` (non-member) cannot see the workflow in the list.
- **T-N2** `test-x` direct `GET /rest/workflows/<id>` is refused (403/404), also for `/rest/workflow-history/workflow/<id>` (service passes n8n's refusal through).
- **T-N3** guessing a workflow id (random UUID-like) returns the same refusal as a missing workflow.
- **T-N4** expired/logged-out session: `GET /rest/login` is 401, history proxy 401.
- **T-N5** remove B from config; after one reconcile B can no longer open it (note the delay).
- **T-N6** personal workflow of A stays invisible to B.

**Credential tests:** T-C1 node uses a credential in A's personal project: B opens, sees the inaccessible credential. T-C2 same credential moved to the team project: B can run it (and note it can be reused for other nodes). T-C3 B tries to reference an unknown credential id.

**Publisher test:** T-P1 B publishes, then read `publish-timeline` as B and check that `userId` equals B.

---

## 13. Exact files for a future implementation (do not touch now)

`n8n-git-service` repo:
- `internal/config/config.go` (new `TEAMS`, `TEAMS_ENABLED`, `TEAMS_DRY_RUN`, `TEAMS_RECONCILE_INTERVAL`, validation, one team per user)
- `internal/n8n/client.go` (+ `ListUsers`, `ListProjectUsers`, `AddProjectUsers`, `RemoveProjectUser`, optional `TransferWorkflow`)
- `internal/teams/` (new: reconciler, diff, guardrails) plus tests and fakes in the style of `internal/service/fakes_test.go`
- `cmd/n8n-git-service/main.go` (wire the loop, same lifecycle as the poller)
- `internal/audit/audit.go` (membership operations)
- `api/openapi.yaml` and `README.md` (new section, change history row), `docs/discovery-n8n-2.28.6.md`

`app-of-apps`:
- `helm-values/platform-manifest/n8n-git-service/values-env-dev.yaml` (`TEAMS*` env, new `OWNER_MAPPINGS` entry for the team project)
- `helm-base/n8n-git-service/values.yaml` only if a default is needed
- **No Ingress change, no n8n chart change, no Secret change** (the existing key is reused, scope to be confirmed: it must be allowed to manage projects).

GitLab: new repo or mapping under `platform/n8n-git-sync/` per team (decision R3).

## 14. Deployment and rollback

1. Merge with `TEAMS_ENABLED=false` (default). Deploy, confirm no behaviour change.
2. Enable with `TEAMS_DRY_RUN=true`: logs the planned diff only. Review.
3. Disable dry-run for one disposable team in dev; run §12.
4. Roll out to real teams only after G1, B-CRED and R3 decisions.

Rollback: set `TEAMS_ENABLED=false` (one values change). Membership already applied stays in n8n; undo by removing the members in the UI/API or by running the reconciler with an empty team. Workflows keep working, nothing is deleted; a transferred workflow can be moved back with the native "Move" action or `PUT /workflows/{id}/transfer`.

## 15. Outstanding decisions and blockers

| # | Item | Owner | Type |
|---|---|---|---|
| 1 | **G1: team projects with Editor role available on this instance?** (T0) | you (owner login) | **blocker** |
| 2 | Credential policy for team projects (B-CRED) | you / security | blocker for real use |
| 3 | Team project to GitLab repo mapping (R3); history split accepted? | you | decision |
| 4 | Who may change `TEAMS` (MR approvers) | you | decision |
| 5 | Is "all members may publish" acceptable, or restrict publishing? | you | decision |
| 6 | Does the existing API key have project-management scope; dedicated key? | you | check |
| 7 | Phase 2 publisher attribution (trailer vs GitLab commit comment; T-P1 result) | later | deferred |

**Recommended next phase:** run T0 and T-I1 (read-only), then, if G1 passes, a small dev prototype of the reconciler in dry-run mode plus the §12 positive and negative tests on the disposable project.

---

## 16. T0 / T-I1 execution log (2026-10-22)

Author / Agent: Claude Code (Sonnet 5.5)

| Check | Request | Result | Status |
|---|---|---|---|
| T-I1 | `GET /rest/login` from the Chrome profile `claude` (read-only, browser-id from localStorage, no cookie read) | **401**, the profile is not signed in to n8n (page redirected to `/signin`) | **NOT RUN**: no authenticated session available |
| T0 | `GET /rest/settings` (unauthenticated) | 200, 8 keys only; `enterprise` = saml/ldap/oidc false; no project, sharing or licence flags exposed | **INCONCLUSIVE** |
| T0 | `GET /api/v1/projects` with an API key | not run, no key available to this session | **NOT RUN** |

G1 is therefore **neither passed nor failed**. No credentials were entered and no write was made. Stopped before any implementation, as required.
