# Discovery: n8n 2.28.6 public API (n8n-new dev)

Author / Agent: Claude Code (Opus 5.5)
Timestamp: 2026-10-20

Status: **Phase 0A done (OpenAPI spec). Phase 0B pending: live responses with an API key.**

## 0A. Source and method

- Source: `https://n8n.dev.btn.co.id/api/v1/openapi.yml`, served by the running dev instance (n8n 2.28.6, public API v1.1.1). Read without authentication, GET only.
- Nothing was created, changed or published.

### Endpoints inspected (from the spec)

| Endpoint | Scope | Used by the service |
|---|---|---|
| `GET /workflows` (`active`, `projectId`, `tags`, `name`, `limit`, `cursor`, `excludePinnedData`) | `workflow:list` | poller |
| `GET /workflows/{id}` (`excludePinnedData`) | `workflow:read` | publish, versions, rollback |
| `GET /workflows/{id}/{versionId}` | `workflow:read` | published name when a newer draft exists |
| `PUT /workflows/{id}` | `workflow:update` | rollback |
| `POST /workflows/{id}/activate` (body optional: `versionId`, `name`, `description`) | `workflow:activate` | rollback |
| `POST /workflows/{id}/deactivate` | `workflow:deactivate` | not used |
| `GET /users`, `GET /projects` | | discovery script only |
| `/source-control/pull` | | not used (licensed feature) |

### Fields relevant to the design (spec)

- Workflow: `id`, `name`, `active` (read-only), `versionId` (read-only, *"current version identifier used for optimistic locking"*), `activeVersion` (read-only, nullable), `nodes`, `connections`, `nodeGroups`, `settings`, `staticData`, `pinData`, `meta` (read-only), `tags` (read-only), `shared`, `isArchived`, `triggerCount`, `createdAt`, `updatedAt`. Schema is `additionalProperties: false`.
- `activeVersion`: `versionId`, `workflowId`, `nodes`, `connections`, `nodeGroups`, `authors`, `createdAt`, `updatedAt`. **No `name`, no `settings`.**
- `workflowVersion` (`GET /workflows/{id}/{versionId}`): `versionId`, `workflowId`, `nodes`, `connections`, `nodeGroups`, `authors`, `name`, `description`, `createdAt`, `updatedAt`.
- `sharedWorkflow`: `role` (e.g. `workflow:owner`), `workflowId`, `projectId`, `project {id, name, type}`.
- Node credentials: `credentials.<type> = {id, name}`. No secret values in the workflow schema.
- `POST /activate` is documented as **"Publish a workflow. In n8n v1, this action was termed activating a workflow."**
- `PUT /workflows/{id}`: *"If the workflow is published, the updated version will be automatically re-published."*
- `workflowSettings` accepted keys: `saveExecutionProgress`, `saveManualExecutions`, `saveDataErrorExecution`, `saveDataSuccessExecution`, `executionTimeout`, `errorWorkflow`, `timezone`, `executionOrder`, `callerPolicy`, `callerIds`, `timeSavedPerExecution`, `redactionPolicy`.
- Node accepted keys: `id`, `name`, `webhookId`, `disabled`, `notesInFlow`, `notes`, `type`, `typeVersion`, `executeOnce`, `alwaysOutputData`, `retryOnFail`, `maxTries`, `waitBetweenTries`, `continueOnFail`, `onError`, `position`, `parameters`, `credentials`, `customTelemetryTags`.

## Conclusions (implemented)

| Question | Answer (from spec) |
|---|---|
| Draft vs published | top-level `versionId` = current draft; `activeVersion.versionId` = published snapshot. `activeVersion.versionId != versionId` means an unpublished draft exists. Autosave changes only `versionId`. |
| Detect "user clicked Publish" | No publish event/webhook in the public API. **Poll** `GET /workflows` and compare `activeVersion.versionId` with in-memory state (never `updatedAt`). |
| Owner | `shared[]` entry with `role = workflow:owner` → `project.name` / `project.id`. |
| Restore | `PUT /workflows/{id}` with `name`, `nodes`, `connections`, `settings` (read-only fields omitted, keys filtered to the schema). |
| Make restored version published | `POST /workflows/{id}/activate {"versionId": <versionId returned by PUT>}`; then verify `activeVersion.versionId`. |
| Public API only? | Yes: no DB, no encryption key, credential references stay as `{id, name}`. |
| Enough for polling? | Yes, if the list response contains `activeVersion` (see 0B-1). Otherwise the service reads the detail for workflows with `active=true` (implemented fallback). |

## 0B. To verify with a live API key (STOP-boundary)

Run (read-only, GET only, the key is never printed or stored):

```bash
cd /Users/macbook/Documents/n8n-git-service
export N8N_BASE_URL=https://n8n.dev.btn.co.id
read -rs N8N_API_KEY && export N8N_API_KEY      # paste the key, nothing is echoed
./scripts/discover.sh > /tmp/n8n-discovery.md
unset N8N_API_KEY
```

Then paste `/tmp/n8n-discovery.md` (it contains structure, ownership names and version ids, no node parameters).

| # | Check | Why it matters | If it fails |
|---|---|---|---|
| 1 | `GET /workflows` items contain `activeVersion` | cheap polling | fallback already implemented (detail GET for `active=true`) |
| 2 | items/detail contain `shared[].project.name` | owner → repo mapping | **STOP**: mapping must move to `projectId` or `/users` lookup |
| 3 | personal project name of "admin psa" / "gen-ai itpd" | exact `n8nUser` key in OWNER_MAPPINGS | adjust OWNER_MAPPINGS (name, email or project id are all accepted) |
| 4 | `GET /workflows/{id}/{activeVersionId}` returns `name` | published name when a draft exists | name falls back to draft name (documented limitation) |
| 5 | inactive workflows: `activeVersion: null` | never committed | **STOP** if inactive workflows carry an activeVersion |
| 6 | settings keys in real responses ⊆ accepted list | PUT must not 400 | extend the allow-list in `internal/workflow/sanitize.go` |
| 7 | node keys in real responses ⊆ accepted list | PUT must not 400 | extend `allowedNodeKeys` |

### Needs a write test (manual, on a throw-away workflow in dev; not done by the script)

1. Create a test workflow owned by "admin psa", publish it, call `POST /api/v1/workflows/<id>/publish` on the service, check the commit.
2. Change + publish twice (B, C). Call rollback to B with `expectedPublishedVersion` = current `activeVersion.versionId`.
3. Check in n8n: the workflow shows the B content as published; `PUT` returned a new `versionId`; `activate` made it `activeVersion`.
4. Wait one `POLL_INTERVAL`: GitLab shows a new commit D whose content equals B.

## 0B results

`scripts/discover.sh` has not been run yet. Observed on the live dev deployment (2026-10-20, service logs + committed files in `n8n-pluto`):

| # | Result |
|---|---|
| 1, 5 | Poller found published workflows and skipped unpublished/unmapped ones (list + detail path works). |
| 2, 3 | Owner names match `OWNER_MAPPINGS` as configured: `admin psa` → `n8n-pluto`, `gen-ai itpd` → `n8n-ai` (owner project name contains these names). |
| 4 | **Differs from the spec**: `GET /workflows/{id}/{versionId}` returns `name` = version label (`Version 3ae8d960`), not the workflow name. The first build used it when a draft existed, so three files in `n8n-pluto` got `"name": "Version …"`. Fixed: the name now always comes from the workflow object; the next reconcile (pod restart, `SYNC_ON_STARTUP=true`) commits the corrected names as new commits. |
| — | Stored files: keys `id, name, nodes, connections, settings[, meta]`, no forbidden fields, credential refs `{id, name}` only, canonical format. |
| — | GitLab: the protected branch `main` initially rejected Developer pushes (`403 You are not allowed to push into this branch`); fixed by allowing Developers + Maintainers to push (force push stays off). |

Still not verified: PUT + activate (rollback) against the real n8n, and settings/node keys accepted by PUT on real workflows.

## Editor-internal history API (frontend bundle of 2.28.6, read-only inspection)

Used by the history proxy (`internal/historyproxy`). These endpoints are **not** part of the public API:

| Call | Endpoint |
|---|---|
| list | `GET /rest/workflow-history/workflow/{id}?take&skip` → `{data:[{versionId,name,description,authors,createdAt,updatedAt,workflowId,workflowPublishHistory[]}]}` |
| get | `GET /rest/workflow-history/workflow/{id}/version/{versionId}` → `{data:{...,nodes,connections,nodeGroups}}` |
| batch | `.../workflow/{id}/versions` |
| publish timeline | `GET .../workflow/{id}/publish-timeline` |
| rename | `.../workflow/{id}/versions/{versionId}` |

- **Restore** (`builder.store` `restoreWorkflow`) is client-side: get version, then `updateWorkflow(id, {nodes, connections, nodeGroups})` through n8n with the user's session.
- **Compare** also uses get version.
- Item index 0 is treated as "latest" (no Restore). "Published" badge = `versionId == activeVersionId`.
- The "limited to 1 day" footer is computed from `/rest/settings` `workflowHistory.licensePruneTime`; pruning itself is server-side.
- Sessions: cookie `n8n-auth` bound to the `browser-id` header (localStorage `n8n-browserId`).
- No CSP on the editor HTML; ingress-nginx snippets are disabled in the cluster (plain path Ingress only).
