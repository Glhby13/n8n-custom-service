#!/usr/bin/env python3
"""Check (and, without --check, prepare) the Keycloak side of the sign-in page with one-time codes.

What the sign-in page (auth-service) needs from Keycloak, for one OIDC client:
  1. Direct Access Grants enabled and a Direct Grant flow bound to the client that asks for a one-time code only when
     the user holds the client's admin role AND already has an OTP credential:
         Username Validation (REQUIRED) -> Password (REQUIRED) -> conditional sub-flow (CONDITIONAL):
             Condition - user role (REQUIRED, role = <client>.<admin role>), Condition - user configured (REQUIRED), OTP (REQUIRED)
  2. The client's service account holds realm-management view-users, query-users, manage-users, view-clients,
     query-clients (it registers the OTP credential and tells whether a login needs a code).

The script READS the flow (it never creates or edits it) and GRANTS the missing service-account roles (idempotent).
With --check it changes nothing and exits 1 when something is missing.

Env: KC_URL (default https://auth.lab.local)  KC_REALM (lab)  KC_CLIENT (n8n-lab)  KC_ADMIN_ROLE (n8n-admin)
     KC_ADMIN_USER (admin)  KC_ADMIN_PASSWORD (else lab/SECRETS.md when present, else asked on the terminal)
     KC_INSECURE=1 only for a self-signed lab certificate.
Usage: python3 -I keycloak_otp_setup.py [--check]
"""
import getpass, json, os, re, ssl, sys, urllib.error, urllib.parse, urllib.request

KC = os.environ.get("KC_URL", "https://auth.lab.local").rstrip("/")
REALM = os.environ.get("KC_REALM", "lab")
CLIENT = os.environ.get("KC_CLIENT", "n8n-lab")
ADMIN_ROLE = os.environ.get("KC_ADMIN_ROLE", "n8n-admin")
ROLES = ["view-users", "query-users", "manage-users", "view-clients", "query-clients"]
CTX = ssl._create_unverified_context() if os.environ.get("KC_INSECURE") == "1" else ssl.create_default_context()


def admin_password():
    if os.environ.get("KC_ADMIN_PASSWORD"):
        return os.environ["KC_ADMIN_PASSWORD"]
    secrets = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "SECRETS.md")  # lab layout only
    if os.path.exists(secrets):
        for line in open(secrets, encoding="utf8"):
            if "Admin console" in line and "realm `master`" in line:
                cells = re.findall(r"`([^`]+)`", line)
                if len(cells) >= 2:
                    return cells[1]
    return getpass.getpass("Keycloak admin password: ")


def call(method, path, token=None, body=None, form=None):
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(KC + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} -> HTTP {e.code}")


def check_flow(tok, base, client, problems):
    if not client.get("directAccessGrantsEnabled"):
        problems.append("Direct Access Grants is not enabled on the client")
    fid = (client.get("authenticationFlowBindingOverrides") or {}).get("direct_grant")
    if not fid:
        problems.append("no Direct Grant flow is bound to the client (Advanced > Authentication flow overrides)")
        return
    alias = next((f["alias"] for f in call("GET", f"{base}/authentication/flows", tok) if f["id"] == fid), None)
    if not alias:
        problems.append("the bound Direct Grant flow does not exist")
        return
    rows = call("GET", f"{base}/authentication/flows/{urllib.parse.quote(alias)}/executions", tok)
    print(f"flow {alias}:")
    seen = {}
    in_deny = False  # the optional "<flow>-deny-no-access" sub-flow (keycloak_require_access_role.py) is not part of the OTP steps
    for e in rows:
        if e["level"] == 0:
            in_deny = (e.get("displayName") or "").endswith("-deny-no-access")
        cfg = ""
        if e.get("authenticationConfig"):
            cfg = (call("GET", f"{base}/authentication/config/{e['authenticationConfig']}", tok).get("config") or {}).get("condUserRole", "")
        if not in_deny:
            seen[e.get("providerId") or e.get("displayName")] = (e["requirement"], cfg, e["level"])
        print("  " + "  " * e["level"] + f"{e.get('displayName') or e.get('providerId')}  [{e['requirement']}]" + (f"  role={cfg}" if cfg else ""))

    def need(provider, req, level, label):
        got = seen.get(provider)
        if not got or got[0] != req or got[2] != level:
            problems.append(f"flow {alias}: {label} must be {req} at level {level}")
        return got

    need("direct-grant-validate-username", "REQUIRED", 0, "Username Validation")
    need("direct-grant-validate-password", "REQUIRED", 0, "Password")
    role = need("conditional-user-role", "REQUIRED", 1, "Condition - user role")
    if role and role[1] != f"{CLIENT}.{ADMIN_ROLE}":
        problems.append(f"flow {alias}: the role condition is '{role[1]}', expected '{CLIENT}.{ADMIN_ROLE}'")
    need("conditional-user-configured", "REQUIRED", 1, "Condition - user configured")
    need("direct-grant-validate-otp", "REQUIRED", 1, "OTP")
    if not any(v[0] == "CONDITIONAL" and v[2] == 0 for v in seen.values()) and not any(
            e["requirement"] == "CONDITIONAL" and e["level"] == 0 and not (e.get("displayName") or "").endswith("-deny-no-access") for e in rows):
        problems.append(f"flow {alias}: the OTP steps must sit in a CONDITIONAL sub-flow")


def main():
    check = "--check" in sys.argv
    tok = call("POST", "/realms/master/protocol/openid-connect/token",
               form=dict(grant_type="password", client_id="admin-cli", username=os.environ.get("KC_ADMIN_USER", "admin"), password=admin_password()))["access_token"]
    base = f"/admin/realms/{REALM}"
    found = call("GET", f"{base}/clients?clientId={CLIENT}", tok)
    if not found:
        sys.exit(f"client {CLIENT} not found in realm {REALM}")
    client = found[0]
    problems = []

    check_flow(tok, base, client, problems)

    if not client.get("serviceAccountsEnabled"):
        problems.append("Service accounts roles is not enabled on the client")
    else:
        sa = call("GET", f"{base}/clients/{client['id']}/service-account-user", tok)["id"]
        rm = call("GET", f"{base}/clients?clientId=realm-management", tok)[0]["id"]
        have = {r["name"] for r in call("GET", f"{base}/users/{sa}/role-mappings/clients/{rm}", tok)}
        missing = [r for r in ROLES if r not in have]
        print(f"service account of {CLIENT} holds: {sorted(have)}")
        if missing and check:
            problems.append(f"service account lacks realm-management roles: {missing}")
        elif missing:
            avail = call("GET", f"{base}/clients/{rm}/roles", tok)
            reps = [r for r in avail if r["name"] in missing]
            if len(reps) != len(missing):
                sys.exit("a role does not exist in realm-management")
            call("POST", f"{base}/users/{sa}/role-mappings/clients/{rm}", tok, body=reps)
            print("granted:", missing)

    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print(" -", p)
        sys.exit(1)
    print("\nOK: client, Direct Grant flow and service account are ready")


main()
