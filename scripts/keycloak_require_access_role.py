#!/usr/bin/env python3
"""Make Keycloak itself refuse a sign-in when the user lacks the client's access role (Direct Grant flow).

Adds one CONDITIONAL sub-flow to the Direct Grant flow bound to the client, right AFTER "Password" and before the OTP
sub-flow:

    Username Validation (REQUIRED) -> Password (REQUIRED)
      -> <flow>-deny-no-access (CONDITIONAL): Condition - user role (REQUIRED, role=<client>.<access role>, negate=true),
                                              Deny access (REQUIRED)
      -> <flow>-conditional-otp ... (unchanged)

It sits after Password on purpose: only someone who proved the password learns the account has no access, so the answer
cannot be used to probe which user names hold the role. The application (auth-service) keeps its own check as a second
lock, but Keycloak is now the first one.

Idempotent. --check changes nothing (exit 1 when missing). --undo removes the sub-flow again.

Env: KC_URL (default https://auth.lab.local)  KC_REALM (lab)  KC_CLIENT (n8n-lab)  KC_ACCESS_ROLE (n8n-access)
     KC_ADMIN_USER (admin)  KC_ADMIN_PASSWORD (else lab/SECRETS.md, only when KC_URL is *.lab.local, else asked on the terminal)
     KC_INSECURE=1 only for a self-signed lab certificate.
Usage: python3 -I keycloak_require_access_role.py [--check | --undo]
"""
import getpass, json, os, re, ssl, sys, urllib.error, urllib.parse, urllib.request

KC = os.environ.get("KC_URL", "https://auth.lab.local").rstrip("/")
REALM = os.environ.get("KC_REALM", "lab")
CLIENT = os.environ.get("KC_CLIENT", "n8n-lab")
ACCESS_ROLE = os.environ.get("KC_ACCESS_ROLE", "n8n-access")
CTX = ssl._create_unverified_context() if os.environ.get("KC_INSECURE") == "1" else ssl.create_default_context()


def admin_password():
    if os.environ.get("KC_ADMIN_PASSWORD"):
        return os.environ["KC_ADMIN_PASSWORD"]
    secrets = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "SECRETS.md")  # lab layout only
    if KC.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].endswith(".lab.local") and os.path.exists(secrets):  # never send the lab password to another host
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
        sys.exit(f"{method} {path} -> HTTP {e.code} {e.read().decode()[:200]}")


def main():
    check, undo = "--check" in sys.argv, "--undo" in sys.argv
    tok = call("POST", "/realms/master/protocol/openid-connect/token",
               form=dict(grant_type="password", client_id="admin-cli", username=os.environ.get("KC_ADMIN_USER", "admin"), password=admin_password()))["access_token"]
    base = f"/admin/realms/{REALM}"
    found = call("GET", f"{base}/clients?clientId={CLIENT}", tok)
    if not found:
        sys.exit(f"client {CLIENT} not found in realm {REALM}")
    fid = (found[0].get("authenticationFlowBindingOverrides") or {}).get("direct_grant")
    if not fid:
        sys.exit("no Direct Grant flow is bound to the client")
    alias = next((f["alias"] for f in call("GET", f"{base}/authentication/flows", tok) if f["id"] == fid), None)
    if not alias:
        sys.exit("the bound Direct Grant flow does not exist")
    sub = f"{alias}-deny-no-access"
    q = urllib.parse.quote
    rows = call("GET", f"{base}/authentication/flows/{q(alias)}/executions", tok)
    existing = next((e for e in rows if e.get("displayName") == sub and e["level"] == 0), None)
    want_role = f"{CLIENT}.{ACCESS_ROLE}"

    if undo:
        if not existing:
            print("nothing to undo: the sub-flow is not there")
            return
        call("DELETE", f"{base}/authentication/executions/{existing['id']}", tok)
        print(f"removed sub-flow {sub} from {alias}")
        return

    if existing:
        kids = call("GET", f"{base}/authentication/flows/{q(sub)}/executions", tok)
        role = next((k for k in kids if k.get("providerId") == "conditional-user-role"), None)
        cfg = (call("GET", f"{base}/authentication/config/{role['authenticationConfig']}", tok).get("config") or {}) if role and role.get("authenticationConfig") else {}
        deny = next((k for k in kids if k.get("providerId") == "deny-access-authenticator"), None)
        order = [e.get("displayName") or e.get("providerId") for e in rows if e["level"] == 0]
        ok = (existing["requirement"] == "CONDITIONAL" and role and role["requirement"] == "REQUIRED" and cfg.get("condUserRole") == want_role
              and cfg.get("negate") == "true" and deny and deny["requirement"] == "REQUIRED"
              and order.index(sub) == order.index("Password") + 1)
        print(f"flow {alias}: {'OK, deny-without-role is in place' if ok else 'sub-flow exists but is wrong'} (role={cfg.get('condUserRole')}, negate={cfg.get('negate')})")
        sys.exit(0 if ok else 1)

    if check:
        print(f"flow {alias}: MISSING sub-flow {sub} (Keycloak does not refuse users without {want_role})")
        sys.exit(1)

    call("POST", f"{base}/authentication/flows/{q(alias)}/executions/flow", tok,
         body={"alias": sub, "type": "basic-flow", "provider": "registration-page-form",
               "description": f"deny sign-in without client role {want_role}"})
    rows = call("GET", f"{base}/authentication/flows/{q(alias)}/executions", tok)
    ex = next(e for e in rows if e.get("displayName") == sub and e["level"] == 0)
    call("PUT", f"{base}/authentication/flows/{q(alias)}/executions", tok, body={**ex, "requirement": "CONDITIONAL"})
    call("POST", f"{base}/authentication/flows/{q(sub)}/executions/execution", tok, body={"provider": "conditional-user-role"})
    call("POST", f"{base}/authentication/flows/{q(sub)}/executions/execution", tok, body={"provider": "deny-access-authenticator"})
    for k in call("GET", f"{base}/authentication/flows/{q(sub)}/executions", tok):
        call("PUT", f"{base}/authentication/flows/{q(sub)}/executions", tok, body={**k, "requirement": "REQUIRED"})
        if k.get("providerId") == "conditional-user-role":
            call("POST", f"{base}/authentication/executions/{k['id']}/config", tok,
                 body={"alias": f"{sub}-role", "config": {"condUserRole": want_role, "negate": "true"}})
    # the new sub-flow is appended last: move it up until it directly follows "Password"
    for _ in range(10):
        order = [e.get("displayName") or e.get("providerId") for e in call("GET", f"{base}/authentication/flows/{q(alias)}/executions", tok) if e["level"] == 0]
        if order.index(sub) == order.index("Password") + 1:
            break
        call("POST", f"{base}/authentication/executions/{ex['id']}/raise-priority", tok)
    print(f"added sub-flow {sub} to {alias}: a user without {want_role} is refused by Keycloak after the password check")


main()
