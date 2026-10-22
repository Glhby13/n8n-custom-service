package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) Getenv { return func(k string) string { return m[k] } }

func base() map[string]string {
	return map[string]string{
		"N8N_BASE_URL":      "http://n8n-dev.platform-dev.svc:5678",
		"N8N_API_KEY":       "n8n-key",
		"GITLAB_BASE_URL":   "https://gitlab.devops.btn.co.id/",
		"GITLAB_TOKEN":      "glpat-xxx",
		"SERVICE_API_TOKEN": "0123456789abcdef0123",
		"OWNER_MAPPINGS":    `[{"n8nUser":"admin psa","repository":"platform/n8n-git-sync/n8n-pluto"},{"n8nUser":"gen-ai itpd","repository":"platform/n8n-git-sync/n8n-ai"}]`,
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.GitLabBaseURL != "https://gitlab.devops.btn.co.id" || c.GitLabBranch != "main" || c.PollInterval != 30*time.Second ||
		!c.SyncOnStartup || c.MaxBodyBytes != 1<<20 || len(c.Mappings) != 2 || c.Port != "8080" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadRejectsBadConfig(t *testing.T) {
	cases := map[string]func(m map[string]string){
		"missing token":   func(m map[string]string) { delete(m, "GITLAB_TOKEN") },
		"missing n8n key": func(m map[string]string) { delete(m, "N8N_API_KEY") },
		"missing api tok": func(m map[string]string) { delete(m, "SERVICE_API_TOKEN") },
		"short api tok":   func(m map[string]string) { m["SERVICE_API_TOKEN"] = "short" },
		"http gitlab":     func(m map[string]string) { m["GITLAB_BASE_URL"] = "http://gitlab" },
		"bad url":         func(m map[string]string) { m["N8N_BASE_URL"] = "ftp://x" },
		"no mappings":     func(m map[string]string) { delete(m, "OWNER_MAPPINGS") },
		"bad json":        func(m map[string]string) { m["OWNER_MAPPINGS"] = "[" },
		"traversal repo":  func(m map[string]string) { m["OWNER_MAPPINGS"] = `[{"n8nUser":"a","repository":"platform/../x"}]` },
		"url as repo":     func(m map[string]string) { m["OWNER_MAPPINGS"] = `[{"n8nUser":"a","repository":"https://evil/x"}]` },
		"no group":        func(m map[string]string) { m["OWNER_MAPPINGS"] = `[{"n8nUser":"a","repository":"x"}]` },
		"duplicate user": func(m map[string]string) {
			m["OWNER_MAPPINGS"] = `[{"n8nUser":"A","repository":"g/x"},{"n8nUser":"a","repository":"g/y"}]`
		},
		"empty user":       func(m map[string]string) { m["OWNER_MAPPINGS"] = `[{"n8nUser":" ","repository":"g/x"}]` },
		"bad interval":     func(m map[string]string) { m["POLL_INTERVAL"] = "abc" },
		"too fast poll":    func(m map[string]string) { m["POLL_INTERVAL"] = "10ms" },
		"bad bool":         func(m map[string]string) { m["SYNC_ON_STARTUP"] = "maybe" },
		"retries too high": func(m map[string]string) { m["MAX_COMMIT_RETRIES"] = "50" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(m)
			if _, err := Load(env(m)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestErrorsNeverContainSecrets(t *testing.T) {
	m := base()
	m["N8N_BASE_URL"] = ""
	_, err := Load(env(m))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, secret := range []string{"n8n-key", "glpat-xxx", "0123456789abcdef0123"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks secret %q: %v", secret, err)
		}
	}
}

func TestRedactKeysParsed(t *testing.T) {
	m := base()
	m["REDACT_PARAMETER_KEYS"] = " Password, apiKey ,,token"
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.RedactParamKeys, ",") != "password,apikey,token" {
		t.Fatalf("got %v", c.RedactParamKeys)
	}
}
