// Command sharing-service enables universal workflow sharing and settings proxy for n8n Community.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/httpx"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/metrics"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/shareproxy"
)

const serviceName = "sharing-service"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(httpx.HealthcheckMain())
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, `{"level":"ERROR","service":%q,"msg":"startup failed","error":%q}`+"\n", serviceName, err.Error())
		os.Exit(1)
	}
}

func getDBURL() string {
	if u := strings.TrimSpace(os.Getenv("DB_URL")); u != "" {
		return u
	}
	dbHost := strings.TrimSpace(os.Getenv("DB_HOST"))
	dbPass := strings.TrimSpace(os.Getenv("DB_PASSWORD"))
	if dbPass == "" {
		dbPass = strings.TrimSpace(os.Getenv("PG_PASSWORD"))
	}
	if dbPass == "" {
		dbPass = strings.TrimSpace(os.Getenv("DB_POSTGRESDB_PASSWORD"))
	}
	if dbHost != "" && dbPass != "" {
		dbPort := os.Getenv("DB_PORT")
		if dbPort == "" {
			dbPort = "5432"
		}
		dbUser := os.Getenv("DB_USER")
		if dbUser == "" {
			dbUser = "lab_worker"
		}
		dbName := os.Getenv("DB_NAME")
		if dbName == "" {
			dbName = "n8n_db"
		}
		dbSSL := os.Getenv("DB_SSLMODE")
		if dbSSL == "" {
			dbSSL = "disable"
		}
		return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", dbUser, dbPass, dbHost, dbPort, dbName, dbSSL)
	}
	return ""
}

func run() error {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	logLevel := strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	if logLevel == "" {
		logLevel = "info"
	}
	n8nBaseURL := strings.TrimSpace(os.Getenv("N8N_BASE_URL"))
	if n8nBaseURL == "" {
		n8nBaseURL = "http://n8n-dev.lab-dev.svc:5678"
	}
	cookieName := strings.TrimSpace(os.Getenv("N8N_AUTH_COOKIE_NAME"))
	if cookieName == "" {
		cookieName = "n8n-auth"
	}
	dbURL := getDBURL()
	if dbURL == "" {
		return fmt.Errorf("database configuration required (DB_URL or DB_HOST + DB_PASSWORD)")
	}

	log := httpx.NewLogger(os.Stdout, logLevel, serviceName)
	m := metrics.New()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sp, err := shareproxy.New(ctx, shareproxy.Options{
		N8NBaseURL: n8nBaseURL,
		CookieName: cookieName,
		DBURL:      dbURL,
		Timeout:    30 * time.Second,
		Log:        log,
	})
	if err != nil {
		return fmt.Errorf("initialize share proxy: %w", err)
	}
	defer sp.Close()

	startedAt := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"live","uptime_seconds":%d}`, int64(time.Since(startedAt).Seconds()))
	})
	mux.Handle("GET /metrics", m.Handler())

	// Proxy endpoints for n8n UI
	mux.Handle("GET /rest/settings", sp)
	mux.Handle("GET /rest/settings/", sp)
	mux.Handle("PUT /rest/workflows/{workflowId}/share", sp)
	mux.Handle("PUT /rest/workflows/{workflowId}/share/", sp)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "unknown endpoint")
	})

	handler := httpx.Chain(mux, httpx.RequestID, httpx.Recover(log), httpx.AccessLog(log))

	log.Info("starting", "service", serviceName, "addr", ":"+port, "n8n_base_url", n8nBaseURL)
	return httpx.Run(ctx, log, httpx.NewServer(":"+port, handler), 10*time.Second)
}
