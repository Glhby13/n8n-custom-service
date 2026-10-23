// Command auth-service enables OIDC authentication, Keycloak integration, and account takeover mapping for n8n Community.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/authservice"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/httpx"
)

const serviceName = "auth-service"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(httpx.HealthcheckMain())
	}

	cfg, err := authservice.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"level":"ERROR","service":%q,"msg":"config error","error":%q}`+"\n", serviceName, err.Error())
		os.Exit(1)
	}

	log := httpx.NewLogger(os.Stdout, cfg.LogLevel, serviceName)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := authservice.NewDB(ctx, cfg.DBURL, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"level":"ERROR","service":%q,"msg":"db connect failed","error":%q}`+"\n", serviceName, err.Error())
		os.Exit(1)
	}
	defer db.Close()

	// Check if invoked as CLI subcommand
	if authservice.RunCLI(ctx, os.Args, cfg, db) {
		return
	}

	// Start HTTP Daemon
	server := authservice.NewServer(cfg, db, log)
	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("starting auth-service daemon", "port", cfg.Port, "keycloak", cfg.KeycloakURL)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server listen failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down auth-service daemon...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	log.Info("auth-service stopped gracefully")
}
