// Command n8n-git-service versions published n8n workflows in GitLab and restores them.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/audit"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/config"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/github"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/gitlab"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/historyproxy"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/httpx"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/metrics"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/n8n"
	"gitlab.devops.btn.co.id/platform/n8n-git-service/internal/service"
)

const serviceName = "n8n-git-service"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(httpx.HealthcheckMain())
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, `{"level":"ERROR","service":%q,"msg":"startup failed","error":%q}`+"\n", serviceName, err.Error())
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	log := httpx.NewLogger(os.Stdout, cfg.LogLevel, serviceName)
	m := metrics.New()

	n8nClient := n8n.NewHTTPClient(n8n.Options{
		BaseURL: cfg.N8NBaseURL, APIKey: cfg.N8NAPIKey, Timeout: cfg.HTTPTimeout,
		PageSize: cfg.WorkflowPageSize, Observe: m.N8NObserver(),
	})
	var gitClient gitlab.Store
	if cfg.GitProvider == "github" {
		gitClient, err = github.New(github.Options{
			BaseURL: cfg.GitLabBaseURL, Token: cfg.GitLabToken, Timeout: cfg.HTTPTimeout,
			Observe: m.GitLabObserver(),
		})
	} else {
		gitClient, err = gitlab.New(gitlab.Options{
			BaseURL: cfg.GitLabBaseURL, Token: cfg.GitLabToken, Timeout: cfg.HTTPTimeout,
			CAFile: cfg.GitLabCAFile, Observe: m.GitLabObserver(),
		})
	}
	if err != nil {
		return err
	}

	svc := service.New(service.Options{
		N8N: n8nClient, Git: gitClient, Mapper: service.NewMapper(cfg.Mappings),
		Branch: cfg.GitLabBranch, RedactKeys: cfg.RedactParamKeys,
		MaxCommitRetries: cfg.MaxCommitRetries, MaxHistory: cfg.MaxHistoryCommits,
		MaxWorkflowBytes: cfg.MaxWorkflowBytes, Log: log, Audit: audit.New(log), Metrics: m,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var poller *service.Poller
	if cfg.PollEnabled {
		poller = service.NewPoller(svc, cfg.PollInterval, cfg.SyncOnStartup, log)
		go poller.Run(ctx)
	}

	repos := make([]string, 0, len(cfg.Mappings))
	for _, mp := range cfg.Mappings {
		repos = append(repos, mp.N8NUser+" -> "+mp.Repository)
	}
	log.Info("starting", "n8n_base_url", cfg.N8NBaseURL, "gitlab_base_url", cfg.GitLabBaseURL,
		"branch", cfg.GitLabBranch, "poll_enabled", cfg.PollEnabled, "poll_interval", cfg.PollInterval.String(),
		"sync_on_startup", cfg.SyncOnStartup, "history_proxy", cfg.HistoryProxyEnabled, "mappings", repos)

	var history http.Handler
	if cfg.HistoryProxyEnabled {
		hp, err := historyproxy.New(historyproxy.Options{
			N8NBaseURL: cfg.N8NBaseURL, Source: svc, CookieName: cfg.N8NAuthCookieName,
			Timeout: cfg.HTTPTimeout, Log: log, Mode: cfg.HistoryProxyMode,
		})
		if err != nil {
			return err
		}
		history = hp
	}

	h := service.NewHandler(service.HandlerOptions{
		Service: svc, Poller: poller, Log: log, APIToken: cfg.ServiceAPIToken,
		MaxBodyBytes: cfg.MaxBodyBytes, RateLimitRPS: cfg.RateLimitRPS, Metrics: m.Handler(),
		StartedAt: time.Now(), History: history,
	})
	return httpx.Run(ctx, log, httpx.NewServer(":"+cfg.Port, h), cfg.ShutdownTimeout)
}
