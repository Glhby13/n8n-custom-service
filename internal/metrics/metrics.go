// Package metrics defines the Prometheus metrics exposed on /metrics.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics groups every collector the service updates.
type Metrics struct {
	Registry *prometheus.Registry

	Publish   *prometheus.CounterVec
	Rollback  *prometheus.CounterVec
	Duration  *prometheus.HistogramVec
	Errors    *prometheus.CounterVec
	GitLabReq *prometheus.CounterVec
	N8NReq    *prometheus.CounterVec
}

// New registers all collectors on a private registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Publish: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_git_publish_total", Help: "Publish synchronisations by result (changed, unchanged, skipped, error).",
		}, []string{"result"}),
		Rollback: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_git_rollback_total", Help: "Rollbacks by result (success, error).",
		}, []string{"result"}),
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "n8n_git_operation_duration_seconds", Help: "Duration of service operations.",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),
		Errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_git_operation_errors_total", Help: "Operation errors by operation and reason.",
		}, []string{"operation", "reason"}),
		GitLabReq: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_gitlab_requests_total", Help: "Outbound GitLab API requests by method and status code.",
		}, []string{"method", "code"}),
		N8NReq: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_n8n_api_requests_total", Help: "Outbound n8n API requests by method and status code.",
		}, []string{"method", "code"}),
	}
	m.Registry.MustRegister(m.Publish, m.Rollback, m.Duration, m.Errors, m.GitLabReq, m.N8NReq,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

// GitLabObserver returns a callback used by the GitLab client transport.
func (m *Metrics) GitLabObserver() func(method, code string) {
	return func(method, code string) { m.GitLabReq.WithLabelValues(method, code).Inc() }
}

// N8NObserver returns a callback used by the n8n client transport.
func (m *Metrics) N8NObserver() func(method, code string) {
	return func(method, code string) { m.N8NReq.WithLabelValues(method, code).Inc() }
}
