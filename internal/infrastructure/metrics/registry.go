package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var (
	// HTTP Metrics
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests.",
		},
		[]string{"method", "path", "status_code"},
	)

	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// Auth Business Metrics
	AuthEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_events_total",
			Help: "Total number of authentication events.",
		},
		[]string{"event", "status"},
	)

	ActiveSessionsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_active_sessions",
			Help: "Number of currently active sessions.",
		},
	)
)

// NewRegistry creates a new prometheus registry and registers the standard metrics.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()

	reg.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDuration,
		AuthEventsTotal,
		ActiveSessionsGauge,
	)

	return reg
}

// Handler returns an http.Handler for the given registry.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
