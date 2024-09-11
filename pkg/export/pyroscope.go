package export

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/profiling"
	"go.uber.org/zap"
)

// PyroscopeExporter pushes pprof profiles to a Pyroscope-compatible HTTP endpoint.
type PyroscopeExporter struct {
	endpoint string
	username string // Basic auth username (Grafana Cloud instance ID)
	password string // Basic auth password (Grafana Cloud API token)
	client   *http.Client
	logger   *zap.Logger
}

// NewPyroscopeExporter creates a new Pyroscope HTTP exporter.
func NewPyroscopeExporter(cfg *config.PyroscopeConfig, logger *zap.Logger) *PyroscopeExporter {
	return &PyroscopeExporter{
		endpoint: cfg.Endpoint,
		username: cfg.Username,
		password: cfg.Password,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// sanitizeServiceName replaces characters not allowed by Pyroscope.
var invalidServiceNameChars = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func sanitizeServiceName(name string) string {
	return invalidServiceNameChars.ReplaceAllString(name, "_")
}

// ExportProfile sends a gzip'd pprof profile to the Pyroscope receiver.
func (e *PyroscopeExporter) ExportProfile(ctx context.Context, p *profiling.Profile) error {
	svcName := sanitizeServiceName(p.ServiceName)
	url := fmt.Sprintf("%s/ingest?name=%s.cpu&format=pprof&from=%d&until=%d",
		e.endpoint,
		svcName,
		p.Start.Unix(),
		p.End.Unix(),
	)

	backoff := initialBackoff
	for attempt := 0; attempt <= maxRetries; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(p.PProfData))
		if err != nil {
			cancel()
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		if e.username != "" {
			req.SetBasicAuth(e.username, e.password)
		}

		resp, err := e.client.Do(req)
		cancel()

		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			err = fmt.Errorf("pyroscope HTTP %d: %s", resp.StatusCode, string(body))
		}

		if attempt == maxRetries {
			return fmt.Errorf("pyroscope export failed after %d retries: %w", maxRetries+1, err)
		}

		e.logger.Warn("pyroscope export failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}

		backoff = time.Duration(math.Min(
			float64(backoff)*backoffFactor,
			float64(maxBackoff),
		))
	}

	return nil
}

// Shutdown closes the HTTP client.
func (e *PyroscopeExporter) Shutdown(ctx context.Context) error {
	e.client.CloseIdleConnections()
	return nil
}
