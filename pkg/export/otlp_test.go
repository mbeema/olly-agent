// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package export

import (
	"testing"
	"time"

	"github.com/mbeema/olly/pkg/config"
)

func TestConfigResourceAttributes(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ServiceVersion = "1.2.3"
	cfg.DeploymentEnv = "production"

	if cfg.ServiceVersion != "1.2.3" {
		t.Errorf("expected service version 1.2.3, got %s", cfg.ServiceVersion)
	}
	if cfg.DeploymentEnv != "production" {
		t.Errorf("expected deployment env production, got %s", cfg.DeploymentEnv)
	}
}

func TestConfigCompressionDefault(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.Exporters.OTLP.Compression != "gzip" {
		t.Errorf("expected default compression 'gzip', got %q", cfg.Exporters.OTLP.Compression)
	}
}

func TestConfigCompressionValidation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Exporters.OTLP.Compression = "invalid"
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for invalid compression")
	}
}

func TestConfigCompressionNone(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Exporters.OTLP.Compression = "none"
	err := cfg.Validate()
	if err != nil {
		t.Errorf("expected no error for compression 'none', got %v", err)
	}
}

func TestMetricServiceName(t *testing.T) {
	m := &Metric{
		Name:        "test.metric",
		Type:        MetricGauge,
		Value:       42.0,
		Timestamp:   time.Now(),
		Labels:      map[string]string{},
		ServiceName: "my-service",
	}
	if m.ServiceName != "my-service" {
		t.Errorf("expected service name 'my-service', got %q", m.ServiceName)
	}
}

func TestLogRecordServiceName(t *testing.T) {
	lr := &LogRecord{
		Timestamp:   time.Now(),
		Body:        "test log",
		Level:       "INFO",
		Attributes:  map[string]interface{}{},
		ServiceName: "log-service",
		PID:         1234,
	}
	if lr.ServiceName != "log-service" {
		t.Errorf("expected service name 'log-service', got %q", lr.ServiceName)
	}
}

func TestResourceForServiceWithVersion(t *testing.T) {
	e := &OTLPExporter{
		serviceName:    "test-svc",
		serviceVersion: "2.0.0",
		deploymentEnv:  "staging",
	}

	res := e.resourceForService("my-app", 1234)
	found := map[string]bool{}
	for _, attr := range res.Attributes {
		switch attr.Key {
		case "service.version":
			found["service.version"] = true
			if attr.Value.GetStringValue() != "2.0.0" {
				t.Errorf("expected service.version=2.0.0, got %s", attr.Value.GetStringValue())
			}
		case "deployment.environment":
			found["deployment.environment"] = true
			if attr.Value.GetStringValue() != "staging" {
				t.Errorf("expected deployment.environment=staging, got %s", attr.Value.GetStringValue())
			}
		case "service.name":
			if attr.Value.GetStringValue() != "my-app" {
				t.Errorf("expected service.name=my-app, got %s", attr.Value.GetStringValue())
			}
		}
	}
	if !found["service.version"] {
		t.Error("service.version attribute missing from resource")
	}
	if !found["deployment.environment"] {
		t.Error("deployment.environment attribute missing from resource")
	}
}

func TestResourceForServiceWithoutVersion(t *testing.T) {
	e := &OTLPExporter{
		serviceName: "test-svc",
		// serviceVersion and deploymentEnv are empty
	}

	res := e.resourceForService("my-app", 1234)
	for _, attr := range res.Attributes {
		if attr.Key == "service.version" {
			t.Error("service.version should not be present when empty")
		}
		if attr.Key == "deployment.environment" {
			t.Error("deployment.environment should not be present when empty")
		}
	}
}

func TestResourceForServiceFallback(t *testing.T) {
	e := &OTLPExporter{
		serviceName: "fallback-svc",
	}

	res := e.resourceForService("", 1234)
	for _, attr := range res.Attributes {
		if attr.Key == "service.name" {
			if attr.Value.GetStringValue() != "fallback-svc" {
				t.Errorf("expected service.name=fallback-svc, got %s", attr.Value.GetStringValue())
			}
		}
	}
}
