package sidecar

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const telemetryQueueSize = 256

// Telemetry is process-local diagnostics. It is never Action or receipt truth.
type Telemetry struct {
	tracer        trace.Tracer
	checks        metric.Int64Counter
	requests      metric.Int64Counter
	traceProvider *sdktrace.TracerProvider
	meterProvider *sdkmetric.MeterProvider
	processor     *boundedSpanProcessor
	failures      atomic.Uint64
}

// NewTelemetry enables optional OTLP/HTTP export to a customer-operated Collector.
// An empty endpoint leaves the sidecar fully functional without telemetry.
func NewTelemetry(ctx context.Context, endpoint string) (*Telemetry, error) {
	t := &Telemetry{}
	if endpoint == "" {
		return t, nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("AUTHRAIL_OTLP_ENDPOINT must be an HTTP(S) Collector base URL")
	}
	base := strings.TrimRight(endpoint, "/")
	traceExporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(base+"/v1/traces"),
		otlptracehttp.WithTimeout(500*time.Millisecond),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}))
	if err != nil {
		return nil, errors.New("sidecar trace exporter could not initialize")
	}
	metricExporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(base+"/v1/metrics"),
		otlpmetrichttp.WithTimeout(500*time.Millisecond),
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}))
	if err != nil {
		_ = traceExporter.Shutdown(ctx)
		return nil, errors.New("sidecar metric exporter could not initialize")
	}
	t.processor = newBoundedSpanProcessor(traceExporter, &t.failures)
	t.traceProvider = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(t.processor))
	t.meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(
		sdkmetric.NewPeriodicReader(&countingMetricExporter{Exporter: metricExporter,
			failures: &t.failures}, sdkmetric.WithInterval(10*time.Second),
			sdkmetric.WithTimeout(500*time.Millisecond))))
	t.tracer = t.traceProvider.Tracer("authrail-sidecar")
	meter := t.meterProvider.Meter("authrail-sidecar")
	t.requests, err = meter.Int64Counter("authrail.sidecar.requests")
	if err == nil {
		t.checks, err = meter.Int64Counter("authrail.sidecar.decisions")
	}
	if err != nil {
		_ = t.Shutdown(ctx)
		return nil, errors.New("sidecar telemetry instruments could not initialize")
	}
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return t, nil
}

// WrapHTTP records only the fixed route and response class, never request content.
func (t *Telemetry) WrapHTTP(route string, next http.Handler) http.Handler {
	if t.tracer == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if parent, valid := requestTraceparent(r); valid && parent != "" {
			ctx = propagation.TraceContext{}.Extract(ctx, propagation.HeaderCarrier(r.Header))
		}
		ctx, span := t.tracer.Start(ctx, "sidecar."+route,
			trace.WithAttributes(attribute.String("authrail.route", route)))
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r.WithContext(ctx))
		statusClass := "2xx"
		if wrapped.status >= 500 {
			statusClass = "5xx"
			span.SetStatus(codes.Error, "server_error")
		} else if wrapped.status >= 400 {
			statusClass = "4xx"
		}
		t.requests.Add(ctx, 1, metric.WithAttributes(
			attribute.String("route", route), attribute.String("status_class", statusClass)))
		span.End()
	})
}

// RecordDecision uses enumerated output only; identifiers and payloads stay local.
func (t *Telemetry) RecordDecision(ctx context.Context, evaluation Evaluation) {
	if t.checks == nil {
		return
	}
	decision := evaluation.Outcome
	switch decision {
	case "allow", "deny", "approval_required", "additional_context_required":
	default:
		decision = "other"
	}
	coverage := evaluation.Coverage
	switch coverage {
	case "evaluated", "uncovered", "unavailable":
	default:
		coverage = "other"
	}
	t.checks.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", decision),
		attribute.String("coverage", coverage)))
}

// Run records a fixed background operation without affecting its result.
func (t *Telemetry) Run(ctx context.Context, operation string,
	fn func(context.Context) error) error {
	if t.tracer == nil {
		return fn(ctx)
	}
	ctx, span := t.tracer.Start(ctx, "sidecar."+operation)
	err := fn(ctx)
	status := "success"
	if err != nil {
		status = "error"
		span.SetStatus(codes.Error, "operation_failed")
	}
	t.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("route", operation),
		attribute.String("status_class", status)))
	span.End()
	return err
}

// Failures is a local diagnostic count, not proof of collector retention.
func (t *Telemetry) Failures() uint64 { return t.failures.Load() }

// Shutdown gives queued telemetry a short best-effort flush.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t.traceProvider == nil {
		return nil
	}
	err := t.traceProvider.Shutdown(ctx)
	if metricErr := t.meterProvider.Shutdown(ctx); err == nil {
		err = metricErr
	}
	return err
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

type countingMetricExporter struct {
	sdkmetric.Exporter
	failures *atomic.Uint64
}

func (e *countingMetricExporter) Export(ctx context.Context, data *metricdata.ResourceMetrics) error {
	err := e.Exporter.Export(ctx, data)
	if err != nil {
		e.failures.Add(1)
	}
	return err
}

// The queue drops excess spans instead of delaying a protected operation.
type boundedSpanProcessor struct {
	exporter sdktrace.SpanExporter
	queue    chan sdktrace.ReadOnlySpan
	flush    chan chan struct{}
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	failures *atomic.Uint64
}

func newBoundedSpanProcessor(exporter sdktrace.SpanExporter, failures *atomic.Uint64) *boundedSpanProcessor {
	p := &boundedSpanProcessor{exporter: exporter, queue: make(chan sdktrace.ReadOnlySpan,
		telemetryQueueSize), flush: make(chan chan struct{}), stop: make(chan struct{}),
		done: make(chan struct{}), failures: failures}
	go p.run()
	return p
}

func (p *boundedSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

func (p *boundedSpanProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	select {
	case p.queue <- span:
	default:
		p.failures.Add(1)
	}
}

func (p *boundedSpanProcessor) run() {
	defer close(p.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	batch := make([]sdktrace.ReadOnlySpan, 0, 32)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if p.exporter.ExportSpans(ctx, batch) != nil {
			p.failures.Add(uint64(len(batch)))
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case span := <-p.queue:
			batch = append(batch, span)
			if len(batch) == cap(batch) {
				flush()
			}
		case <-ticker.C:
			flush()
		case done := <-p.flush:
			for len(p.queue) > 0 {
				batch = append(batch, <-p.queue)
				if len(batch) == cap(batch) {
					flush()
				}
			}
			flush()
			close(done)
		case <-p.stop:
			for len(batch) < cap(batch) {
				select {
				case span := <-p.queue:
					batch = append(batch, span)
				default:
					flush()
					return
				}
			}
			flush()
			p.failures.Add(uint64(len(p.queue)))
			return
		}
	}
}

func (p *boundedSpanProcessor) Shutdown(ctx context.Context) error {
	p.once.Do(func() { close(p.stop) })
	select {
	case <-p.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return p.exporter.Shutdown(ctx)
}

func (p *boundedSpanProcessor) ForceFlush(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case p.flush <- done:
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
