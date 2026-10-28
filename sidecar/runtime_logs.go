package sidecar

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// RuntimeLogs writes bounded, best-effort process diagnostics independently of OTLP.
// It never retains request bodies, credentials or provider responses.
type RuntimeLogs struct {
	queue   chan runtimeLogEvent
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	dropped atomic.Uint64
}

type runtimeLogEvent struct {
	AttemptID      string `json:"attemptId,omitempty"`
	ExecutionEvent string `json:"executionEvent,omitempty"`
	Time           string `json:"time"`
	Event          string `json:"event"`
	Operation      string `json:"operation,omitempty"`
	Status         int    `json:"status,omitempty"`
	DurationMS     int64  `json:"durationMs,omitempty"`
	RequestID      string `json:"requestId,omitempty"`
	ActionID       string `json:"actionId,omitempty"`
	ApprovalID     string `json:"approvalRequestId,omitempty"`
	Phase          string `json:"phase,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Outcome        string `json:"outcome,omitempty"`
	Recording      string `json:"recordingStatus,omitempty"`
}

// NewRuntimeLogs starts a single bounded output worker. A slow output drops logs
// instead of blocking protected calls; the caller still owns the writer.
func NewRuntimeLogs(output io.Writer) *RuntimeLogs {
	l := &RuntimeLogs{queue: make(chan runtimeLogEvent, 256), stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		encoder := json.NewEncoder(output)
		write := func(event runtimeLogEvent) {
			if encoder.Encode(event) != nil {
				l.dropped.Add(1)
			}
		}
		for {
			select {
			case event := <-l.queue:
				write(event)
			case <-l.stop:
				for {
					select {
					case event := <-l.queue:
						write(event)
					default:
						return
					}
				}
			}
		}
	}()
	return l
}

func (l *RuntimeLogs) emit(event runtimeLogEvent) {
	if l == nil {
		return
	}
	event.Time = time.Now().UTC().Format(time.RFC3339Nano)
	select {
	case l.queue <- event:
	default:
		l.dropped.Add(1)
	}
}

// Dropped counts queue overflow and output errors, not lost Action records.
func (l *RuntimeLogs) Dropped() uint64 { return l.dropped.Load() }

// Shutdown flushes diagnostics within the caller's deadline, without closing output.
func (l *RuntimeLogs) Shutdown(ctx context.Context) {
	l.once.Do(func() { close(l.stop) })
	select {
	case <-l.done:
	case <-ctx.Done():
	}
}

func logChoice(value string, choices ...string) string {
	for _, choice := range choices {
		if value == choice {
			return value
		}
	}
	return "other"
}

func logID(value string) string {
	if uuidPattern.MatchString(value) {
		return value
	}
	return ""
}

func (l *RuntimeLogs) decision(e Evaluation, phase string) {
	approvalID := ""
	if e.ApprovalRequestID != nil {
		approvalID = logID(*e.ApprovalRequestID)
	}
	l.emit(runtimeLogEvent{Event: "decision", RequestID: logID(e.RequestID), ActionID: logID(e.ActionID),
		ApprovalID: approvalID, Phase: logChoice(phase, "tool_call", "tool_result"), Mode: logChoice(e.Mode, "observe", "enforce"),
		Outcome:   logChoice(e.Outcome, "allow", "deny", "approval_required", "additional_context_required"),
		Recording: logChoice(e.RecordingStatus, "retained", "queued", "unavailable")})
}

func (t *Telemetry) recordExecution(actionID, attemptID, event, recording string) {
	if t == nil {
		return
	}
	t.logs.emit(runtimeLogEvent{Event: "execution_report", ActionID: logID(actionID), AttemptID: logID(attemptID),
		ExecutionEvent: logChoice(event, "started", "succeeded", "failed", "unknown", "reconciled_succeeded", "reconciled_failed"),
		Recording:      logChoice(recording, "retained", "queued", "unavailable")})
}

// RecordServiceEvent accepts only fixed service events, never error messages or configuration values.
func (l *RuntimeLogs) RecordServiceEvent(event string) {
	l.emit(runtimeLogEvent{Event: logChoice(event, "sidecar_started", "sidecar_stopped", "configuration_sync_failed",
		"reports_queued", "health_signal_failed", "listener_stopped", "telemetry_export_disabled")})
}

func (l *RuntimeLogs) decisionDelivered(entry queuedObserve, retained retainedObserve) {
	if l == nil {
		return
	}
	// Read only the correlation identifier; persisted report content never enters logs.
	var metadata struct {
		Report struct {
			Evaluation struct {
				RequestID string `json:"requestId"`
			} `json:"evaluation"`
		} `json:"report"`
	}
	_ = json.Unmarshal(entry.Body, &metadata)
	l.emit(runtimeLogEvent{Event: "report_delivered", Operation: "decision_report", ActionID: logID(retained.ActionID),
		RequestID: logID(metadata.Report.Evaluation.RequestID), Phase: logChoice(entry.Phase, "tool_call", "tool_result"), Recording: "retained"})
}
