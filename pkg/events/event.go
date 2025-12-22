// oreon/defense · watchthelight <wtl>

package events

import (
	"time"
)

// EventType identifies the kind of operation being logged.
type EventType string

const (
	EventTypeScan        EventType = "scan"
	EventTypeIPCRequest  EventType = "ipc_request"
	EventTypeStateChange EventType = "state_change"
	EventTypeThreat      EventType = "threat_detected"
	EventTypeHealthCheck EventType = "health_check"
)

// Event represents a wide event / canonical log line.
// One Event is emitted per logical operation, containing all relevant context.
type Event struct {
	// Core identification
	Type        EventType `json:"event_type"`
	OperationID string    `json:"operation_id"`
	Component   string    `json:"component"`

	// Timing
	StartedAt  time.Time     `json:"started_at"`
	Duration   time.Duration `json:"-"`
	DurationMs int64         `json:"duration_ms"`

	// Outcome
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`

	// High-cardinality fields (operation-specific)
	Fields map[string]interface{} `json:"fields,omitempty"`
}

// Standard field names for consistency across events.
const (
	FieldOperationID   = "operation_id"
	FieldDurationMs    = "duration_ms"
	FieldSuccess       = "success"
	FieldError         = "error"
	FieldScanType      = "scan_type"
	FieldJobID         = "job_id"
	FieldPath          = "path"
	FieldFilesScanned  = "files_scanned"
	FieldThreatsFound  = "threats_found"
	FieldFileSizeBytes = "file_size_bytes"
	FieldCommand       = "command"
	FieldRequestID     = "request_id"
	FieldClientVersion = "client_version"
	FieldResponseSize  = "response_size_bytes"
	FieldFromState     = "from_state"
	FieldToState       = "to_state"
	FieldReason        = "reason"
	FieldThreatName    = "threat_name"
	FieldAction        = "action"
	FieldClamAvailable = "clamav_available"
	FieldFWEnabled     = "firewall_enabled"
)
