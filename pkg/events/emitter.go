// oreon/defense · watchthelight <wtl>

package events

import (
	"log/slog"
	"math/rand"
	"time"
)

// Emitter handles event output with optional sampling.
type Emitter struct {
	logger     *slog.Logger
	sampleRate float64 // 0.0-1.0, percentage of successful events to emit
	slowThresh time.Duration
}

// EmitterOption configures an Emitter.
type EmitterOption func(*Emitter)

// WithSampleRate sets the sampling rate for successful events (0.0-1.0).
// Errors and slow operations are always emitted regardless of this setting.
func WithSampleRate(rate float64) EmitterOption {
	return func(e *Emitter) {
		if rate < 0 {
			rate = 0
		}
		if rate > 1 {
			rate = 1
		}
		e.sampleRate = rate
	}
}

// WithSlowThreshold sets the duration threshold for "slow" operations.
// Operations exceeding this are always emitted regardless of sample rate.
func WithSlowThreshold(d time.Duration) EmitterOption {
	return func(e *Emitter) {
		e.slowThresh = d
	}
}

// WithLogger sets a custom slog.Logger for output.
func WithLogger(logger *slog.Logger) EmitterOption {
	return func(e *Emitter) {
		e.logger = logger
	}
}

// NewEmitter creates a new Emitter with the given options.
// Defaults: 100% sample rate, 1s slow threshold, default slog logger.
func NewEmitter(opts ...EmitterOption) *Emitter {
	e := &Emitter{
		logger:     slog.Default(),
		sampleRate: 1.0,
		slowThresh: time.Second,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Emit outputs an event if it passes sampling criteria.
// Always emits: errors, slow operations.
// Samples: successful fast operations based on sampleRate.
func (e *Emitter) Emit(evt Event) {
	if !e.shouldEmit(evt) {
		return
	}
	e.log(evt)
}

// shouldEmit determines if an event should be output based on sampling rules.
func (e *Emitter) shouldEmit(evt Event) bool {
	// Always emit errors
	if !evt.Success {
		return true
	}
	// Always emit slow operations
	if evt.Duration >= e.slowThresh {
		return true
	}
	// Sample successful fast operations
	if e.sampleRate >= 1.0 {
		return true
	}
	if e.sampleRate <= 0 {
		return false
	}
	return rand.Float64() < e.sampleRate
}

// log outputs the event via slog.
func (e *Emitter) log(evt Event) {
	// Build attribute list
	attrs := []any{
		slog.String("event_type", string(evt.Type)),
		slog.String("operation_id", evt.OperationID),
		slog.String("component", evt.Component),
		slog.Int64("duration_ms", evt.DurationMs),
		slog.Bool("success", evt.Success),
	}

	if evt.Error != "" {
		attrs = append(attrs, slog.String("error", evt.Error))
	}

	// Add all custom fields
	for k, v := range evt.Fields {
		attrs = append(attrs, slog.Any(k, v))
	}

	// Use appropriate log level
	level := slog.LevelInfo
	if !evt.Success {
		level = slog.LevelError
	}

	e.logger.Log(nil, level, string(evt.Type), attrs...)
}
