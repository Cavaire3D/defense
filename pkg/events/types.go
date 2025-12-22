// oreon/defense · watchthelight <wtl>

package events

// ScanBuilder is a typed builder for scan events.
type ScanBuilder struct {
	*Builder
}

// StartScan creates a new scan event builder.
func StartScan(scanType, jobID string) *ScanBuilder {
	b := Start(EventTypeScan, "scanner")
	b.Set(FieldScanType, scanType)
	b.Set(FieldJobID, jobID)
	return &ScanBuilder{Builder: b}
}

// FilesScanned sets the number of files scanned.
func (b *ScanBuilder) FilesScanned(count int) *ScanBuilder {
	b.Set(FieldFilesScanned, count)
	return b
}

// ThreatsFound sets the number of threats found.
func (b *ScanBuilder) ThreatsFound(count int) *ScanBuilder {
	b.Set(FieldThreatsFound, count)
	return b
}

// Path sets the path being scanned.
func (b *ScanBuilder) Path(path string) *ScanBuilder {
	b.Set(FieldPath, path)
	return b
}

// IPCRequestBuilder is a typed builder for IPC request events.
type IPCRequestBuilder struct {
	*Builder
}

// StartIPCRequest creates a new IPC request event builder.
func StartIPCRequest(command, requestID string) *IPCRequestBuilder {
	b := Start(EventTypeIPCRequest, "ipc")
	b.Set(FieldCommand, command)
	b.Set(FieldRequestID, requestID)
	return &IPCRequestBuilder{Builder: b}
}

// ClientVersion sets the client protocol version.
func (b *IPCRequestBuilder) ClientVersion(version int) *IPCRequestBuilder {
	b.Set(FieldClientVersion, version)
	return b
}

// ResponseSize sets the response size in bytes.
func (b *IPCRequestBuilder) ResponseSize(bytes int) *IPCRequestBuilder {
	b.Set(FieldResponseSize, bytes)
	return b
}

// StateChangeBuilder is a typed builder for state change events.
type StateChangeBuilder struct {
	*Builder
}

// StartStateChange creates a new state change event builder.
func StartStateChange(fromState, toState string) *StateChangeBuilder {
	b := Start(EventTypeStateChange, "daemon")
	b.Set(FieldFromState, fromState)
	b.Set(FieldToState, toState)
	return &StateChangeBuilder{Builder: b}
}

// Reason sets the reason for the state change.
func (b *StateChangeBuilder) Reason(reason string) *StateChangeBuilder {
	b.Set(FieldReason, reason)
	return b
}

// ThreatBuilder is a typed builder for threat detection events.
type ThreatBuilder struct {
	*Builder
}

// StartThreat creates a new threat detection event builder.
func StartThreat(path, threatName string) *ThreatBuilder {
	b := Start(EventTypeThreat, "scanner")
	b.Set(FieldPath, path)
	b.Set(FieldThreatName, threatName)
	return &ThreatBuilder{Builder: b}
}

// Action sets the action taken on the threat.
func (b *ThreatBuilder) Action(action string) *ThreatBuilder {
	b.Set(FieldAction, action)
	return b
}

// FileSize sets the size of the infected file.
func (b *ThreatBuilder) FileSize(bytes int64) *ThreatBuilder {
	b.Set(FieldFileSizeBytes, bytes)
	return b
}

// HealthCheckBuilder is a typed builder for health check events.
type HealthCheckBuilder struct {
	*Builder
}

// StartHealthCheck creates a new health check event builder.
func StartHealthCheck() *HealthCheckBuilder {
	b := Start(EventTypeHealthCheck, "daemon")
	return &HealthCheckBuilder{Builder: b}
}

// ClamAVAvailable sets whether ClamAV is available.
func (b *HealthCheckBuilder) ClamAVAvailable(available bool) *HealthCheckBuilder {
	b.Set(FieldClamAvailable, available)
	return b
}

// FirewallEnabled sets whether the firewall is enabled.
func (b *HealthCheckBuilder) FirewallEnabled(enabled bool) *HealthCheckBuilder {
	b.Set(FieldFWEnabled, enabled)
	return b
}
