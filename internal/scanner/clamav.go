// oreon/defense · watchthelight <wtl>

package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// ClamAV provides an interface to the ClamAV daemon.
type ClamAV struct {
	socketPath string
}

// New creates a new ClamAV scanner instance.
func New(socketPath string) *ClamAV {
	return &ClamAV{
		socketPath: socketPath,
	}
}

// IsAvailable checks if the ClamAV daemon is reachable.
func (c *ClamAV) IsAvailable() bool {
	if _, err := os.Stat(c.socketPath); err != nil {
		return false
	}
	return c.Ping() == nil
}

// ScanResult represents the result of scanning a file.
type ScanResult struct {
	Path      string
	Clean     bool
	Threat    string
	Error     error
	ScannedAt time.Time
}

// Ping sends a PING command to clamd and expects PONG.
func (c *ClamAV) Ping() error {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to clamd: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte("PING\n"))
	if err != nil {
		return fmt.Errorf("send PING: %w", err)
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if strings.TrimSpace(response) != "PONG" {
		return fmt.Errorf("unexpected response: %s", response)
	}

	return nil
}

// ScanFile scans a single file using clamd.
func (c *ClamAV) ScanFile(path string) *ScanResult {
	result := &ScanResult{
		Path:      path,
		ScannedAt: time.Now(),
	}

	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		result.Error = fmt.Errorf("connect to clamd: %w", err)
		return result
	}
	defer conn.Close()

	// Use longer timeout for scanning
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	// Send SCAN command with file path
	_, err = fmt.Fprintf(conn, "SCAN %s\n", path)
	if err != nil {
		result.Error = fmt.Errorf("send SCAN command: %w", err)
		return result
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		result.Error = fmt.Errorf("read scan response: %w", err)
		return result
	}

	// Parse response: "/path: OK" or "/path: ThreatName FOUND"
	response = strings.TrimSpace(response)
	if strings.HasSuffix(response, " OK") {
		result.Clean = true
	} else if strings.HasSuffix(response, " FOUND") {
		// Extract threat name: everything between ": " and " FOUND"
		colonIdx := strings.LastIndex(response, ": ")
		if colonIdx != -1 {
			threat := response[colonIdx+2 : len(response)-6] // -6 for " FOUND"
			result.Threat = threat
		}
		result.Clean = false
	} else if strings.Contains(response, "ERROR") {
		result.Error = fmt.Errorf("clamd error: %s", response)
	}

	return result
}
