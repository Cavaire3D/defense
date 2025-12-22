// oreon/defense · watchthelight <wtl>

package daemon

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/oreonproject/defense/pkg/config"
	"github.com/oreonproject/defense/pkg/ipc"
)

func setupTestServer(t *testing.T) (*Server, string, func()) {
	t.Helper()

	cfg := &config.Config{}
	d := New(cfg, slog.Default())
	d.State().SetState(StateProtected)

	sockPath := t.TempDir() + "/test.sock"
	server := NewServer(sockPath, d)

	if err := server.Listen(); err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	go server.Serve()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	return server, sockPath, func() { server.Close() }
}

func sendRequest(t *testing.T, sockPath string, req *ipc.Request) *ipc.Response {
	t.Helper()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	data, _ := json.Marshal(req)
	data = append(data, '\n')
	conn.Write(data)

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	var resp ipc.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	return &resp
}

func TestServer_Ping(t *testing.T) {
	_, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	resp := sendRequest(t, sockPath, &ipc.Request{
		ID:      "1",
		Command: ipc.CmdPing,
	})

	if !resp.Success {
		t.Errorf("Success = false, want true")
	}
}

func TestServer_Status(t *testing.T) {
	_, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	resp := sendRequest(t, sockPath, &ipc.Request{
		ID:      "1",
		Command: ipc.CmdStatus,
	})

	if !resp.Success {
		t.Fatalf("Success = false, error: %s", resp.Error)
	}

	var status ipc.StatusResponse
	if err := resp.UnmarshalData(&status); err != nil {
		t.Fatalf("UnmarshalData error: %v", err)
	}

	if status.State != "protected" {
		t.Errorf("State = %v, want protected", status.State)
	}
}

func TestServer_FirewallToggle(t *testing.T) {
	server, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	// Enable firewall
	resp := sendRequest(t, sockPath, &ipc.Request{
		ID:      "1",
		Command: ipc.CmdFirewallEnable,
	})
	if !resp.Success {
		t.Fatalf("FirewallEnable failed: %s", resp.Error)
	}
	if !server.daemon.FirewallEnabled() {
		t.Error("FirewallEnabled() = false after enable")
	}

	// Disable firewall
	resp = sendRequest(t, sockPath, &ipc.Request{
		ID:      "2",
		Command: ipc.CmdFirewallDisable,
	})
	if !resp.Success {
		t.Fatalf("FirewallDisable failed: %s", resp.Error)
	}
	if server.daemon.FirewallEnabled() {
		t.Error("FirewallEnabled() = true after disable")
	}
}

func TestServer_PauseResume(t *testing.T) {
	server, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	// Pause
	resp := sendRequest(t, sockPath, &ipc.Request{
		ID:      "1",
		Command: ipc.CmdPause,
	})
	if !resp.Success {
		t.Fatalf("Pause failed: %s", resp.Error)
	}
	time.Sleep(20 * time.Millisecond) // wait for async state change
	if server.daemon.State().State() != StatePaused {
		t.Errorf("State = %v, want StatePaused", server.daemon.State().State())
	}

	// Resume
	resp = sendRequest(t, sockPath, &ipc.Request{
		ID:      "2",
		Command: ipc.CmdResume,
	})
	if !resp.Success {
		t.Fatalf("Resume failed: %s", resp.Error)
	}
	time.Sleep(20 * time.Millisecond)
	if server.daemon.State().State() != StateProtected {
		t.Errorf("State = %v, want StateProtected", server.daemon.State().State())
	}
}

func TestServer_ScanQuick(t *testing.T) {
	_, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	resp := sendRequest(t, sockPath, &ipc.Request{
		ID:      "1",
		Command: ipc.CmdScanQuick,
	})

	if !resp.Success {
		t.Fatalf("ScanQuick failed: %s", resp.Error)
	}

	var scanResp ipc.ScanResponse
	if err := resp.UnmarshalData(&scanResp); err != nil {
		t.Fatalf("UnmarshalData error: %v", err)
	}

	if scanResp.JobID == "" {
		t.Error("JobID is empty")
	}
}

func TestServer_UnknownCommand(t *testing.T) {
	_, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	resp := sendRequest(t, sockPath, &ipc.Request{
		ID:      "1",
		Command: "unknown_command",
	})

	if resp.Success {
		t.Error("Success = true for unknown command")
	}
	if resp.Error == "" {
		t.Error("Error is empty for unknown command")
	}
}

func TestServer_InvalidJSON(t *testing.T) {
	_, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	// Send invalid JSON
	conn.Write([]byte("not valid json\n"))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	var resp ipc.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Success {
		t.Error("Success = true for invalid JSON")
	}
}

func TestServer_ProtocolVersion(t *testing.T) {
	_, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	// Send with matching version
	resp := sendRequest(t, sockPath, &ipc.Request{
		Version: ipc.ProtocolVersion,
		ID:      "1",
		Command: ipc.CmdPing,
	})

	if !resp.Success {
		t.Errorf("Success = false with matching version")
	}
}

func TestServer_BadVersion(t *testing.T) {
	_, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	// Send with wrong version
	resp := sendRequest(t, sockPath, &ipc.Request{
		Version: 999, // future version
		ID:      "1",
		Command: ipc.CmdPing,
	})

	if resp.Success {
		t.Error("Success = true for mismatched version")
	}
	if resp.Error == "" {
		t.Error("Error is empty for mismatched version")
	}
}

func TestServer_LegacyClient(t *testing.T) {
	_, sockPath, cleanup := setupTestServer(t)
	defer cleanup()

	// Send with version 0 (legacy client)
	resp := sendRequest(t, sockPath, &ipc.Request{
		Version: 0,
		ID:      "1",
		Command: ipc.CmdPing,
	})

	if !resp.Success {
		t.Error("Success = false for version 0 (legacy client)")
	}
}
