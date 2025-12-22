// oreon/defense · watchthelight <wtl>

package scanner

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	scanner := New("/tmp/test.sock")
	if scanner.socketPath != "/tmp/test.sock" {
		t.Errorf("socketPath = %v, want /tmp/test.sock", scanner.socketPath)
	}
}

func TestIsAvailable_NoSocket(t *testing.T) {
	scanner := New("/nonexistent/socket.sock")
	if scanner.IsAvailable() {
		t.Error("IsAvailable() = true for nonexistent socket")
	}
}

// mockClamdServer creates a mock ClamAV daemon for testing
func mockClamdServer(t *testing.T, handler func(conn net.Conn)) (string, func()) {
	t.Helper()

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "clamd.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()

	return sockPath, func() { listener.Close() }
}

func TestPing_Success(t *testing.T) {
	sockPath, cleanup := mockClamdServer(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		cmd, _ := reader.ReadString('\n')
		if cmd == "PING\n" {
			conn.Write([]byte("PONG\n"))
		}
	})
	defer cleanup()

	scanner := New(sockPath)
	if err := scanner.Ping(); err != nil {
		t.Errorf("Ping() error = %v", err)
	}
}

func TestPing_WrongResponse(t *testing.T) {
	sockPath, cleanup := mockClamdServer(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		reader.ReadString('\n')
		conn.Write([]byte("WRONG\n"))
	})
	defer cleanup()

	scanner := New(sockPath)
	if err := scanner.Ping(); err == nil {
		t.Error("Ping() should fail on wrong response")
	}
}

func TestScanFile_Clean(t *testing.T) {
	sockPath, cleanup := mockClamdServer(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		cmd, _ := reader.ReadString('\n')
		// Parse: SCAN /path/to/file
		if len(cmd) > 5 {
			path := cmd[5 : len(cmd)-1] // remove "SCAN " and "\n"
			conn.Write([]byte(path + ": OK\n"))
		}
	})
	defer cleanup()

	// Create a temp file to scan
	tmpFile := filepath.Join(t.TempDir(), "clean.txt")
	os.WriteFile(tmpFile, []byte("clean content"), 0644)

	scanner := New(sockPath)
	result := scanner.ScanFile(tmpFile)

	if result.Error != nil {
		t.Errorf("ScanFile() error = %v", result.Error)
	}
	if !result.Clean {
		t.Error("ScanFile() Clean = false, want true")
	}
	if result.Threat != "" {
		t.Errorf("ScanFile() Threat = %v, want empty", result.Threat)
	}
}

func TestScanFile_ThreatFound(t *testing.T) {
	sockPath, cleanup := mockClamdServer(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		cmd, _ := reader.ReadString('\n')
		if len(cmd) > 5 {
			path := cmd[5 : len(cmd)-1]
			conn.Write([]byte(path + ": Eicar-Test-Signature FOUND\n"))
		}
	})
	defer cleanup()

	tmpFile := filepath.Join(t.TempDir(), "infected.txt")
	os.WriteFile(tmpFile, []byte("test"), 0644)

	scanner := New(sockPath)
	result := scanner.ScanFile(tmpFile)

	if result.Error != nil {
		t.Errorf("ScanFile() error = %v", result.Error)
	}
	if result.Clean {
		t.Error("ScanFile() Clean = true, want false")
	}
	if result.Threat != "Eicar-Test-Signature" {
		t.Errorf("ScanFile() Threat = %v, want Eicar-Test-Signature", result.Threat)
	}
}

func TestScanFile_Error(t *testing.T) {
	sockPath, cleanup := mockClamdServer(t, func(conn net.Conn) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		reader.ReadString('\n')
		conn.Write([]byte("/path: lstat() failed: No such file. ERROR\n"))
	})
	defer cleanup()

	scanner := New(sockPath)
	result := scanner.ScanFile("/nonexistent/file")

	if result.Error == nil {
		t.Error("ScanFile() should return error for ERROR response")
	}
}

func TestScanFile_ConnectionError(t *testing.T) {
	scanner := New("/nonexistent/socket.sock")
	result := scanner.ScanFile("/some/file")

	if result.Error == nil {
		t.Error("ScanFile() should return error when can't connect")
	}
}
