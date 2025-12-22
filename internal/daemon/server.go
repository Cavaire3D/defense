// oreon/defense · watchthelight <wtl>

package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oreonproject/defense/pkg/events"
	"github.com/oreonproject/defense/pkg/ipc"
)

// Server handles IPC connections from clients (tray, CLI).
type Server struct {
	socketPath  string
	listener    net.Listener
	daemon      *Daemon
	done        chan struct{}
	subscribers map[net.Conn]bool
	subMu       sync.Mutex
}

// NewServer creates an IPC server that exposes daemon state.
func NewServer(socketPath string, daemon *Daemon) *Server {
	s := &Server{
		socketPath:  socketPath,
		daemon:      daemon,
		done:        make(chan struct{}),
		subscribers: make(map[net.Conn]bool),
	}

	// Register for state changes to push to subscribers
	daemon.State().OnStateChange(func(old, new State) {
		s.broadcastStateChange(old.String(), new.String())
	})

	return s
}

// Listen creates the unix socket and starts accepting connections.
func (s *Server) Listen() error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0755); err != nil {
		return err
	}

	// Remove stale socket if it exists
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	s.listener = ln

	// Set socket permissions (world accessible for user UI to connect)
	if err := os.Chmod(s.socketPath, 0666); err != nil {
		ln.Close()
		return err
	}

	slog.Info("IPC server listening", "socket", s.socketPath)
	return nil
}

// Serve accepts connections until Close is called.
func (s *Server) Serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return // shutdown
			default:
				slog.Warn("accept error", "error", err)
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

// Close shuts down the server.
func (s *Server) Close() error {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
	return nil
}

// subscribe adds a connection to the subscriber list.
func (s *Server) subscribe(conn net.Conn) {
	s.subMu.Lock()
	s.subscribers[conn] = true
	s.subMu.Unlock()
	slog.Debug("client subscribed", "remote", conn.RemoteAddr())
}

// unsubscribe removes a connection from the subscriber list.
func (s *Server) unsubscribe(conn net.Conn) {
	s.subMu.Lock()
	delete(s.subscribers, conn)
	s.subMu.Unlock()
}

// broadcastStateChange sends state change events to all subscribers.
func (s *Server) broadcastStateChange(oldState, newState string) {
	event := ipc.StateChangeEvent{
		OldState: oldState,
		NewState: newState,
	}
	resp := makeResponse("event", event)

	s.subMu.Lock()
	subscribers := make([]net.Conn, 0, len(s.subscribers))
	for conn := range s.subscribers {
		subscribers = append(subscribers, conn)
	}
	s.subMu.Unlock()

	for _, conn := range subscribers {
		encoder := json.NewEncoder(conn)
		if err := encoder.Encode(resp); err != nil {
			slog.Debug("failed to send event to subscriber", "error", err)
			s.unsubscribe(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer s.unsubscribe(conn) // clean up subscription on disconnect

	reader := bufio.NewReader(conn)
	encoder := json.NewEncoder(conn)

	for {
		// Read one line (one JSON request)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return // client disconnected
		}

		var req ipc.Request
		if err := json.Unmarshal(line, &req); err != nil {
			if err := encoder.Encode(ipc.Response{
				Success: false,
				Error:   "invalid JSON",
			}); err != nil {
				slog.Warn("failed to encode error response", "error", err)
				return
			}
			continue
		}

		// Handle subscribe specially - it registers this connection for push events
		if req.Command == ipc.CmdSubscribe {
			s.subscribe(conn)
			resp := makeResponse(req.ID, "subscribed")
			if err := encoder.Encode(resp); err != nil {
				slog.Warn("failed to encode response", "error", err)
				return
			}
			continue
		}

		resp := s.handleRequest(&req)
		if err := encoder.Encode(resp); err != nil {
			slog.Warn("failed to encode response", "error", err)
			return
		}
	}
}

// makeResponse creates a response with properly marshaled data.
func makeResponse(id string, data interface{}) *ipc.Response {
	resp := &ipc.Response{ID: id, Success: true}
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return &ipc.Response{ID: id, Success: false, Error: "marshal error: " + err.Error()}
		}
		resp.Data = jsonData
	}
	return resp
}

func (s *Server) handleRequest(req *ipc.Request) *ipc.Response {
	evt := events.StartIPCRequest(req.Command, req.ID).ClientVersion(req.Version)
	var resp *ipc.Response
	defer func() {
		if resp != nil && !resp.Success {
			evt.SetError(fmt.Errorf("%s", resp.Error))
		}
		if resp != nil {
			evt.ResponseSize(len(resp.Data))
		}
		s.daemon.Events().Emit(evt.End())
	}()

	// Check protocol version (0 means old client that didn't send version)
	if req.Version != 0 && req.Version != ipc.ProtocolVersion {
		resp = &ipc.Response{
			ID:      req.ID,
			Success: false,
			Error:   fmt.Sprintf("protocol version mismatch: client=%d, server=%d", req.Version, ipc.ProtocolVersion),
		}
		return resp
	}

	switch req.Command {
	case ipc.CmdPing:
		resp = makeResponse(req.ID, "pong")

	case ipc.CmdStatus:
		resp = makeResponse(req.ID, ipc.StatusResponse{
			State:           s.daemon.State().State().String(),
			FirewallEnabled: s.daemon.FirewallEnabled(),
			LastScan:        s.daemon.LastScan(),
			RulesUpdated:    s.daemon.RulesUpdated(),
		})

	case ipc.CmdFirewallEnable:
		s.daemon.SetFirewallEnabled(true)
		resp = makeResponse(req.ID, "firewall enabled")

	case ipc.CmdFirewallDisable:
		s.daemon.SetFirewallEnabled(false)
		resp = makeResponse(req.ID, "firewall disabled")

	case ipc.CmdFirewallStatus:
		resp = makeResponse(req.ID, ipc.FirewallStatusResponse{
			Enabled: s.daemon.FirewallEnabled(),
		})

	case ipc.CmdScanQuick:
		s.daemon.State().SetState(StateScanning)
		go s.runScan("quick")
		resp = makeResponse(req.ID, ipc.ScanResponse{
			JobID: "quick-" + time.Now().Format("20060102-150405"),
		})

	case ipc.CmdScanFull:
		s.daemon.State().SetState(StateScanning)
		go s.runScan("full")
		resp = makeResponse(req.ID, ipc.ScanResponse{
			JobID: "full-" + time.Now().Format("20060102-150405"),
		})

	case ipc.CmdPause:
		s.daemon.State().SetState(StatePaused)
		resp = makeResponse(req.ID, "protection paused")

	case ipc.CmdResume:
		s.daemon.State().SetState(StateProtected)
		resp = makeResponse(req.ID, "protection resumed")

	default:
		resp = &ipc.Response{
			ID:      req.ID,
			Success: false,
			Error:   "unknown command: " + req.Command,
		}
	}

	return resp
}

// runScan performs a scan using ClamAV.
func (s *Server) runScan(scanType string) {
	jobID := scanType + "-" + time.Now().Format("20060102-150405")
	evt := events.StartScan(scanType, jobID)
	defer func() {
		s.daemon.Events().Emit(evt.End())
	}()

	if !s.daemon.Scanner().IsAvailable() {
		evt.SetError(fmt.Errorf("ClamAV not available"))
		s.daemon.State().SetState(StateWarning)
		return
	}

	var paths []string
	if scanType == "quick" {
		paths = s.daemon.Config().Scanning.QuickScanPaths
	} else {
		// Full scan: start from root (be careful with this)
		paths = []string{"/home", "/tmp", "/var/tmp"}
	}

	var filesScanned, threatsFound int
	for _, basePath := range paths {
		s.scanDirectory(basePath, &filesScanned, &threatsFound)
	}

	evt.FilesScanned(filesScanned).ThreatsFound(threatsFound)
	s.daemon.SetLastScan(time.Now())

	if threatsFound > 0 {
		s.daemon.State().SetState(StateAlert)
	} else {
		s.daemon.State().SetState(StateProtected)
	}
}

// scanDirectory recursively scans a directory.
func (s *Server) scanDirectory(basePath string, filesScanned, threatsFound *int) {
	filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if info.IsDir() {
			return nil
		}

		result := s.daemon.Scanner().ScanFile(path)
		if result.Error != nil {
			return nil // skip files that can't be scanned
		}

		*filesScanned++
		if !result.Clean {
			*threatsFound++
			// Emit threat detection event
			threatEvt := events.StartThreat(path, result.Threat).
				Action("detected").
				FileSize(info.Size())
			s.daemon.Events().Emit(threatEvt.End())
		}
		return nil
	})
}
