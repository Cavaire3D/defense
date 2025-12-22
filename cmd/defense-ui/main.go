// oreon/defense · watchthelight <wtl>

package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/oreonproject/defense/internal/tray"
	"github.com/oreonproject/defense/pkg/ipc"
)

var version = "0.1.0-dev"

func main() {
	fmt.Printf("Oreon Defense v%s\n", version)

	// Create a channel to listen for interrupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Initialize the IPC client (connects lazily on first call)
	client := ipc.NewClient("/run/oreon/defense.sock")

	// Create and run the system tray
	trayApp := tray.New(client)

	// Run the tray in a goroutine so we can handle shutdown gracefully
	errCh := make(chan error, 1)
	go func() {
		errCh <- trayApp.Run()
	}()

	// Wait for either interrupt signal or tray exit
	select {
	case <-sigCh:
		slog.Info("received interrupt, shutting down")
	case err := <-errCh:
		if err != nil {
			slog.Error("tray application error", "error", err)
		}
	}

	// Cleanup
	client.Close()
}
