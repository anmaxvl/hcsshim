package logging

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
)

// Config is passed to the binary logging function
type Config struct {
	ID        string
	Namespace string
	Stdout    io.Reader
	Stderr    io.Reader
}

// LoggerFunc is a binary logging function signature
type LoggerFunc func(context.Context, *Config, func() error) error

// Run runs LoggerFunc
func Run(fn LoggerFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var errCh = make(chan error, 0)

	sout, _ := winio.DialPipeContext(ctx, os.Getenv("CONTAINER_STDOUT"))
	serr, _ := winio.DialPipeContext(ctx, os.Getenv("CONTAINER_STDERR"))
	wait, _ := winio.DialPipeContext(ctx, os.Getenv("CONTAINER_WAIT"))

	config := &Config{
		ID:        os.Getenv("CONTAINER_ID"),
		Namespace: os.Getenv("CONTAINER_NAMESPACE"),
		Stdout:    sout,
		Stderr:    serr,
	}

	// Write to wait pipe
	ready := func() error {
		wait.Write([]byte("#"))
		return wait.Close()
	}

	f, _ := os.Create("C:/Users/Administrator/LCOW/binary-results.txt")
	defer f.Close()

	w := bufio.NewWriter(f)
	w.WriteString("Starting logging goroutine\n")
	w.Flush()

	go func() {
		if err := fn(ctx, config, ready); err != nil {
			w.WriteString("Binary exited with error. sending error via channel\n")
			w.Flush()
			errCh <- err
			return
		}
		w.WriteString("Binary exited normally.\n")
		w.Flush()
		errCh <- nil
	}()

	w.WriteString("Started logging goroutine\n")
	w.Flush()

	for {
		select {
		case err := <-errCh:
			w.WriteString(fmt.Sprintf("Received from error channel: %s\n", err))
			w.Flush()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		default:
			w.WriteString("Nothing received, sleeping for 500ms\n")
			w.Flush()
			time.Sleep(500 * time.Millisecond)
		}
	}
}
