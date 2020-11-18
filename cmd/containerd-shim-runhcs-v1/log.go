/*
Example logger, which writes to 2 different files
*/

package main

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/Microsoft/hcsshim/cmd/logging"
)

func _main() {
	logging.Run(logger)
}

func logger(_ context.Context, config *logging.Config, ready func() error) error {
	var wg sync.WaitGroup
	wg.Add(2)

	fileOut, err := os.Create("C:/Users/Administrator/LCOW/container-stdout.txt")
	defer fileOut.Close()
	if err != nil {
		return err
	}

	fileErr, err := os.Create("C:/Users/Administrator/LCOW/container-stderr.txt")
	defer fileErr.Close()
	if err != nil {
		return err
	}

	go func() {
		defer wg.Done()
		io.Copy(fileOut, config.Stdout)
	}()

	go func() {
		defer wg.Done()
		io.Copy(fileErr, config.Stderr)
	}()

	if err := ready(); err != nil {
		return err
	}

	wg.Wait()
	return nil
}
