package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/pkg/errors"
)

const pipeRootBinary = `\\.\pipe`
const binaryCmdWaitTimeout = 5 * time.Second

func newBinaryCmd(ctx context.Context, uri *url.URL, id string, ns string) *exec.Cmd {
	var args []string
	for k, vs := range uri.Query() {
		args = append(args, k)
		if len(vs) > 0 {
			args = append(args, vs[0])
		}
	}

	execPath := uri.Path

	cmd := exec.CommandContext(ctx, execPath, args...)
	cmd.Env = append(cmd.Env,
		"CONTAINER_ID="+id,
		"CONTAINER_NAMESPACE="+ns,
	)

	return cmd
}

type binaryIO struct {
	cmd *exec.Cmd

	binaryCloser sync.Once

	stdin, stdout, stderr string

	sout, serr, wait io.ReadWriteCloser
	soutCloser       sync.Once
}

// NewBinaryIO starts a binary logger
func NewBinaryIO(ctx context.Context, id string, uri *url.URL) (_ UpstreamIO, err error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}

	var (
		sout, serr, w io.ReadWriteCloser = nil, nil, nil
	)

	bio := &binaryIO{}

	stdoutPipe := fmt.Sprintf(`%s\binary-%s-stdout`, pipeRootBinary, id)
	sout, err = openNPipe(stdoutPipe)
	if err != nil {
		return nil, err
	}
	bio.stdout = stdoutPipe
	bio.sout = sout

	stderrPipe := fmt.Sprintf(`%s\binary-%s-stderr`, pipeRootBinary, id)
	serr, err = openNPipe(stderrPipe)
	if err != nil {
		return nil, err
	}
	bio.stderr = stderrPipe
	bio.serr = serr

	waitPipe := fmt.Sprintf(`%s\binary-%s-wait`, pipeRootBinary, id)
	w, err = openNPipe(waitPipe)
	if err != nil {
		return nil, err
	}
	bio.wait = w

	cmd := newBinaryCmd(ctx, uri, id, ns)
	cmd.Env = append(cmd.Env,
		"CONTAINER_STDOUT="+stdoutPipe,
		"CONTAINER_STDERR="+stderrPipe,
		"CONTAINER_WAIT="+waitPipe,
	)

	bio.cmd = cmd

	started := make(chan bool, 1)
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		defer w.Close()
		t := 0
		for {
			b := make([]byte, 1)
			v, err := w.Read(b)
			if (v == 0) || err != nil && err != io.EOF {
				log.G(ctx).Debugf("Failed to read from wait pipe. Sleeping")
				time.Sleep(1 * time.Second)
				t++
				if t > 10 {
					break
				}
			} else {
				log.G(ctx).Debugf("Read from wait pipe. Binary started: %s", b)
				started <- true
				return
			}
		}
		started <- false
	}()

	if !<-started {
		return nil, errors.Errorf("Failed to started binary")
	}

	return bio, nil
}

var _ UpstreamIO = &binaryIO{}

func (b *binaryIO) Close(ctx context.Context) {
	b.soutCloser.Do(func() {
		if b.sout != nil {
			err := b.sout.Close()
			if err != nil {
				log.G(ctx).WithError(err).Errorf("Error while closing stdout npipe")
			}
		}
		if b.serr != nil {
			err := b.serr.Close()
			if err != nil {
				log.G(ctx).WithError(err).Errorf("Error while closing stderr npipe")
			}
		}
	})
	b.binaryCloser.Do(func() {
		// Borrowed this from Ming's PR
		log.G(ctx).Debugf("Waiting for binaryIO to exit: %d", b.cmd.Process.Pid)
		done := make(chan error, 1)
		go func() {
			done <- b.cmd.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				log.G(ctx).WithError(err).Errorf("Error while waiting for cmd to finish")
			} else {
				log.G(ctx).Debugf("binary_io::b.cmd.Wait() finished normally")
			}

		case <-time.After(binaryCmdWaitTimeout):
			log.G(ctx).Errorf("Timeout while waiting for binaryIO process to finish")
			err := b.cmd.Process.Kill()
			if err != nil {
				log.G(ctx).WithError(err).Errorf("Error while killing binaryIO process")
			}
			log.G(ctx).Debugln("BinaryIO process killed")
		}
	})
}

func (b *binaryIO) CloseStdin(ctx context.Context) {

}

func (b *binaryIO) Stdin() io.Reader {
	return nil
}

func (b *binaryIO) StdinPath() string {
	return ""
}

func (b *binaryIO) Stdout() io.Writer {
	return b.sout
}

func (b *binaryIO) StdoutPath() string {
	return b.stdout
}

func (b *binaryIO) Stderr() io.Writer {
	return b.serr
}

func (b *binaryIO) StderrPath() string {
	return b.stderr
}

func (b *binaryIO) Terminal() bool {
	return false
}

type pipe struct {
	l      net.Listener
	con    net.Conn
	conErr error
	conWg  sync.WaitGroup
}

func openNPipe(path string) (io.ReadWriteCloser, error) {
	l, err := winio.ListenPipe(path, nil)
	if err != nil {
		return nil, err
	}

	p := &pipe{l: l}
	p.conWg.Add(1)

	go func() {
		defer p.conWg.Done()
		c, err := l.Accept()
		if err != nil {
			p.conErr = err
			return
		}
		p.con = c
	}()
	return p, nil
}

func (p *pipe) Write(b []byte) (int, error) {
	p.conWg.Wait()
	if p.conErr != nil {
		return 0, errors.Wrap(p.conErr, "connection error")
	}
	return p.con.Write(b)
}

func (p *pipe) Read(b []byte) (int, error) {
	p.conWg.Wait()
	if p.conErr != nil {
		return 0, errors.Wrap(p.conErr, "connection error")
	}
	return p.con.Read(b)
}

func (p *pipe) Close() error {
	p.l.Close()
	p.conWg.Wait()
	if p.con != nil {
		err := p.con.Close()
		return err
	}
	return p.conErr
}
