package unixsocket

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// Listen prepares a Unix socket path, starts listening, and applies the
// permissions required by the local PHP or Nginx process.
func Listen(socket, group, label string) (net.Listener, error) {
	if socket == "" || !filepath.IsAbs(socket) {
		return nil, fmt.Errorf("%s socket must be an absolute path", label)
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0750); err != nil {
		return nil, fmt.Errorf("create %s socket directory: %w", label, err)
	}

	info, err := os.Lstat(socket)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket path %q", socket)
		}
		if err := os.Remove(socket); err != nil {
			return nil, fmt.Errorf("remove stale %s socket: %w", label, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect %s socket: %w", label, err)
	}

	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen on %s socket: %w", label, err)
	}

	cleanup := func() {
		_ = listener.Close()
		_ = os.Remove(socket)
	}
	if err := os.Chmod(socket, 0660); err != nil {
		cleanup()
		return nil, fmt.Errorf("set %s socket permissions: %w", label, err)
	}
	if err := setGroup(socket, group, label); err != nil {
		cleanup()
		return nil, err
	}

	return listener, nil
}

func setGroup(socket, group, label string) error {
	if group == "" {
		return nil
	}

	gid, err := strconv.Atoi(group)
	if err != nil {
		groupInfo, lookupErr := user.LookupGroup(group)
		if lookupErr != nil {
			return fmt.Errorf("lookup %s socket group: %w", label, lookupErr)
		}
		gid, err = strconv.Atoi(groupInfo.Gid)
		if err != nil {
			return fmt.Errorf("parse %s socket group ID: %w", label, err)
		}
	}

	if err := os.Chown(socket, -1, gid); err != nil {
		return fmt.Errorf("set %s socket group: %w", label, err)
	}

	return nil
}
