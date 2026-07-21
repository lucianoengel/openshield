//go:build !linux

package fanotify

import (
	"context"
	"errors"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

var ErrUnsupported = errors.New("fanotify: not supported on this platform")

type Watcher struct{}

func Open(string) (*Watcher, error)                          { return nil, ErrUnsupported }
func (*Watcher) Next(context.Context) (*corev1.Event, error) { return nil, ErrUnsupported }
func (*Watcher) Close() error                                { return ErrUnsupported }
