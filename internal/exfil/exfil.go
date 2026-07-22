// Package exfil classifies which exfiltration channel a file event is on (DLP-2):
// removable media, a cloud-sync folder, or local. The channel is what turns a file
// write into an exfiltration signal — sensitive content landing in ~/Dropbox or on a
// USB stick is exfil; the same content in a temp dir is not. A DLP that watches
// directories but not the channels users exfiltrate through is not a DLP.
//
// Classification is a pure, content-free function of the PATH: it never opens the
// file or resolves mounts at runtime (a blocking syscall in the decision path, D24).
package exfil

import (
	"path"
	"strings"
)

// Channel is the exfiltration channel a file path is on.
type Channel int

const (
	// ChannelLocal is the explicit default — a path on no exfil channel. It is a
	// value, not an absence, so a policy reads a concrete channel for every file.
	ChannelLocal Channel = iota
	// ChannelRemovable is a path under a removable-media mount root.
	ChannelRemovable
	// ChannelCloudSync is a path inside a cloud-sync folder.
	ChannelCloudSync
)

// String returns a stable lowercase token for the policy input.
func (c Channel) String() string {
	switch c {
	case ChannelRemovable:
		return "removable"
	case ChannelCloudSync:
		return "cloud_sync"
	default:
		return "local"
	}
}

// Classifier maps a path to an exfil channel. Its roots and folder names are
// configurable — an operator's fleet may mount elsewhere or use a different sync
// client — with sensible defaults.
type Classifier struct {
	removableRoots []string
	cloudFolders   []string // lowercased path components
}

// DefaultRemovableRoots are the well-known removable-media mount roots on Linux.
var DefaultRemovableRoots = []string{"/media", "/run/media", "/mnt"}

// DefaultCloudFolders are common cloud-sync folder names (matched as a whole path
// component, case-insensitively).
var DefaultCloudFolders = []string{"dropbox", "onedrive", "google drive", "icloud drive", "box", ".dropbox"}

// New returns a classifier with the default roots and cloud folders.
func New() *Classifier {
	return NewWith(DefaultRemovableRoots, DefaultCloudFolders)
}

// NewWith returns a classifier with explicit removable roots and cloud-sync folder
// names (folder names are matched case-insensitively as whole path components).
func NewWith(removableRoots, cloudFolders []string) *Classifier {
	lc := make([]string, len(cloudFolders))
	for i, f := range cloudFolders {
		lc[i] = strings.ToLower(f)
	}
	return &Classifier{removableRoots: append([]string(nil), removableRoots...), cloudFolders: lc}
}

// Classify returns the exfil channel for a file path. Removable (a mount-root
// prefix) takes precedence over cloud-sync; a path matching neither is local.
func (c *Classifier) Classify(p string) Channel {
	if p == "" {
		return ChannelLocal
	}
	clean := path.Clean(p)
	for _, root := range c.removableRoots {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return ChannelRemovable
		}
	}
	// Cloud-sync: a WHOLE path component matches a configured folder name (so
	// ~/Dropbox/x matches regardless of home, but a folder named "dropboxes" does
	// not — a component match, not a substring).
	for _, comp := range strings.Split(clean, "/") {
		lc := strings.ToLower(comp)
		for _, folder := range c.cloudFolders {
			if lc == folder {
				return ChannelCloudSync
			}
		}
	}
	return ChannelLocal
}

// Default is a package-level classifier with the default configuration.
var Default = New()

// Classify uses the default classifier.
func Classify(p string) Channel { return Default.Classify(p) }
