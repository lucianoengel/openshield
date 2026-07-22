package exfil

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]Channel{
		"/media/usb0/report.pdf":          ChannelRemovable,
		"/run/media/alice/STICK/x.docx":   ChannelRemovable,
		"/mnt/backup/db.sql":              ChannelRemovable,
		"/media":                          ChannelRemovable, // the root itself
		"/home/alice/Dropbox/secret.xlsx": ChannelCloudSync,
		"~/OneDrive/y.txt":                ChannelCloudSync,
		"/home/u/Google Drive/z.csv":      ChannelCloudSync,
		"/home/u/dropbox/lower.txt":       ChannelCloudSync, // case-insensitive
		"/home/alice/docs/notes.txt":      ChannelLocal,
		"/tmp/scratch":                    ChannelLocal,
		"":                                ChannelLocal,
		// A folder merely CONTAINING "dropbox" as a substring is NOT a match —
		// component match, not substring.
		"/home/u/dropboxes/x": ChannelLocal,
		"/home/u/mydropbox/x": ChannelLocal,
		// "/media" as a substring of a non-root component is not removable.
		"/home/u/mediafiles/x": ChannelLocal,
	}
	for p, want := range cases {
		if got := Classify(p); got != want {
			t.Errorf("Classify(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestClassifyCustomConfig(t *testing.T) {
	c := NewWith([]string{"/removable"}, []string{"MegaSync"})
	if c.Classify("/removable/dev/x") != ChannelRemovable {
		t.Error("custom removable root not honored")
	}
	if c.Classify("/home/u/MegaSync/x") != ChannelCloudSync {
		t.Error("custom cloud folder not honored")
	}
	// The defaults are NOT active in the custom classifier.
	if c.Classify("/media/usb/x") != ChannelLocal {
		t.Error("custom classifier should not use the default removable roots")
	}
	if c.Classify("/home/u/Dropbox/x") != ChannelLocal {
		t.Error("custom classifier should not use the default cloud folders")
	}
}

func TestChannelString(t *testing.T) {
	for c, want := range map[Channel]string{
		ChannelLocal: "local", ChannelRemovable: "removable", ChannelCloudSync: "cloud_sync",
	} {
		if c.String() != want {
			t.Errorf("Channel(%d).String() = %q, want %q", c, c.String(), want)
		}
	}
}
