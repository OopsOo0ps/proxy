package version

import (
	"strings"
	"testing"
)

func TestGetReportsCurrentBuild(t *testing.T) {
	info := Get()
	if info.Version != Version {
		t.Fatalf("Version = %q, want %q", info.Version, Version)
	}
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Fatalf("GoVersion = %q, want go prefix", info.GoVersion)
	}
	if !strings.Contains(info.Platform, "/") {
		t.Fatalf("Platform = %q, want os/arch", info.Platform)
	}
}

func TestStringIncludesAllFields(t *testing.T) {
	info := Info{
		Version:   "v1.2.3",
		Commit:    "abc1234",
		BuildDate: "2026-01-01T00:00:00Z",
		GoVersion: "go1.25.0",
		Platform:  "linux/amd64",
	}
	got := info.String()
	for _, want := range []string{"v1.2.3", "abc1234", "2026-01-01T00:00:00Z", "go1.25.0", "linux/amd64"} {
		if !strings.Contains(got, want) {
			t.Fatalf("String() = %q, missing %q", got, want)
		}
	}
}
