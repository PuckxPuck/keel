package buildinfo

import (
	"runtime"
	"runtime/debug"
	"sync"
)

// Set at link time: -ldflags "-X github.com/PuckxPuck/keel/internal/kit/buildinfo.version=v1.2.3".
var (
	version   = ""
	commit    = ""
	buildTime = ""
)

const devVersion = "dev"

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	Modified  bool   `json:"modified"`
}

var get = sync.OnceValue(func() Info {
	bi, _ := debug.ReadBuildInfo()
	return resolve(version, commit, buildTime, bi)
})

func Get() Info { return get() }

// resolve prefers link-time values and fills gaps from the VCS data Go embeds.
func resolve(version, commit, buildTime string, bi *debug.BuildInfo) Info {
	info := Info{Version: version, Commit: commit, BuildTime: buildTime, GoVersion: runtime.Version()}
	if bi != nil {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.BuildTime == "" {
					info.BuildTime = s.Value
				}
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
	}
	if info.Version == "" {
		info.Version = devVersion
	}
	return info
}
