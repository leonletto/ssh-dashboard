package internal

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
	GitTag    = "unknown"
)

func FullVersion() string {
	if Version == "dev" && GitCommit != "unknown" {
		return "dev+" + GitCommit[:8]
	}
	return Version
}

func ShortVersion() string {
	return Version
}
