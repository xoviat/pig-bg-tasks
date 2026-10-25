module example.com/pig-bg-tasks

go 1.26

require (
	// Pig resolves this requirement to the version-matched staged SDK at build time.
	github.com/MichaelKinsy/PiG/extensions/sdk v0.0.0
	golang.org/x/sys v0.49.0
)
require example.com/srt-win v0.0.0

replace example.com/srt-win => ./srt-win
