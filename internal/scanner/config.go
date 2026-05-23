package scanner

import "time"

// ScanConfig holds all tunable parameters for a port scan.
type ScanConfig struct {
	Threads  int
	Timeout  time.Duration
	Rate     int // max packets per second
	Jitter   bool
	Preset   string
	Fast     bool
}

// DefaultConfig returns safe defaults — user must pick a preset explicitly.
func DefaultConfig() ScanConfig {
	return ScanConfig{
		Threads: 500,
		Timeout: 800 * time.Millisecond,
		Rate:    500,
		Jitter:  false,
		Preset:  "lan",
	}
}

// ApplyPreset overwrites config values based on the chosen preset.
func ApplyPreset(cfg *ScanConfig, preset string, fast bool) {
	switch preset {
	case "public":
		cfg.Threads = 75
		cfg.Timeout = 3 * time.Second
		cfg.Rate = 15
		cfg.Jitter = true
		cfg.Preset = "public"

		// --fast loosens the limits a bit — user accepts the risk
		if fast {
			cfg.Threads = 150
			cfg.Timeout = 1500 * time.Millisecond
			cfg.Rate = 50
		}

	default: // lan
		cfg.Threads = 500
		cfg.Timeout = 800 * time.Millisecond
		cfg.Rate = 500
		cfg.Jitter = false
		cfg.Preset = "lan"
	}

	cfg.Fast = fast
}
