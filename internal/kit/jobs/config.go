package jobs

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is APP_JOBS_*.
type Config struct {
	InServe       bool          `env:"IN_SERVE" envDefault:"true"`
	Lanes         Lanes         `env:"LANES" envDefault:"fast:4,slow:1"`
	Lease         time.Duration `env:"LEASE" envDefault:"2m"`
	Poll          time.Duration `env:"POLL" envDefault:"1s"`
	MaxAttempts   int           `env:"MAX_ATTEMPTS" envDefault:"8"`
	RetainDone    time.Duration `env:"RETAIN_DONE" envDefault:"168h"`
	RetainFailed  time.Duration `env:"RETAIN_FAILED" envDefault:"720h"`
	ShutdownGrace time.Duration `env:"SHUTDOWN_GRACE" envDefault:"15s"`
}

// Defaults is the configuration with the documented defaults, for tests and tools.
func Defaults() Config {
	return Config{
		InServe: true, Lanes: Lanes{list: []LaneWorkers{{"fast", 4}, {"slow", 1}}}, Lease: 2 * time.Minute, Poll: time.Second,
		MaxAttempts: 8, RetainDone: 168 * time.Hour, RetainFailed: 720 * time.Hour, ShutdownGrace: 15 * time.Second,
	}
}

func (c Config) Validate(bool) error {
	var errs []error
	if len(c.Lanes.list) == 0 {
		errs = append(errs, errors.New("at least one lane is required"))
	}
	if c.Lease < time.Second {
		errs = append(errs, errors.New("lease must be at least 1s"))
	}
	if c.Poll <= 0 || c.Poll > time.Minute {
		errs = append(errs, errors.New("poll must be between 1ns and 1m"))
	}
	if c.MaxAttempts < 1 || c.MaxAttempts > maxAttemptsLimit {
		errs = append(errs, fmt.Errorf("max attempts must be 1 to %d", maxAttemptsLimit))
	}
	if c.RetainDone < time.Hour || c.RetainFailed < time.Hour {
		errs = append(errs, errors.New("retention must be at least 1h"))
	}
	if c.ShutdownGrace < 0 {
		errs = append(errs, errors.New("shutdown grace must not be negative"))
	}
	return errors.Join(errs...)
}

// Workers is the number of workers across every lane.
func (c Config) Workers() int {
	n := 0
	for _, l := range c.Lanes.list {
		n += l.Workers
	}
	return n
}

// LaneWorkers is a named pool of workers; handlers pick a lane so slow work never starves fast work.
type LaneWorkers struct {
	Name    string
	Workers int
}

// Lanes parses "fast:4,slow:1".
type Lanes struct {
	list []LaneWorkers
}

// NewLanes is Lanes for code and tests.
func NewLanes(lanes ...LaneWorkers) Lanes { return Lanes{list: lanes} }

func (l Lanes) List() []LaneWorkers { return append([]LaneWorkers(nil), l.list...) }

func (l Lanes) workers(name string) (int, bool) {
	for _, lane := range l.list {
		if lane.Name == name {
			return lane.Workers, true
		}
	}
	return 0, false
}

func (l Lanes) String() string {
	parts := make([]string, len(l.list))
	for i, lane := range l.list {
		parts[i] = lane.Name + ":" + strconv.Itoa(lane.Workers)
	}
	return strings.Join(parts, ",")
}

var laneName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func (l *Lanes) UnmarshalText(text []byte) error {
	*l = Lanes{}
	for part := range strings.SplitSeq(string(text), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, count, ok := strings.Cut(part, ":")
		n, err := strconv.Atoi(count)
		if !ok || err != nil || n < 1 || n > 256 || !laneName.MatchString(name) {
			return fmt.Errorf("lane %q must be name:workers with 1 to 256 workers", part)
		}
		if _, dup := l.workers(name); dup {
			return fmt.Errorf("lane %q is listed twice", name)
		}
		l.list = append(l.list, LaneWorkers{Name: name, Workers: n})
	}
	return nil
}
