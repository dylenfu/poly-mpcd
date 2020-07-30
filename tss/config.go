package tss

import (
	"time"

	xtime "github.com/polynetwork/mpcd/pkg/time"
)

const (
	defaultPreParamsGenerationTimeout = 2 * time.Minute
)

type Config struct {
	PreParamsGenerationTimeout xtime.Duration
}

// GetPreParamsGenerationTimeout returns pre-parameters generation timeout.
// if a value is not set it returns a default value.
func (c *Config) GetPreParamsGenerationTimeout() time.Duration {
	timeout := c.PreParamsGenerationTimeout.ToDuration()
	if timeout == 0 {
		timeout = defaultPreParamsGenerationTimeout
	}
	return timeout
}
