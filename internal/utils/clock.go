package utils

import "time"

// Clock is an interface for time operations to facilitate testing.
type Clock interface {
	Now() time.Time
}

// RealClock is the production implementation of Clock using time.Now().
type RealClock struct{}

func (c RealClock) Now() time.Time {
	return time.Now()
}
