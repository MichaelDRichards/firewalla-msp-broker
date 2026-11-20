package auth

import (
	"math"
	"sync"
	"time"
)

// Limiter is a per-key token bucket. Capacity equals the per-minute limit
// (a full minute's allowance can be spent in a burst) and refills at
// limit/60 tokens per second.
type Limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter returns an empty limiter using now as its clock.
func NewLimiter(now func() time.Time) *Limiter {
	return &Limiter{now: now, buckets: map[string]*bucket{}}
}

const sweepThreshold = 1024

// Allow takes one token from id's bucket. perMinute <= 0 means unlimited.
// When the bucket is empty it returns false and how long until a token is
// available.
func (l *Limiter) Allow(id string, perMinute int) (ok bool, retryAfter time.Duration) {
	if perMinute <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	capacity := float64(perMinute)
	rate := capacity / 60 // tokens per second

	b := l.buckets[id]
	if b == nil {
		if len(l.buckets) >= sweepThreshold {
			l.sweep(now)
		}
		b = &bucket{tokens: capacity, last: now}
		l.buckets[id] = b
	} else {
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = math.Min(capacity, b.tokens+elapsed*rate)
		}
		b.tokens = math.Min(b.tokens, capacity) // limit may have been lowered
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / rate * float64(time.Second))
	return false, wait
}

// sweep drops buckets idle long enough to be full again at any limit
// (a bucket refills completely within 60 seconds).
func (l *Limiter) sweep(now time.Time) {
	for id, b := range l.buckets {
		if now.Sub(b.last) > 2*time.Minute {
			delete(l.buckets, id)
		}
	}
}

// Len is the number of tracked buckets (tests).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
