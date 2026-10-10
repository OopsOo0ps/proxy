package shutdown

import (
	"sync"
	"testing"
	"time"
)

func TestWaitDrainsWithinTimeout(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
	}()

	forced := false
	if ok := Wait(&wg, time.Second, func() { forced = true }); !ok {
		t.Fatal("Wait() = false, want true when drained in time")
	}
	if forced {
		t.Fatal("force must not be called when drained within timeout")
	}
}

func TestWaitForcesAfterTimeout(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	release := make(chan struct{})
	go func() {
		defer wg.Done()
		<-release
	}()

	start := time.Now()
	ok := Wait(&wg, 50*time.Millisecond, func() { close(release) })
	if ok {
		t.Fatal("Wait() = true, want false when timeout is exceeded")
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("Wait returned after %v, want at least the timeout", elapsed)
	}
}
