package corenet

import (
	"fmt"
	"net/http"
	"sync"
)

type statsCounter struct {
	mu  sync.Mutex
	val int64
}

func (s *statsCounter) Delta(v int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.val += v
}

func (s *statsCounter) Inc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.val++
}

func (s *statsCounter) Dec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.val--
}

func (s *statsCounter) Val() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.val
}

type statsCounterMap struct {
	mu   sync.Mutex
	data map[string]*statsCounter
}

func newStatsCounterMap() *statsCounterMap {
	return &statsCounterMap{data: make(map[string]*statsCounter)}
}

func (m *statsCounterMap) getEntry(entryID string) *statsCounter {
	m.mu.Lock()
	defer m.mu.Unlock()
	counter, exists := m.data[entryID]
	if !exists {
		counter = &statsCounter{val: 0}
		m.data[entryID] = counter
	}
	return counter
}

func (m *statsCounterMap) Inc(entry string) {
	m.getEntry(entry).Inc()
}

func (m *statsCounterMap) Dec(entry string) {
	m.getEntry(entry).Dec()
}

func (m *statsCounterMap) Delta(entry string, delta int64) {
	m.getEntry(entry).Delta(delta)
}

func (m *statsCounterMap) Stats() map[string]int64 {
	res := make(map[string]int64)
	m.mu.Lock()
	defer m.mu.Unlock()
	for entryID, counter := range m.data {
		res[entryID] = counter.Val()
	}
	return res
}

var (
	globalStatsCounterMap = newStatsCounterMap()
)

func init() {
	http.HandleFunc("/debug/clover3", func(w http.ResponseWriter, r *http.Request) {
		statsSnapshot := globalStatsCounterMap.Stats()
		for entryName, value := range statsSnapshot {
			fmt.Fprintf(w, "%s = %d\n", entryName, value)
		}
	})
}
