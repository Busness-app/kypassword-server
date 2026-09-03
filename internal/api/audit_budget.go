package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// auditBudgetWindow and auditBudgetBurst cap the audit writes one source can cause
	// from an unauthenticated request at 20 per minute-long window — about 50 ms of the
	// 2.6 ms fsync pair a record costs (CHANGELOG.md), whatever the request rate above
	// it. The windows are fixed rather than sliding, so a burst straddling a boundary
	// can produce two windows' worth in quick succession; that is 40 records, not a
	// rate an attacker can sustain.
	auditBudgetWindow = time.Minute
	auditBudgetBurst  = 20
)

// auditBudget bounds the audit-write cost one network source can impose with requests
// that carry no credential, without letting the excess go unrecorded.
//
// Two handlers record a rejection before any authentication succeeds — the replication
// webhook and pairing redeem — and each record costs two fsyncs held under the audit
// store's single mutex, so anonymous traffic serialises every audited operation in the
// server behind it. Past burst records in a window, a source's rejections stop being
// written one by one and are counted instead, and the count is folded into one summary
// record in the next window.
//
// Folded, never dropped. A limiter that discards audit records is a suppression
// primitive, and these two records — sync.rejected and device.pairing_failed — are the
// ones an attacker most wants gone; making them vanish must not be as easy as generating
// more of them. TestAnonymousRejectionsAreBoundedAndFolded pins both halves.
type auditBudget struct {
	window time.Duration
	burst  int

	mu      sync.Mutex
	now     func() time.Time // guarded by mu; a test replaces it
	sources map[string]*budgetSource
}

type budgetSource struct {
	windowStart time.Time
	recorded    int
	suppressed  int64
}

func newAuditBudget(window time.Duration, burst int) *auditBudget {
	return &auditBudget{
		window:  window,
		burst:   burst,
		now:     time.Now,
		sources: make(map[string]*budgetSource),
	}
}

// take reports whether src may have this rejection recorded on its own, and returns the
// count its previous window suppressed. A non-zero folded count is the caller's to
// record: take has already cleared it.
func (b *auditBudget) take(src string) (record bool, folded int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	s := b.sources[src]
	if s == nil {
		s = &budgetSource{windowStart: now}
		b.sources[src] = s
	}
	if now.Sub(s.windowStart) >= b.window {
		folded, s.suppressed = s.suppressed, 0
		s.windowStart, s.recorded = now, 0
	}
	if s.recorded < b.burst {
		s.recorded++
		return true, folded
	}
	s.suppressed++
	return false, folded
}

// sweep returns the suppressed counts of every source whose window has passed, and
// forgets those sources.
//
// A flood that stops sending is why it exists: nothing would call take for that source
// again, so its count would sit in memory and never reach the log — the rejections
// vanishing because more of them were generated. Forgetting idle sources is also what
// keeps the map from growing without bound.
func (b *auditBudget) sweep() map[string]int64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	var out map[string]int64
	for src, s := range b.sources {
		if now.Sub(s.windowStart) < b.window {
			continue
		}
		if s.suppressed > 0 {
			if out == nil {
				out = make(map[string]int64)
			}
			out[src] = s.suppressed
		}
		delete(b.sources, src)
	}
	return out
}

// sourceKey is the peer address, deliberately not clientIP: X-Forwarded-For is written by
// the caller, and a budget keyed on a header the attacker controls is no budget at all —
// a fresh value per request would draw a fresh allowance every time. Behind a reverse
// proxy every caller shares one budget, which folds more records than it needs to but
// still loses none of them.
func sourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// recordAnonymousRejection records a rejection an unauthenticated caller caused, within
// that caller's audit budget. The answer to the request is unchanged either way: the
// budget folds the record, it does not refuse the caller.
func (s *Server) recordAnonymousRejection(r *http.Request, action, ip, details string) {
	src := sourceKey(r)
	record, folded := s.rejects.take(src)
	if folded > 0 {
		s.recordSuppressed(r.Context(), src, folded)
	}
	if record {
		s.record(r, action, "", "", ip, details)
	}
}

func (s *Server) recordSuppressed(ctx context.Context, src string, n int64) {
	s.recordCtx(ctx, "audit.suppressed", "", "", src,
		fmt.Sprintf("%d rejections from this source were not recorded individually", n))
}

// flushSuppressed writes the summaries no further traffic would trigger. Started by
// NewServer, stopped by Close.
func (s *Server) flushSuppressed() {
	defer close(s.flushDone)

	t := time.NewTicker(s.rejects.window)
	defer t.Stop()
	for {
		select {
		case <-s.flushStop:
			return
		case <-t.C:
			s.flushOnce()
		}
	}
}

func (s *Server) flushOnce() {
	for src, n := range s.rejects.sweep() {
		s.recordSuppressed(context.Background(), src, n)
	}
}

// Close stops the background flush and waits for it, so a caller about to take the data
// directory away is not racing a summary write. Safe to call more than once.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.flushStop)
		<-s.flushDone
	})
}
