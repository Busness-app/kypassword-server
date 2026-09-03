package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// setClock replaces the budget's clock under its own mutex, so a test can move time
// without racing the background flush.
func (b *auditBudget) setClock(f func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = f
}

// auditTally counts, per action, what actually reached the log, and sums the rejections
// the summary records account for.
func auditTally(t *testing.T, srv *Server) (byAction map[string]int, summaries []string) {
	t.Helper()
	entries, err := srv.audit.List(10000)
	if err != nil {
		t.Fatalf("audit.List: %v", err)
	}
	byAction = make(map[string]int)
	for _, e := range entries {
		byAction[e.Action]++
		if e.Action == "audit.suppressed" {
			summaries = append(summaries, e.Details)
		}
	}
	return byAction, summaries
}

// TestAnonymousRejectionsAreBoundedAndFolded covers the amplification an unauthenticated
// caller could otherwise impose: every rejection recorded before a credential is checked
// costs two fsyncs under the audit store's one mutex, and nothing else in this server
// limits how many of them a caller can ask for.
//
// Both halves matter. The count of records must be bounded, and the rejections that did
// not get one must still be accounted for — a limiter that dropped them would hand an
// attacker a way to erase their own rejections by making more of them.
func TestAnonymousRejectionsAreBoundedAndFolded(t *testing.T) {
	const flood = 200

	cases := map[string]struct {
		action string
		newReq func() *http.Request
	}{
		"replication webhook": {
			action: "sync.rejected",
			newReq: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/sync/webhook", strings.NewReader(`{}`))
				r.Header.Set("X-KySignOn-Event-Type", "user.created")
				r.Header.Set("X-KySignOn-Timestamp", time.Now().UTC().Format(time.RFC3339))
				r.Header.Set("X-KySignOn-Signature", "0000000000000000000000000000000000000000000000000000000000000000")
				return r
			},
		},
		"pairing redeem": {
			action: "device.pairing_failed",
			newReq: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem",
					strings.NewReader(`{"codeOrPin":"000000","deviceName":"d","platform":"p"}`))
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newTestServer(t)
			handler := srv.Routes()

			clock := time.Now().UTC()
			srv.rejects.setClock(func() time.Time { return clock })

			for i := 0; i < flood; i++ {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, tc.newReq())
				if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusBadRequest {
					t.Fatalf("rejection %d = %d; the budget folds the record, it must not change the answer", i, rec.Code)
				}
			}

			byAction, summaries := auditTally(t, srv)
			recorded := byAction[tc.action]
			if recorded == 0 {
				t.Fatalf("%d rejections produced no %s record at all", flood, tc.action)
			}
			if recorded > auditBudgetBurst {
				t.Fatalf("%d of %d rejections were recorded one by one; the budget allows %d a window",
					recorded, flood, auditBudgetBurst)
			}
			if len(summaries) != 0 {
				t.Fatalf("a summary was written inside the window it is summarising: %v", summaries)
			}

			// The flood stops. Nothing will call take for this source again, so only
			// the periodic flush can still account for what it suppressed.
			clock = clock.Add(auditBudgetWindow + time.Second)
			srv.flushOnce()

			byAction, summaries = auditTally(t, srv)
			if len(summaries) != 1 {
				t.Fatalf("want exactly one periodic summary for the whole flood, got %d: %v", len(summaries), summaries)
			}
			if got := byAction[tc.action]; got != recorded {
				t.Fatalf("the flush wrote %d more %s records; it must summarise, not replay", got-recorded, tc.action)
			}
			want := fmt.Sprintf("%d rejections", flood-recorded)
			if !strings.Contains(summaries[0], want) {
				t.Fatalf("summary %q does not account for the %d suppressed rejections", summaries[0], flood-recorded)
			}

			// And a second flush must not invent a second summary for a source that
			// has already been accounted for.
			clock = clock.Add(auditBudgetWindow + time.Second)
			srv.flushOnce()
			if _, again := auditTally(t, srv); len(again) != 1 {
				t.Fatalf("flushing twice produced %d summaries", len(again))
			}
		})
	}
}

// TestAuditBudgetRefillsAndForgets pins the two properties the fold depends on: a source
// that comes back after its window gets a fresh allowance rather than being silenced for
// good, and the count it left behind is handed to the first caller of the new window
// instead of being cleared quietly.
func TestAuditBudgetRefillsAndForgets(t *testing.T) {
	now := time.Now().UTC()
	b := newAuditBudget(time.Minute, 2)
	b.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		record, folded := b.take("10.0.0.1")
		if want := i < 2; record != want {
			t.Fatalf("take %d recorded=%v, want %v", i, record, want)
		}
		if folded != 0 {
			t.Fatalf("take %d folded %d before any window had passed", i, folded)
		}
	}

	now = now.Add(time.Minute)
	record, folded := b.take("10.0.0.1")
	if !record {
		t.Fatal("the new window gave no allowance; a source that keeps trying would never be recorded again")
	}
	if folded != 3 {
		t.Fatalf("the new window folded %d suppressed rejections, want 3", folded)
	}

	// Handed over once, and only once.
	now = now.Add(time.Minute)
	if _, folded := b.take("10.0.0.1"); folded != 0 {
		t.Fatalf("the same %d suppressed rejections were handed out twice", folded)
	}

	// A source that stops is forgotten, so the map cannot grow with every address a
	// caller invents.
	now = now.Add(time.Minute)
	b.sweep()
	b.mu.Lock()
	n := len(b.sources)
	b.mu.Unlock()
	if n != 0 {
		t.Fatalf("sweep left %d idle sources behind", n)
	}
}

// A caller with a routed IPv6 prefix controls every address in it. Keyed on the whole
// address, the budget handed each one a fresh allowance and a fresh map entry, which
// restores the fsync amplification it exists to bound and grows the table with the
// address supply. The prefix is one source; past the table cap, everything unseen is one
// source.
//
// Written first against whole-address keying, where the /64 case recorded all 200.
func TestAuditBudgetIsBoundedAcrossAnIPv6Prefix(t *testing.T) {
	const flood = 200
	srv := newTestServer(t)
	handler := srv.Routes()

	for i := 0; i < flood; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem",
			strings.NewReader(`{"codeOrPin":"000000","deviceName":"d","platform":"p"}`))
		// One /64, a different interface identifier every time.
		r.RemoteAddr = fmt.Sprintf("[2001:db8:1:2::%x]:4000", i+1)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
	}

	byAction, _ := auditTally(t, srv)
	if got := byAction["device.pairing_failed"]; got > auditBudgetBurst {
		t.Fatalf("%d of %d rejections from one /64 were recorded one by one; the budget allows %d", got, flood, auditBudgetBurst)
	}
	srv.rejects.mu.Lock()
	n := len(srv.rejects.sources)
	srv.rejects.mu.Unlock()
	if n != 1 {
		t.Fatalf("one /64 occupies %d table entries, want 1", n)
	}
}

func TestAuditBudgetTableIsCapped(t *testing.T) {
	b := newAuditBudget(time.Minute, 2)
	for i := 0; i < 3*auditBudgetMaxSources; i++ {
		b.take(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	b.mu.Lock()
	n, overflow := len(b.sources), b.sources[auditBudgetOverflow]
	b.mu.Unlock()
	if n > auditBudgetMaxSources+1 {
		t.Fatalf("table holds %d sources, cap is %d plus the shared bucket", n, auditBudgetMaxSources)
	}
	if overflow == nil {
		t.Fatal("sources past the cap were not folded into the shared bucket")
	}
	// The overflow bucket is one budget: 2 recorded, the rest counted.
	if overflow.recorded != 2 || overflow.suppressed != int64(2*auditBudgetMaxSources-2) {
		t.Fatalf("shared bucket recorded=%d suppressed=%d", overflow.recorded, overflow.suppressed)
	}
}

// "Folded, not dropped" has to hold on the shutdown path operators use. Close stopped
// the flush and returned, and a window's worth of suppressed counts per source went
// with the process -- including a flood that ended right before the restart.
//
// Written first against the non-flushing Close, where no summary appeared.
func TestCloseFlushesTheFoldedCounts(t *testing.T) {
	const flood = 50
	srv := newTestServer(t)
	handler := srv.Routes()

	for i := 0; i < flood; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/devices/pairing/redeem",
			strings.NewReader(`{"codeOrPin":"000000","deviceName":"d","platform":"p"}`)))
	}
	byAction, summaries := auditTally(t, srv)
	recorded := byAction["device.pairing_failed"]
	if len(summaries) != 0 {
		t.Fatalf("a summary was written before any window passed: %v", summaries)
	}

	srv.Close()

	_, summaries = auditTally(t, srv)
	if len(summaries) != 1 {
		t.Fatalf("Close wrote %d summaries, want 1", len(summaries))
	}
	if want := fmt.Sprintf("%d rejections", flood-recorded); !strings.Contains(summaries[0], want) {
		t.Fatalf("summary %q does not account for the %d suppressed rejections", summaries[0], flood-recorded)
	}

	// Once. The t.Cleanup Close must not write a second summary.
	srv.Close()
	if _, again := auditTally(t, srv); len(again) != 1 {
		t.Fatalf("closing twice produced %d summaries", len(again))
	}
}
