package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/auditchain"
	"github.com/Busness-app/ky-primitives/keyfile"
)

// genesisHash is the PrevHash of the first entry in a chain.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// keyBytes is the audit HMAC key length. keyfile requires an exact size rather than a
// floor: "at least 32" let a longer file through, and two installs disagreeing about the
// length is two installs that cannot read each other's keys.
const keyBytes = 32

// appendTimeout bounds Append's wait for the chain lock. It does not bound persist,
// which runs with that lock held and no context reaching it, so a store that hangs
// hangs this caller for as long as it stays hung.
var appendTimeout = 5 * time.Second

// ErrCorruptLog reports a log the reader cannot get to the end of: bytes that do not
// decode, with newline-terminated records still behind them. It is separate from
// ErrTruncated only so the message can name the damage and its remedy; both refuse to
// start. It names what was read, not what caused it — an undecodable line is something
// an attacker can write, so which error comes back is not evidence about who wrote it.
var ErrCorruptLog = errors.New("audit: log holds bytes that do not decode")

// Entry represents a single tamper-evident audit record in the chain.
type Entry struct {
	Index     int64     `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	UserID    string    `json:"userId,omitempty"`
	DeviceID  string    `json:"deviceId,omitempty"`
	IPAddress string    `json:"ipAddress,omitempty"`
	Details   string    `json:"details,omitempty"`
	PrevHash  string    `json:"prevHash"`
	Hash      string    `json:"hash"`
}

// fieldsOf is the entry content the chain authenticates. The order is part of the
// chain format: changing it invalidates every stored digest.
func fieldsOf(e Entry) []string {
	return []string{
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.Action,
		e.UserID,
		e.DeviceID,
		e.IPAddress,
		e.Details,
	}
}

// recordOf reads a stored entry as a chain record. Entry indices are zero-based
// and chain sequences are one-based.
func recordOf(e Entry) auditchain.Record {
	return auditchain.Record{
		Seq:    uint64(e.Index) + 1,
		Prev:   e.PrevHash,
		Hash:   e.Hash,
		Fields: fieldsOf(e),
	}
}

// Store manages the append-only audit trail file.
type Store struct {
	mu        sync.Mutex
	filePath  string
	statePath string
	key       []byte
	chain     *auditchain.Chain
	anchor    auditchain.Anchor
}

// Snapshot is a lock-consistent copy of the three files needed to resume and
// verify the audit chain. Key is the effective in-memory key, including when it
// came from AUDIT_KEY rather than audit.key on disk.
type Snapshot struct {
	Log   []byte
	State []byte
	Key   []byte
}

func (s *Store) Snapshot() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	logData, err := os.ReadFile(s.filePath)
	if errors.Is(err, os.ErrNotExist) {
		logData = []byte{}
	} else if err != nil {
		return Snapshot{}, err
	}
	stateData, err := os.ReadFile(s.statePath)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Log: logData, State: stateData, Key: bytes.Clone(s.key)}, nil
}

// legacyHash is the keyed digest this server used before the chain moved to the
// shared format. It joined the fields with a bare "|", so content carrying the
// delimiter could be shifted into a neighbouring field without changing the digest.
//
// The unkeyed variant that preceded it is gone. It was chained under no secret at
// all, so anyone who could write the log could rewrite it and recompute every
// digest; the boundary that said where those entries stopped was never persisted.
//
// Deprecated: retained only to recognise entries written this way, never to write
// one. New entries are written by auditchain.
func (s *Store) legacyHash(e Entry) string {
	raw := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s",
		e.Index, e.Timestamp.Format(time.RFC3339Nano), e.Action,
		e.UserID, e.DeviceID, e.IPAddress, e.Details, e.PrevHash)

	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// chainState is the anchor persisted outside the log: how many entries it held and
// the digest of the last one, held beside the key rather than beside the log.
// Hashes alone cannot detect a log that has had records removed, because what
// remains still chains correctly; only a mark out of the attacker's reach can.
type chainState struct {
	Count uint64 `json:"count"`
	Hash  string `json:"hash,omitempty"`
}

// loadState reads the anchor, creating an empty one only when there is none.
//
// Only os.ErrNotExist may create. The read used to be `if err == nil { ... }`, so every
// other failure — a permission error, an I/O error, a directory in its place — fell
// through and wrote an empty mark over the real one. The rename succeeds whenever keyDir
// is writable, so the anchor was destroyed, and placeTail then told the operator the mark
// "was removed and recreated empty, or never written": a description of what this function
// had just done. TestUnreadableMarkIsNotOverwritten pins it.
func loadState(keyDir string) (chainState, error) {
	statePath := filepath.Join(keyDir, "audit.state")
	data, err := os.ReadFile(statePath)
	switch {
	case err == nil:
		var st chainState
		if err := json.Unmarshal(data, &st); err != nil {
			return chainState{}, fmt.Errorf("audit state file is corrupt: %w", err)
		}
		return st, nil
	case !errors.Is(err, os.ErrNotExist):
		return chainState{}, fmt.Errorf("read audit state: %w", err)
	}

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return chainState{}, fmt.Errorf("mkdir key dir: %w", err)
	}
	st := chainState{}
	if err := writeState(statePath, st); err != nil {
		return chainState{}, err
	}
	return st, nil
}

func writeState(statePath string, st chainState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	// Rename so a crash mid-write cannot leave a state file that reads as "the
	// log should be empty", and flush the bytes before the rename that publishes
	// them: a rename that reaches the disk ahead of its own contents leaves a mark
	// that does not parse, and loadState refuses to start on one. The rename is not
	// itself flushed — losing it leaves the previous mark, which is the direction
	// placeTail already reconciles.
	tmp := statePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("write audit state: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write audit state: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("flush audit state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write audit state: %w", err)
	}
	if err := os.Rename(tmp, statePath); err != nil {
		return fmt.Errorf("replace audit state: %w", err)
	}
	return nil
}

// loadKey returns the HMAC key for the audit chain, generating and persisting one on
// first use. keyDir must not be writable by anyone who can write the audit log, or the
// key protects nothing.
//
// This is keyfile's job, and this package's own version is the bug that package's doc
// comment cites by name. The condition was `if data, err := os.ReadFile(f); err == nil &&
// len(data) > 0`, so a zero-byte audit.key — or one that could not be read at all — fell
// through to the generator and was overwritten with a fresh key. Every record ever written
// under the original then failed verification, permanently and with nothing to restore
// from. keyfile.LoadOrCreate creates only when the file does not exist, refuses anything
// that does not decode to exactly 32 bytes rather than replacing it, and fsyncs the file
// and its directory so a crash after first boot cannot leave the zero-length file that
// started this. TestEmptyKeyFileIsNotRegenerated pins it.
func loadKey(keyDir string) ([]byte, error) {
	if key, ok, err := keyfile.FromEnv("AUDIT_KEY", keyBytes); err != nil {
		return nil, err
	} else if ok {
		return key, nil
	}
	return keyfile.LoadOrCreate(filepath.Join(keyDir, "audit.key"), keyBytes)
}

// NewStore initializes an audit store in dir, keyed by material held in keyDir.
// keyDir must be outside dir: a key stored beside the log it protects is no
// protection at all.
func NewStore(dir, keyDir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir audit dir: %w", err)
	}

	key, err := loadKey(keyDir)
	if err != nil {
		return nil, err
	}

	s := &Store{
		filePath:  filepath.Join(dir, "audit.jsonl"),
		statePath: filepath.Join(keyDir, "audit.state"),
		key:       key,
	}

	st, err := loadState(keyDir)
	if err != nil {
		return nil, err
	}
	s.anchor = auditchain.Anchor{Count: st.Count, Hash: st.Hash}

	entries, end, err := s.readAll()
	if err != nil {
		return nil, err
	}
	entries, rewrote, err := s.converge(entries, st)
	if err != nil {
		return nil, err
	}

	// Before the empty-log short circuit, not after it. readAll stops at the first
	// line it cannot decode, so a log wiped to zero bytes — or one whose first line
	// is corrupt — reads as no entries at all, and used to be the one truncation that
	// opened cleanly and went on accepting appends.
	anchor, err := s.placeTail(entries)
	if err != nil {
		return nil, err
	}

	// converge rewrites the whole file when it runs, so end describes a file that no
	// longer exists and there is nothing left to trim.
	if !rewrote {
		if err := s.trimTornTail(end); err != nil {
			return nil, err
		}
	}

	if len(entries) == 0 {
		s.chain, err = auditchain.New(key)
		return s, err
	}

	if s.chain, err = auditchain.Resume(key, recordOf(entries[len(entries)-1]), anchor); err != nil {
		return nil, err
	}
	if anchor != s.anchor {
		s.anchor = anchor
		if err := s.saveAnchor(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// placeTail returns the anchor to resume the log against, and refuses outright when
// the mark and the log cannot be reconciled at all.
//
// It does not settle everything. When the counts agree it hands back the stored mark
// unexamined, and whether the last record is really the one that mark names is left
// to Resume's own digest check — which is what rejects a forged or downgraded log
// whose length happens to be right. TestEmptiedLogIsRejected and
// TestForgedChainIsRejected are the two ends of that division.
func (s *Store) placeTail(entries []Entry) (auditchain.Anchor, error) {
	n := uint64(len(entries))

	switch {
	case n < s.anchor.Count:
		// Fewer records than the mark counted. Resuming at this tail would mint a
		// sequence number that already exists: a fork that persists cleanly and can
		// never verify again. Refuse to start rather than append over the evidence.
		//
		// n == 0 lands here too, and must: an emptied log is the most truncated log
		// there is, not a fresh install.
		return auditchain.Anchor{}, fmt.Errorf("%w: %s holds %d records but the mark in %s counts %d. "+
			"Entries have been removed from the end of the log; appending would write over the gap, "+
			"so this server will not start. Restore the log from backup, or move both files aside to "+
			"begin a new chain and keep the old pair for the auditor",
			auditchain.ErrTruncated, s.filePath, n, s.statePath, s.anchor.Count)

	case n == 0:
		// No log and no mark: a first run.
		return auditchain.Anchor{}, nil

	case s.anchor.Count == 0:
		// A log with no mark cannot be placed. The mark is the only record of how
		// long the log is meant to be, so without it a log with entries removed and
		// one that is intact are the same file. Minting a mark here would bless
		// whatever is on disk, and one append used to do exactly that.
		return auditchain.Anchor{}, fmt.Errorf("%w: %s holds %d records but the mark in %s counts none. "+
			"It was removed and recreated empty, or never written; either way a truncated log "+
			"cannot be told from an intact one, so this server will not start. Restore the mark "+
			"from backup, or move both files aside to begin a new chain and keep the old pair "+
			"for the auditor", auditchain.ErrBrokenChain, s.filePath, n, s.statePath)

	case n > s.anchor.Count:
		// The mark is behind the log: records landed and the mark write that should
		// have followed did not. One behind is the classic interrupted write; several
		// behind is a config volume that was unwritable for a while, which is a disk
		// fault and not tampering. So walk the whole run: every record past the mark
		// must sit at its own position, carry its own digest, and follow the one
		// before it, starting from the mark's own hash. Minting any one of them still
		// requires the key, so accepting a run is no weaker than accepting one — but
		// without the predecessor check a re-minted fork would be adopted here.
		prev := s.anchor.Hash
		for i := s.anchor.Count; i < n; i++ {
			rec := recordOf(entries[i])
			if rec.Seq != i+1 {
				return auditchain.Anchor{}, fmt.Errorf("%w: %s overruns the mark in %s and record %d sits at position %d",
					auditchain.ErrBrokenChain, s.filePath, s.statePath, rec.Seq, i+1)
			}
			if err := auditchain.VerifyRecord(s.key, rec); err != nil {
				return auditchain.Anchor{}, fmt.Errorf("audit: %s overruns the mark in %s and record %d does not verify: %w",
					s.filePath, s.statePath, rec.Seq, err)
			}
			if rec.Prev != prev {
				return auditchain.Anchor{}, fmt.Errorf("%w: %s overruns the mark in %s and record %d does not follow its predecessor",
					auditchain.ErrBrokenChain, s.filePath, s.statePath, rec.Seq)
			}
			prev = rec.Hash
		}
		return auditchain.Anchor{Count: n, Hash: entries[n-1].Hash}, nil
	}
	return s.anchor, nil
}

// readAll returns the log oldest first, or nothing if it does not exist yet, along with
// the offset just past the last record it could decode. Anything after that offset is
// what the decoder stopped at; trimTornTail is what removes it.
func (s *Store) readAll() ([]Entry, int64, error) {
	file, err := os.Open(s.filePath)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	var entries []Entry
	var end int64
	dec := json.NewDecoder(file)
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			break
		}
		entries = append(entries, e)
		end = dec.InputOffset()
	}
	return entries, end, nil
}

// trimTornTail drops an unterminated fragment left on the end of the log, and refuses to
// start when the bytes the reader stopped at are anything else.
//
// A record and its newline are written in one call, and a crash or a full disk can cut
// that call in half. The reader stops at the fragment, so the next append lands behind it
// and every record after that is unreadable — the log lost from the tear onward while
// every check still passes.
//
// Only a fragment may be removed, and the newline is what tells one from the other: every
// complete record this package writes ends in one, so bytes past the last decodable record
// that contain no newline cannot hold a complete record. That is the whole of the safety
// claim, and it is the whole of the condition below.
//
// Bytes that do contain a newline are damage further up the log — one corrupted line with
// intact records behind it. readAll stops at the first line it cannot decode, so `end`
// there is the middle of the file, not its tail; truncating to it destroyed every complete
// record after the damage, and a mark lagging behind the tear made that a clean boot with
// nothing left to show it. So refuse, in the same terms as the other boot refusals: the
// remedy is a restore, and a log this server cannot read to the end is not one it may
// append to. TestDamagedRecordDoesNotTakeTheLogWithIt holds it;
// TestTornTailIsRepaired covers the fragment that is genuinely trailing.
//
// It runs after placeTail, never before. A log placeTail refuses is evidence for the
// operator, and editing evidence is not this function's job.
func (s *Store) trimTornTail(end int64) error {
	fi, err := os.Stat(s.filePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Size() <= end {
		return nil
	}

	f, err := os.OpenFile(s.filePath, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	// The record's newline went out in the same write as the record, so when anything
	// follows the last complete record, that newline is the first byte past it. Keep it.
	clean := end
	var nl [1]byte
	if _, err := f.ReadAt(nl[:], end); err != nil {
		return err
	}
	if nl[0] == '\n' {
		clean++
	}
	if fi.Size() == clean {
		return nil
	}

	newline, err := holdsNewline(io.NewSectionReader(f, clean, fi.Size()-clean))
	if err != nil {
		return err
	}
	if newline {
		return fmt.Errorf("%w: %s stops decoding %d bytes in and %d bytes of newline-terminated "+
			"records follow. That is damage in the middle of the log — a corrupted block, or a write "+
			"torn by a full disk — not an incomplete record on the end, and the records after it are "+
			"still there. This server will not start rather than append past bytes it cannot read. "+
			"Keep the file for the auditor and restore the log from backup",
			ErrCorruptLog, s.filePath, clean, fi.Size()-clean)
	}

	if err := f.Truncate(clean); err != nil {
		return err
	}
	log.Printf("audit: dropped %d bytes of an incomplete trailing record from %s", fi.Size()-clean, s.filePath)
	return f.Sync()
}

// holdsNewline reports whether r contains a newline, without holding r in memory: the
// fragment it is asked about is one record long, but the damage case it separates that
// from can be the rest of the log.
func holdsNewline(r io.Reader) (bool, error) {
	buf := make([]byte, 8192)
	for {
		n, err := r.Read(buf)
		if bytes.IndexByte(buf[:n], '\n') >= 0 {
			return true, nil
		}
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}

// saveAnchor persists the anchor beside the key.
func (s *Store) saveAnchor() error {
	return writeState(s.statePath, chainState{Count: s.anchor.Count, Hash: s.anchor.Hash})
}

// converge rewrites a log written under this server's own keyed hashing onto the
// shared package's digests. It runs once, when the log does not already carry them.
//
// Every entry must first verify under the digest that wrote it, so a log that was
// already broken is never blessed. On top of that the mark has to attest to this exact
// log — the same record count *and* the same tail hash — because the mark is the only
// input that does not live in the log's own directory.
//
// The count alone was not enough. An equal-length substitution passes a count check, and
// that is the cheapest forgery to mount: kybookmarks-server keys its oldest legacy format
// with a constant published in its repository, so a whole chain that "verifies as legacy"
// is something anyone with write access can author, and converting on that alone re-mints
// it under the real key. This server's legacy digest is keyed with the real key, so the
// same substitution is not forgeable here — but the check that decides whether to re-mint
// a log under the audit key should not be one whose soundness rests on that.
//
// When conversion is refused the log is left exactly as it is: if the mark counts more
// than the log holds placeTail refuses, if it counts none placeTail refuses, and otherwise
// the entries are still in the old format, so Resume's digest check is what rejects them.
func (s *Store) converge(entries []Entry, st chainState) ([]Entry, bool, error) {
	if len(entries) == 0 {
		return entries, false, nil
	}
	// Is this log already in the shared digest format? That is all this asks.
	// Resume would also assert that the record is the tail, which is a different
	// question and not the one converge needs answered.
	if auditchain.VerifyRecord(s.key, recordOf(entries[len(entries)-1])) == nil {
		return entries, false, nil
	}
	if st.Count != uint64(len(entries)) || st.Hash != entries[len(entries)-1].Hash {
		return entries, false, nil
	}
	if !s.legacyChainVerifies(entries) {
		return entries, false, nil
	}

	// Replay, not a per-record Append: the log is written once after the loop and
	// the mark saved once after that, so a persist callback per record would have
	// nothing to persist.
	tuples := make([][]string, 0, len(entries))
	for _, e := range entries {
		tuples = append(tuples, fieldsOf(e))
	}
	records, anchor, err := auditchain.Replay(s.key, tuples)
	if err != nil {
		return nil, false, err
	}
	converted := make([]Entry, 0, len(entries))
	for i, e := range entries {
		e.Index, e.PrevHash, e.Hash = int64(records[i].Seq)-1, records[i].Prev, records[i].Hash
		converted = append(converted, e)
	}

	if err := s.rewrite(converted); err != nil {
		return nil, false, err
	}
	s.anchor = anchor
	if err := s.saveAnchor(); err != nil {
		return nil, false, err
	}
	return converted, true, nil
}

// legacyChainVerifies reports whether every entry carries the keyed digest the
// previous format would have written, with the links and indices intact.
func (s *Store) legacyChainVerifies(entries []Entry) bool {
	prev := genesisHash
	for i, e := range entries {
		if e.Index != int64(i) || e.PrevHash != prev {
			return false
		}
		if !hmac.Equal([]byte(e.Hash), []byte(s.legacyHash(e))) {
			return false
		}
		prev = e.Hash
	}
	return true
}

// rewrite replaces the log atomically, so a crash cannot leave it half-converted.
func (s *Store) rewrite(entries []Entry) error {
	tmp := s.filePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}

// Log records an audit action in the hash-chain.
//
// ctx is accepted for its values; its cancellation is deliberately dropped. Handlers
// pass r.Context(), which dies the instant the client hangs up, and by then the handler
// has already acted — so honouring it would let a client suppress the record of what it
// just did by aborting the connection. The records an attacking client most wants gone,
// device.pairing_failed and sync.rejected, are exactly the ones written that way. The
// audit write is not the caller's to cancel; TestAbortedRequestStillRecordsTheAudit
// pins it.
//
// The error is the caller's to report, not to drop: api.Server.record counts it and
// takes the instance out of health, because a vault that cannot record what it does
// should not be quietly taking traffic.
func (s *Store) Log(ctx context.Context, action, userID, deviceID, ip, details string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Derived after the mutex, not before. s.mu is a plain sync.Mutex that no context
	// can interrupt, so a deadline started above this line is spent waiting on it: a
	// caller queued behind a slow store would reach Append with an already-dead
	// context and throw its record away. That is the same suppression reached by load
	// instead of by a dropped connection. Every waiter gets its budget measured from
	// the moment it can make progress; TestQueuedLogSpendsItsBudgetOnTheChain pins it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)
	defer cancel()

	entry := Entry{
		Timestamp: time.Now().UTC(),
		Action:    action,
		UserID:    userID,
		DeviceID:  deviceID,
		IPAddress: ip,
		Details:   details,
	}

	var anchorErr error
	_, err := s.chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
		entry.Index, entry.PrevHash, entry.Hash = int64(r.Seq)-1, r.Prev, r.Hash
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		data = append(data, '\n')

		f, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		if _, err := f.Write(data); err != nil {
			// A short write — a full disk is the usual one — leaves half a line that
			// the reader stops at and the next append lands behind, losing the log
			// from there on. Put the file back where this record found it. The chain
			// rolls this record back too, so the sequence number is reused rather
			// than skipped. TestShortWriteLeavesNoTornLine covers it.
			if terr := f.Truncate(fi.Size()); terr != nil {
				err = errors.Join(err, terr)
			}
			f.Close()
			return err
		}
		// Flush the record before the mark that counts it. The two files are only
		// ordered on disk if this call is here: without it a crash can land the mark
		// first, and the next start finds fewer records than the mark counts and
		// refuses to boot — an ordinary power loss reported to the operator as
		// tampering. This is one of the two flushes an audited request pays for; the
		// other is writeState's, before its rename. See CHANGELOG.md for the measured
		// cost of the pair.
		//
		// Unproven here: exposing the wrong order takes a crash between the two
		// writes, which no test in this package can stage. What is claimed is the
		// syscall, not a test.
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}

		// Entry first, mark second, and the mark's failure is reported from Log
		// rather than to the chain. The record is already on disk, so failing the
		// append here would leave the chain a step behind the log and the next Log
		// would reuse this sequence number — forking it permanently, and silently,
		// because the mark would already have been advanced. A mark left behind is
		// just the interrupted write placeTail reconciles.
		//
		// Only ever forward: if entries were removed and the log is being appended
		// to again, the recorded mark is the evidence and must not be overwritten.
		if a.Count > s.anchor.Count {
			s.anchor = a
			anchorErr = s.saveAnchor()
		}
		return nil
	}, fieldsOf(entry)...)
	if err != nil {
		return Entry{}, fmt.Errorf("extend audit chain: %w", err)
	}
	if anchorErr != nil {
		return entry, fmt.Errorf("record audit chain anchor: %w", anchorErr)
	}
	return entry, nil
}

// List returns the latest N audit entries.
func (s *Store) List(limit int) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.filePath)
	if os.IsNotExist(err) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []Entry
	dec := json.NewDecoder(file)
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			break
		}
		entries = append(entries, e)
	}

	// Reverse to show latest first
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	return entries, nil
}

// VerifyIntegrity walks the entire audit chain and checks it against the anchor.
func (s *Store) VerifyIntegrity() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.filePath)
	if os.IsNotExist(err) {
		if s.anchor.Count > 0 {
			return false, fmt.Errorf("audit log is missing, but %d entries were recorded", s.anchor.Count)
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	err = auditchain.VerifyStream(s.key, func(yield func(auditchain.Record, error) bool) {
		for {
			var e Entry
			if derr := dec.Decode(&e); derr != nil {
				return
			}
			if !yield(recordOf(e), nil) {
				return
			}
		}
	}, s.anchor)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ExportChain writes the log as shared-package records, and returns the anchor to
// check them against. This is the form kyauditverify reads: the products store
// different fields, so the records as the chain sees them are the only thing one
// verifier can consume from all of them.
func (s *Store) ExportChain(w io.Writer) (auditchain.Anchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, _, err := s.readAll()
	if err != nil {
		return auditchain.Anchor{}, err
	}
	enc := json.NewEncoder(w)
	for _, e := range entries {
		if err := enc.Encode(recordOf(e)); err != nil {
			return auditchain.Anchor{}, err
		}
	}
	return s.anchor, nil
}
