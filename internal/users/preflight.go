package users

import "sort"

// UnlinkedActive returns every active account with no KySignOn identity, sorted by
// username. These are the accounts that would silently lose access — or, worse, be
// duplicated by replication — once KySignOn is the only directory, so the server refuses
// to start while any exist.
func UnlinkedActive(s *Store) []User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []User
	for _, u := range s.users {
		if u.Active && u.SSOSub == "" {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}
