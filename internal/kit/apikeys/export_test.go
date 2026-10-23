package apikeys

import "github.com/google/uuid"

// NewKeyFor makes another key for an existing id: a forger who can compute the checksum.
func (f Format) NewKeyFor(id uuid.UUID) string {
	k, _ := f.newKey(id)
	return k
}
