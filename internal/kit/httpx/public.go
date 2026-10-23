package httpx

import (
	"time"

	"github.com/danielgtaylor/huma/v2"
)

const metaPublic = "keel:apiPublic"

// PublicAPI is how an operation is exposed on the public api realm: the date it joined it and, while it
// is being retired, its deprecation and sunset.
type PublicAPI struct {
	Since      string
	Deprecated time.Time
	Sunset     time.Time
}

// PublicOption adjusts Public.
type PublicOption func(*PublicAPI)

// Sunset retires a public operation: it answers with Deprecation and Sunset headers and is deprecated
// in the api realm's document. Add it in the release where deprecation starts: the api realm's startup
// check refuses a deprecatedOn in the future and a sunset less than six months after it.
func Sunset(deprecatedOn, sunset time.Time) PublicOption {
	return func(p *PublicAPI) { p.Deprecated, p.Sunset = deprecatedOn.UTC(), sunset.UTC() }
}

type publicOption PublicAPI

func (p publicOption) Apply(op *huma.Operation) { SetMeta(op, metaPublic, PublicAPI(p)) }

// Public marks an operation for the public api realm as well as its own, from since (a date,
// 2006-01-02). Without the api realm the mark changes nothing.
func Public(since string, opts ...PublicOption) Option {
	p := PublicAPI{Since: since}
	for _, o := range opts {
		o(&p)
	}
	return publicOption(p)
}

// PublicOf is the mark Public set on op.
func PublicOf(op *huma.Operation) (PublicAPI, bool) {
	p, ok := op.Metadata[metaPublic].(PublicAPI)
	return p, ok
}

// IsPublic is true for an operation marked Public; Mirror uses it to pick the api realm's operations.
func IsPublic(op *huma.Operation) bool {
	_, ok := PublicOf(op)
	return ok
}
