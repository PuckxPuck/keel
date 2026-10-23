// Package rbac is permissions: a catalogue in code, roles as data, a Need on every operation.
package rbac

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Code names one permission, such as "notes.read". There are no wildcards.
type Code string

// Perm describes a permission for the screens that manage roles.
type Perm struct {
	Code         Code
	Area         string
	Label        string
	Description  string
	Sensitive    bool
	APIGrantable bool
}

type Catalogue struct {
	perms  []Perm
	byCode map[Code]Perm
}

var codePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_-]*)+$`)

const maxCode = 128

// NewCatalogue panics on an invalid or repeated code: catalogues are built once at startup.
func NewCatalogue(perms ...Perm) *Catalogue {
	c := &Catalogue{byCode: make(map[Code]Perm, len(perms))}
	for _, p := range perms {
		if len(p.Code) > maxCode || !codePattern.MatchString(string(p.Code)) {
			panic(fmt.Sprintf("rbac: permission code %q must look like area.action in lower case", p.Code))
		}
		if _, dup := c.byCode[p.Code]; dup {
			panic(fmt.Sprintf("rbac: permission %q is declared twice", p.Code))
		}
		c.byCode[p.Code] = p
		c.perms = append(c.perms, p)
	}
	slices.SortFunc(c.perms, func(a, b Perm) int { return strings.Compare(string(a.Code), string(b.Code)) })
	return c
}

func (c *Catalogue) Has(code Code) bool {
	_, ok := c.byCode[code]
	return ok
}

func (c *Catalogue) Get(code Code) (Perm, bool) {
	p, ok := c.byCode[code]
	return p, ok
}

// All lists the catalogue sorted by code.
func (c *Catalogue) All() []Perm { return slices.Clone(c.perms) }

// Unknown returns the codes in codes that the catalogue does not hold.
func (c *Catalogue) Unknown(codes ...Code) []Code {
	var out []Code
	for _, code := range codes {
		if !c.Has(code) {
			out = append(out, code)
		}
	}
	return out
}
