package migrate

import (
	"fmt"
	"regexp"
	"strings"
)

// The tenant policy's expressions (docs/tenancy.md section 4), normalised by policyExpr. The null-safe
// form is what a table holding rows without a tenant uses; on a not-null tenant_id it is the same rule.
var (
	tenantEquals   = policyExpr(`tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid)`)
	tenantNullSafe = policyExpr(`tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid)`)
)

type policyDef struct {
	permissive, parsed bool
	cmd, using, check  string
}

// tenant is true for the tenant policy: permissive, for all commands, using and with check both the
// template's. A policy without with check reuses its using expression, but pg_policies then shows none,
// so the catalogue check would refuse it; it is refused here too.
func (p policyDef) tenant() bool {
	ok := func(e string) bool { return e == tenantEquals || e == tenantNullSafe }
	return p.parsed && p.permissive && p.cmd == "all" && ok(p.using) && ok(p.check)
}

type policyStmt struct {
	create        bool
	name, table   string
	renameTo      string
	def           policyDef
	usingSet      bool
	checkSet      bool
	unparsedAlter bool
}

var policyHeadRE = regexp.MustCompile(`^(create|alter) policy ("[^"]+"|[^\s"]+) on (?:only )?([^\s(]+) ?(.*)$`)

// parsePolicy reads a create or alter policy statement (normalised, literals kept). A statement it cannot
// read fully parses with def.parsed false, which never counts as the tenant policy.
func parsePolicy(stmt string) (policyStmt, bool) {
	m := policyHeadRE.FindStringSubmatch(stmt)
	if m == nil {
		return policyStmt{}, false
	}
	p := policyStmt{create: m[1] == "create", name: strings.Trim(m[2], `"`), table: tableName(m[3])}
	rest := m[4]
	if !p.create {
		if to, ok := strings.CutPrefix(rest, "rename to "); ok {
			p.renameTo = strings.Trim(strings.TrimSpace(to), `"`)
			return p, true
		}
	}
	p.def = policyDef{permissive: true, cmd: "all", parsed: true}
	if p.create {
		if r, ok := strings.CutPrefix(rest, "as "); ok {
			word, after, _ := strings.Cut(r, " ")
			p.def.permissive, p.def.parsed, rest = word == "permissive", word == "permissive" || word == "restrictive", after
		}
		if r, ok := strings.CutPrefix(rest, "for "); ok {
			p.def.cmd, rest, _ = strings.Cut(r, " ")
		}
	}
	if r, ok := strings.CutPrefix(rest, "to "); ok {
		loc := clauseRE.FindStringIndex(r)
		if loc == nil {
			r = ""
		} else {
			r = r[loc[0]:]
		}
		rest = strings.TrimSpace(r)
	}
	if r, ok := cutKeyword(rest, "using"); ok {
		p.def.using, rest, p.def.parsed = parenthesised(r, p.def.parsed)
		p.usingSet = true
	}
	if r, ok := cutKeyword(rest, "with check"); ok {
		p.def.check, rest, p.def.parsed = parenthesised(r, p.def.parsed)
		p.checkSet = true
	}
	if strings.TrimSpace(rest) != "" {
		p.def.parsed = false
		p.unparsedAlter = !p.create
	}
	return p, true
}

var clauseRE = regexp.MustCompile(`\b(?:using|with check) ?\(`)

func cutKeyword(s, keyword string) (string, bool) {
	r, ok := strings.CutPrefix(s, keyword)
	if !ok || (r != "" && r[0] != ' ' && r[0] != '(') {
		return s, false
	}
	return strings.TrimSpace(r), true
}

// parenthesised splits "(expr) rest" at the parenthesis that closes the first, outside quotes.
func parenthesised(s string, parsed bool) (expr, rest string, ok bool) {
	if !strings.HasPrefix(s, "(") {
		return "", s, false
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"':
			i = skipQuoted(s, i, s[i], false) - 1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return policyExpr(s[1:i]), strings.TrimSpace(s[i+1:]), parsed
			}
		}
	}
	return "", "", false
}

// policyExpr is an expression with case folded and spaces kept only between two word characters, so
// spacing never decides a comparison; quoted text is kept as written.
func policyExpr(e string) string {
	e = strings.ToLower(strings.Join(strings.Fields(e), " "))
	var b strings.Builder
	for i := 0; i < len(e); i++ {
		switch c := e[i]; {
		case c == '\'' || c == '"':
			end := skipQuoted(e, i, c, false)
			b.WriteString(e[i:end])
			i = end - 1
		case c == ' ' && i > 0 && i+1 < len(e) && identChar(e[i-1]) && identChar(e[i+1]):
			b.WriteByte(' ')
		case c != ' ':
			b.WriteByte(c)
		}
	}
	return b.String()
}

var (
	dropPolicyRE = regexp.MustCompile(`^drop policy (?:if exists )?("[^"]+"|[^\s"]+) on (?:only )?([^\s(;]+)`)
	referencesRE = regexp.MustCompile(`\breferences (?:only )?([^\s(]+) ?(?:\(([^)]*)\))?`)
	foreignKeyRE = regexp.MustCompile(`foreign key ?\(([^)]*)\) ?$`)
)

// tenantDDL follows tables and policies through every Postgres migration in order and refuses what would
// let a tenant reach another's rows while the release that ships it runs: a policy that is not the tenant
// policy and not allowed by name, a dropped policy or row-level security turned off on a tenant table,
// and a tenant table that references itself without tenant_id.
func tenantDDL(names []string, files map[string]parsed, allowed []Policy) []error {
	type key struct{ table, name string }
	isAllowed := func(k key) bool {
		for _, p := range allowed {
			if p.Table == k.table && p.Name == k.name && p.Reason != "" {
				return true
			}
		}
		return false
	}
	tenant, global := map[string]bool{}, map[string]bool{}
	policies := map[key]policyDef{}
	var errs []error
	for _, name := range names {
		f := files[name]
		report := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("%s: "+format, append([]any{name}, args...)...))
		}
		for _, stmt := range f.up {
			if m := dropTableRE.FindStringSubmatch(stmt.text); m != nil {
				t := tableName(m[1])
				delete(tenant, t)
				for k := range policies {
					if k.table == t {
						delete(policies, k)
					}
				}
				continue
			}
			if t, ok := givesTenantID(stmt); ok {
				tenant[t] = true
				global[t] = global[t] || f.global
			}
			isTenant := func(t string) bool { return tenant[t] && !global[t] }
			if m := alterTableRE.FindStringSubmatch(stmt.text); m != nil && isTenant(tableName(m[1])) {
				for _, clause := range splitClauses(m[2]) {
					if clause == "disable row level security" || clause == "no force row level security" {
						report("turns row-level security off on tenant table %s", tableName(m[1]))
					}
				}
			}
			if t := statementTable(stmt.text); t != "" && isTenant(t) && selfReferenceWithoutTenant(stmt.text, t) {
				report("%s references itself without tenant_id: use foreign key (tenant_id, <column>) references %s (tenant_id, id)", t, t)
			}
			if m := dropPolicyRE.FindStringSubmatch(stmt.text); m != nil {
				k := key{tableName(m[2]), strings.Trim(m[1], `"`)}
				if isTenant(k.table) {
					report("drops policy %s on tenant table %s: change it with alter policy instead", k.name, k.table)
				}
				delete(policies, k)
				continue
			}
			p, ok := parsePolicy(stmt.full)
			if !ok {
				continue
			}
			k := key{p.table, p.name}
			def, known := policies[k]
			switch {
			case p.create:
				def = p.def
			case p.renameTo != "":
				delete(policies, k)
				k.name = p.renameTo
			case !known || p.unparsedAlter:
				def = policyDef{}
			default:
				if p.usingSet {
					def.using = p.def.using
				}
				if p.checkSet {
					def.check = p.def.check
				}
			}
			policies[k] = def
			if !def.tenant() && !isAllowed(k) {
				report("policy %s on %s is not the tenant policy (permissive, for all commands, using and with check as in docs/tenancy.md section 4): make it that, or allow it by name with a reason", k.name, k.table)
			}
		}
	}
	return errs
}

func statementTable(stmt string) string {
	if m := createTableRE.FindStringSubmatch(stmt); m != nil {
		return tableName(m[1])
	}
	if m := alterTableRE.FindStringSubmatch(stmt); m != nil {
		return tableName(m[1])
	}
	return ""
}

// selfReferenceWithoutTenant is true when stmt, on table, declares a foreign key into table itself that
// does not pair tenant_id on both sides; a column's own references clause never can.
func selfReferenceWithoutTenant(stmt, table string) bool {
	for _, loc := range referencesRE.FindAllStringSubmatchIndex(stmt, -1) {
		if tableName(stmt[loc[2]:loc[3]]) != table {
			continue
		}
		local := foreignKeyRE.FindStringSubmatch(strings.TrimSpace(stmt[:loc[0]]))
		if local == nil || !tenantColumnRE.MatchString(local[1]) {
			return true
		}
		if loc[4] >= 0 && !tenantColumnRE.MatchString(stmt[loc[4]:loc[5]]) {
			return true
		}
	}
	return false
}
