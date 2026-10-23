package main

import (
	"regexp"
	"slices"
	"strings"
)

// part is an optional piece of keel that keel init can remove. The Go wiring of a part is an on file
// internal/app/<name>.go (//go:build !no<name>) and an off twin <name>_off.go (//go:build no<name>);
// init keeps one of the two and strips the constraint, so an app has no build tags.
type part struct {
	name string
	// kit are the internal/kit directories the part owns.
	kit []string
	// app names the internal/app on/off pairs by their on file's base name.
	app []string
	// tests are the test files whose constraint names the part, off-twin tests (<name>_off_test.go) included.
	tests []string
	// migrations are stems (<timestamp>_<stem>.sql), removed from every dialect folder that has them.
	migrations []string
	// tables are the internal/dbgen tables those migrations create.
	tables []string
	// paths are other files and directories the part owns.
	paths []string
	// requires are the parts that must be kept for this one.
	requires     []string
	postgresOnly bool
	// module parts are kept only on request (--with), the rest unless removed (--without).
	module bool
}

func (p part) tag() string { return "no" + p.name }

var parts = []part{
	{
		name: "tenancy", kit: []string{"internal/kit/tenancy"}, app: []string{"tenancy"},
		tests: []string{
			"internal/app/tenancy_test.go", "internal/app/doctor_test.go", "internal/app/tenancy_apikeys_test.go", "internal/app/files_test.go",
			"internal/app/tenancy_off_test.go", "internal/app/tenancy_export_test.go",
		},
		migrations: []string{
			"tenancy_tenants", "tenancy_tenant_domains", "tenancy_memberships", "tenancy_sessions", "tenancy_roles",
			"tenancy_role_permissions", "tenancy_user_roles", "tenancy_audit_log", "tenancy_idempotency_keys",
			"tenancy_devices", "tenancy_device_pairing_codes", "tenancy_files", "tenancy_tombstones", "tenancy_jobs",
			"tenancy_mail_outbox", "tenancy_webhook_endpoints", "tenancy_webhook_events",
			"tenancy_webhook_out_deliveries", "tenancy_connections", "tenancy_oauth_states", "tenancy_api_keys",
			"tenancy_api_key_tenants", "tenancy_notes",
		},
		tables:       []string{"tenants", "tenant_domains", "memberships", "api_key_tenants"},
		paths:        []string{"spec/operator.openapi.yaml", "docs/tenancy.md"},
		postgresOnly: true,
	},
	{
		name: "apikeys", kit: []string{"internal/kit/apikeys"}, app: []string{"apikeys"},
		tests:      []string{"internal/app/apirealm_test.go", "internal/app/tenancy_apikeys_test.go"},
		migrations: []string{"kit_api_keys", "tenancy_api_keys", "tenancy_api_key_tenants"},
		tables:     []string{"api_keys", "api_key_tenants"},
		paths:      []string{"spec/api.openapi.yaml", "internal/app/mail/apikey_expiring.txt", "internal/app/mail/apikey_leaked.txt"},
	},
	{
		name: "webhooks", kit: []string{"internal/kit/webhooks"}, app: []string{"webhooks"},
		migrations: []string{
			"kit_webhook_endpoints", "kit_webhook_events", "kit_webhook_out_deliveries", "kit_webhook_endpoints_previous_secret",
			"tenancy_webhook_endpoints", "tenancy_webhook_events", "tenancy_webhook_out_deliveries",
		},
		tables: []string{"webhook_endpoints", "webhook_events", "webhook_out_deliveries"},
		paths:  []string{"internal/app/mail/webhook_disabled.txt"},
	},
	{
		name: "connections", kit: []string{"internal/kit/connections"}, app: []string{"connections"},
		migrations: []string{"kit_connections", "tenancy_connections"},
		tables:     []string{"connections"},
	},
	{
		name: "files", kit: []string{"internal/kit/files", "internal/kit/fileshttp"}, app: []string{"files"},
		tests:      []string{"internal/app/files_test.go", "internal/app/files_doctor_test.go", "internal/app/files_export_test.go"},
		migrations: []string{"kit_files", "tenancy_files"},
		tables:     []string{"files"},
	},
	{
		name: "mail", kit: []string{"internal/kit/mail"}, app: []string{"mail"},
		tests:      []string{"internal/app/mail_test.go"},
		migrations: []string{"kit_mail_outbox", "tenancy_mail_outbox"},
		tables:     []string{"mail_outbox"},
		paths:      []string{"internal/app/mail"},
	},
	{name: "pdf", kit: []string{"internal/kit/pdf"}, app: []string{"pdf"}, tests: []string{"internal/app/pdf_test.go"}},
	{name: "docx", kit: []string{"internal/kit/docx"}},
	{name: "xlsx", kit: []string{"internal/kit/xlsx"}, app: []string{"xlsx"}},
	{name: "barcode", kit: []string{"internal/kit/barcode"}},
	{
		name: "oidc", kit: []string{"internal/kit/auth/oidc"}, app: []string{"oidc"},
		tests:      []string{"internal/app/oidc_test.go"},
		migrations: []string{"kit_identities"},
		tables:     []string{"identities"},
	},
	{
		name: "passkey", kit: []string{"internal/kit/auth/passkey"}, app: []string{"passkey"},
		tests:      []string{"internal/app/passkey_test.go"},
		migrations: []string{"kit_passkeys", "kit_auth_challenges"},
		tables:     []string{"passkeys", "auth_challenges"},
	},
	{name: "otel", kit: []string{"internal/kit/otelx"}, app: []string{"otel"}},
	{
		name: "notes", module: true, app: []string{"notes"},
		migrations: []string{"notes_create_notes", "tenancy_notes"},
		tables:     []string{"notes"},
		tests:      []string{"internal/app/files_test.go"},
		paths:      []string{"internal/modules/notes", "internal/app/mail/note_archived.txt"},
		requires:   []string{"tenancy", "files", "mail", "xlsx"},
	},
}

// coreKit are the internal/kit directories every app keeps; a directory below one belongs to it unless a
// part names it.
var coreKit = []string{
	"internal/kit/audit", "internal/kit/auth", "internal/kit/buildinfo", "internal/kit/cli", "internal/kit/clock",
	"internal/kit/config", "internal/kit/csvx", "internal/kit/dates", "internal/kit/db", "internal/kit/health",
	"internal/kit/httpx", "internal/kit/idempotency", "internal/kit/ids", "internal/kit/jobs", "internal/kit/logx",
	"internal/kit/migrate", "internal/kit/money", "internal/kit/netguard", "internal/kit/oauthstate",
	"internal/kit/occ", "internal/kit/paging", "internal/kit/ratelimit", "internal/kit/rbac", "internal/kit/seal",
	"internal/kit/server", "internal/kit/testdb", "internal/kit/users", "internal/kit/webhook",
}

// coreMigrations are the migration stems every app keeps. oauth_states stays even without oidc and
// connections: it is small and empty.
var coreMigrations = []string{
	"kit_locks", "kit_users", "kit_roles", "kit_role_permissions", "kit_user_roles", "kit_audit_log",
	"kit_rate_counters", "kit_idempotency_keys", "kit_webhook_deliveries", "kit_migrations_applied",
	"kit_audit_chain", "kit_sessions", "kit_credentials", "kit_auth_tokens", "kit_mfa_totp",
	"kit_mfa_recovery_codes", "kit_devices", "kit_device_pairing_codes", "kit_users_email_verified",
	"kit_tombstones", "kit_jobs", "kit_job_schedules", "kit_oauth_states", "kit_job_schedules_build",
}

// keelOnly are paths an app never gets.
var keelOnly = []string{"docs/plans", "docs/research", ".github/workflows/init-matrix.yml"}

var dialectNames = []string{"postgres", "mysql"}

// keelMarker marks lines that describe keel itself; init always strips them.
const keelMarker = "keel"

// ownedFiles are a part's Go files in internal/app: its on/off pairs and tests.
func ownedFiles(p part) []string {
	out := slices.Clone(p.tests)
	for _, base := range p.app {
		out = append(out, "internal/app/"+base+".go", "internal/app/"+base+"_off.go")
	}
	return out
}

// partsOwning are the parts whose on file or tests rel is. keel init strips constraints, so in an app
// this is what still says which part a file belongs to.
func partsOwning(rel string) []string {
	var out []string
	for _, p := range parts {
		if !strings.HasSuffix(rel, "_off.go") && !strings.HasSuffix(rel, "_off_test.go") && slices.Contains(ownedFiles(p), rel) {
			out = append(out, p.name)
		}
	}
	return out
}

func partNamed(name string) (part, bool) {
	i := slices.IndexFunc(parts, func(p part) bool { return p.name == name })
	if i < 0 {
		return part{}, false
	}
	return parts[i], true
}

// optionalParts are the names --without takes.
func optionalParts() []string {
	var out []string
	for _, p := range parts {
		if !p.module {
			out = append(out, p.name)
		}
	}
	return out
}

// markerNames are every name a part: marker may carry.
func markerNames() []string {
	out := []string{keelMarker}
	for _, p := range parts {
		out = append(out, p.name)
	}
	return append(out, dialectNames...)
}

// replacement is one fixed text rewrite init makes outside Go code (and the few Go literals that are not
// import paths). Every entry must match in keel, so a moved line fails a test instead of leaving keel's
// value in an app.
type replacement struct {
	// paths are files, or directories when they end in "/".
	paths []string
	re    *regexp.Regexp
	// to may use $1 for the expression's groups.
	to string
	// dialect limits the entry to apps that keep that engine; its lines are in a dialect block.
	dialect string
}

func (r replacement) covers(rel string) bool {
	for _, p := range r.paths {
		if rel == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(rel, p)) {
			return true
		}
	}
	return false
}

func literal(paths []string, from, to string) replacement {
	return replacement{paths: paths, re: regexp.MustCompile(regexp.QuoteMeta(from)), to: strings.ReplaceAll(to, "$", "$$")}
}

func onlyOn(dialect string, r replacement) replacement {
	r.dialect = dialect
	return r
}

func pattern(paths []string, expr, to string) replacement {
	return replacement{paths: paths, re: regexp.MustCompile(expr), to: to}
}

const embedFile = "db/migrations/embed.go"

func dialectReplacements(keep string) []replacement {
	return []replacement{literal([]string{embedFile}, "//go:embed postgres/*.sql mysql/*.sql", "//go:embed "+keep+"/*.sql")}
}

// moduleReplacements cover the module path outside Go code; Go files are rewritten through go/parser.
func moduleReplacements(from, to string) []replacement {
	q := regexp.QuoteMeta
	return []replacement{
		pattern([]string{"go.mod"}, `(?m)^module `+q(from)+`$`, "module "+to),
		pattern([]string{"tools/go.mod"}, `(?m)^module `+q(from)+`/tools$`, "module "+to+"/tools"),
		literal([]string{"Makefile", "deploy/docker/Dockerfile"}, from+"/internal/kit/buildinfo", to+"/internal/kit/buildinfo"),
		literal([]string{".golangci.yml"}, q(from)+"/", q(to)+"/"),
		pattern([]string{".golangci.yml"}, `(?m)^(\s+- )`+q(from)+`$`, "${1}"+to),
	}
}

// unitFile is the systemd template unit, renamed to <name>@.service.
const unitFile = "deploy/systemd/app@.service"

func unitFileFor(name string) string { return "deploy/systemd/" + name + "@.service" }

func nameReplacements(name string) []replacement {
	unit := []string{unitFile}
	k8s := []string{"deploy/k8s/"}
	return []replacement{
		literal([]string{"internal/app/commands.go"}, `const Name = "app"`, `const Name = "`+name+`"`),
		pattern([]string{"README.md"}, `(?m)^# keel$`, "# "+name),
		pattern([]string{"internal/app/build.go"}, `(Title:\s+)"keel"`, `${1}"`+name+`"`),
		literal([]string{embedFile}, `RolePrefix = "keel"`, `RolePrefix = "`+name+`"`),
		// The migration grants the schema check's function to the roles by name; no database has applied
		// it before init.
		pattern([]string{"deploy/db/postgres-roles.sql", ".env.example", "db/migrations/postgres/", "docs/conventions/database.md"},
			`\bkeel_(owner|app|operator)\b`, name+"_$1"),
		pattern([]string{".env.example"}, `(?m)/keel(\?|$)`, "/"+name+"$1"),
		pattern([]string{"docker-compose.yml"}, `(?m)^name: keel$`, "name: "+name),
		onlyOn("postgres", pattern([]string{"docker-compose.yml"}, `(?m)^(\s+(?:POSTGRES_USER|POSTGRES_DB): )keel$`, "${1}"+name)),
		onlyOn("postgres", literal([]string{"docker-compose.yml"}, "pg_isready -U keel -d keel", "pg_isready -U "+name+" -d "+name)),
		onlyOn("mysql", pattern([]string{"docker-compose.yml"}, `(?m)^(\s+MYSQL_DATABASE: )keel$`, "${1}"+name)),
		literal([]string{"cmd/keel/database.go"}, "postgres://keel:", "postgres://"+name+":"),
		literal([]string{"cmd/keel/database.go"}, `+ port + "/keel`, `+ port + "/`+name),
		literal([]string{"Makefile"}, "bin/app", "bin/"+name),
		literal([]string{"Makefile"}, "(sha256sum app 2>/dev/null || shasum -a 256 app) > app.sha256",
			"(sha256sum "+name+" 2>/dev/null || shasum -a 256 "+name+") > "+name+".sha256"),
		literal([]string{"deploy/release.sh"}, "DEPLOY_NAME=${DEPLOY_NAME:-app}", "DEPLOY_NAME=${DEPLOY_NAME:-"+name+"}"),
		literal([]string{"deploy/release.sh", "docs/"}, unitFile, unitFileFor(name)),
		literal(append(unit, "deploy/systemd/app.env"), "/etc/app/", "/etc/"+name+"/"),
		literal(unit, "/srv/app/", "/srv/"+name+"/"),
		pattern(unit, `/slots/%i/app\b`, "/slots/%i/"+name),
		pattern(unit, `(?m)^(User|Group)=app$`, "${1}="+name),
		literal(unit, "Description=app ", "Description="+name+" "),
		pattern(unit, `\bapp@(blue|green)\b`, name+"@$1"),
		literal(unit, "StateDirectory=app/", "StateDirectory="+name+"/"),
		literal([]string{"deploy/nginx/nginx.conf"}, "conf.d/app.conf", "conf.d/"+name+".conf"),
		literal([]string{"deploy/nginx/nginx.conf"}, "/etc/nginx/app/", "/etc/nginx/"+name+"/"),
		literal([]string{"deploy/nginx/nginx.conf"}, "proxy_pass http://app;", "proxy_pass http://"+name+";"),
		literal([]string{"deploy/nginx/upstream.conf"}, "upstream app {", "upstream "+name+" {"),
		pattern(k8s, `(?m)^(\s*(?:- )?name: )app$`, "${1}"+name),
		pattern(k8s, `(?m)(app\.kubernetes\.io/name: )app$`, "${1}"+name),
		pattern(k8s, `(?m)(secretName: )app$`, "${1}"+name),
		pattern(k8s, `/run/secrets/app\b`, "/run/secrets/"+name),
		literal(k8s, "registry.example.com/app@", "registry.example.com/"+name+"@"),
		pattern(k8s, `\bapp-(env|migrate-)`, name+"-$1"),
		literal(k8s, `the "app" Secret`, `the "`+name+`" Secret`),
		pattern([]string{"deploy/docker/Dockerfile"}, `/out/app\b`, "/out/"+name),
		pattern([]string{"deploy/docker/Dockerfile"}, `(?m) /app$`, " /"+name),
		literal([]string{"deploy/docker/Dockerfile"}, `ENTRYPOINT ["/app"]`, `ENTRYPOINT ["/`+name+`"]`),
		literal([]string{"deploy/docker/Dockerfile", ".github/workflows/deploy-test.yml"}, "-t app:", "-t "+name+":"),
		pattern([]string{".gitignore"}, `(?m)^/app$`, "/"+name),
	}
}

// envNotPrefixed are APP_ names that are not the app's settings: test tooling read by kit/testdb and set
// by keel and CI.
var envNotPrefixed = []string{"APP_TEST_"}

var envTokenRE = regexp.MustCompile(`\bAPP_[A-Z0-9_]*`)

// rewriteEnvPrefix replaces the APP_ prefix of every setting name in src.
func rewriteEnvPrefix(src []byte, prefix string) ([]byte, int) {
	n := 0
	out := envTokenRE.ReplaceAllFunc(src, func(tok []byte) []byte {
		s := string(tok)
		for _, keep := range envNotPrefixed {
			if strings.HasPrefix(s, keep) && (strings.HasSuffix(keep, "_") || s == keep) {
				return tok
			}
		}
		n++
		return []byte(prefix + strings.TrimPrefix(s, "APP_"))
	})
	return out, n
}
