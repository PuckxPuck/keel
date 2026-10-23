# Commands

Two command-line tools, both built on the small `kit/cli` package (stdlib `flag`, no framework):

- **`app`**: the production binary. Runs the server and workers and carries the operational commands you run on a server.
- **`keel`**: the development tool (`go run ./cmd/keel`; `make check`, `make test`, `make gen` and the like call it). Generators and checks. It is never built into a release, so production carries no generator code.

Commands are grouped `group:action`, like Laravel's artisan. `app list` and `keel list` print every command with a one-line description; `<command> --help` prints its flags. Every command takes `--json` where output is tabular, so scripts and agents can read it.

## app (production binary)

| Command | Does |
| --- | --- |
| `serve` | HTTP API; runs workers too unless `APP_JOBS_IN_SERVE=false` |
| `worker` | Job workers, the scheduler and the reaper only (same as `queue:work`, with `--lanes`), for running them apart from `serve` |
| `doctor` | Checks everything an operator should know before trusting a deploy (below). Exit code is non-zero on any failure |
| `config:check` | Validates configuration and prints it with secrets redacted |
| `about` | Version, commit, build time, Go version, dialect, enabled parts, realms |
| `migrate`, `migrate:status`, `migrate:validate`, `migrate:down` | Schema changes; `down` refused in production and staging. They read only the database settings (`APP_ENV`, `APP_DATABASE_MIGRATE_URL` or `APP_DATABASE_URL`, `APP_DATABASE_CA_FILE`, `APP_DATABASE_LOCK_TIMEOUT`); `migrate:validate` reads nothing and also requires exactly one Up statement in every `-- +goose NO TRANSACTION` file |
| `db:seed [--email <email>] [--tenant <slug>]` | Local only (`APP_ENV=local`): runs `setup`, creates the administrator (`admin@example.test`) holding the `admin` role, and under tenancy a tenant they own (`local`) and the `operator` role; sign in with dev login. Runs again without harm |
| `setup` | Production-safe, idempotent defaults: creates missing built-in roles, and makes existing built-in roles carry exactly the permissions their definitions list (adding new ones and removing dropped ones, audited as `role.permissions_synced`), so a new module's permissions reach a database set up before it. The access API never changes a built-in role (422 `builtin_role`), so nothing an administrator chose is overwritten; they make custom roles. Under tenancy the tenant realm's built-in roles are templates copied into each new tenant, so `setup` makes the operator realm's in one operator transaction and then syncs each tenant's copies in a transaction per tenant (a rerun finishes what a failure left) |
| `route:list` | Every operation: method, path, realm, `Need`, rate-limit class, public API flag |
| `permission:list` | The permission catalogue per realm, with which built-in roles hold each |
| `queue:work` | Run workers only (`--lanes fast,slow`) |
| `queue:status` | Depth and oldest job per lane, kind and status |
| `queue:failed [--limit 50]` | Failed jobs with their last error |
| `queue:retry <id\|--all-failed>`, `queue:cancel <id>` | Manual action on jobs |
| `queue:prune` | Remove finished jobs past retention now |
| `schedule:list` | Schedules with next run times |
| `schedule:run <name>` | Enqueue a scheduled job now |
| `user:create`, `user:grant`, `user:revoke-sessions` | People and access from the shell (first administrator, incidents). `user:create [--name <name>] [--print-link] <email>` creates the user and queues an invite through the notifier, or with `--print-link` prints the invite token to this terminal instead (no notifier needed, for the first user before mail is set up). The user can sign in once they hold a role (`user:grant`). `user:grant --realm <realm> --role <code> [--tenant <slug>] <email>` is break-glass: it grants as the system, skipping the checks of what the actor holds but not the realm check, and is audited; under tenancy a tenant realm grant names the tenant (the user becomes a member) and an operator realm grant runs on the operator pool. `user:revoke-sessions <email>` signs the user out of every realm |
| `openapi [--realm tenant]` | Print a realm's OpenAPI document as YAML (`--realm api` for the public API); needs no configuration |

<!-- part:tenancy -->
| Tenancy command | Does |
| --- | --- |
| `tenant:create\|list\|suspend\|resume` | Tenancy only, as the system on the operator pool. `tenant:create --owner <email> [--name <name>] [--domains a.example,b.example] <slug>` makes the tenant, copies the built-in roles into it and makes the owner a member holding `admin`; `tenant:suspend [--reason <why>] <slug>` refuses every request in it and ends its sessions; `tenant:resume [--reason <why>] <slug>` makes a suspended or read-only tenant active again |
<!-- /part:tenancy -->
<!-- part:apikeys -->

| API key command | Does |
| --- | --- |
| `apikey:list\|create\|revoke` | API keys. `apikey:create --name <name> [--scopes a.b,c.d] [--expires-in 720h] [--cidrs 203.0.113.0/24] [--rate-class <class>]` acts as the system (it skips the check of what the creator holds, never which permissions a key may carry) and prints the key once; `apikey:revoke <id>` stops it at once. Under tenancy each takes `--tenant <slug>` |
<!-- /part:apikeys -->
<!-- part:webhooks -->

| Webhook command | Does |
| --- | --- |
| `webhook:deliveries [--limit 50]`, `webhook:replay <id>` | Outbound webhook troubleshooting; under tenancy they run on the operator pool and a replay is queued for the delivery's tenant |
| `webhook:rekey` | Reseal endpoint secrets with the newest key, so an older key can be removed ([security.md](security.md#9-secrets)) |
<!-- /part:webhooks -->
<!-- part:connections -->

| Connection command | Does |
| --- | --- |
| `connection:rekey` | Reseal provider tokens with the newest key, so an older key can be removed ([security.md](security.md#9-secrets)) |
<!-- /part:connections -->

### doctor
Each check prints pass, warn, fail or skip with one line of detail (`--json` for scripts); the exit code is non-zero when any fails. Every network and database check, opening the database included, gives up after three seconds and reports under its own name, so one failure never hides another: when the database cannot be opened, the checks that need it are skipped; when migrations are behind, roles and clock still run while row-level security and jobs, which need the current schema, are skipped with that reason. Nothing is sent and the probe object is removed (the local driver keeps an empty `doctor/` directory).
- configuration: valid for the environment (and whether that is the production profile); an invalid one fails and stops there;
- database: reachable, with the round trip's latency; warns when the URL does not verify TLS;
- migrations: the database has every migration the binary ships (`serve` refuses to start otherwise);
<!-- part:tenancy -->
- roles (tenancy): `tenancy.CheckRoles`, the app role cannot bypass row-level security, own tables or reach the operator role, and the operator role can (fails without `APP_DATABASE_OPERATOR_URL`);
- row-level security (tenancy): the database's tenancy tables match the build, and `tenancy.CheckCatalogue`, every tenant table has it enabled, forced and the policy;
<!-- /part:tenancy -->
- operations: every operation has a `Need` from its realm's catalogue and a defined rate-limit class;
- jobs: warns when no worker ran a schedule in two hours (the hourly retention job), a lane has a job ready for over ten minutes, or a running job is past its lease and unreaped;
<!-- part:mail -->
- mail: connects to the SMTP server, upgrades to TLS as configured with the certificate verified, signs in when `APP_MAIL_SMTP_USER` is set, and quits before `MAIL FROM` (no message sent); warns on the log driver;
<!-- /part:mail -->
<!-- part:files -->
- files: storage writable and readable (a probe object under `<prefix>doctor/` written, read and removed); passes as off without a driver;
<!-- /part:files -->
<!-- part:pdf -->
- pdf: the renderer's `/health` answers 200; passes as off without a URL;
<!-- /part:pdf -->
- clock: this host within two seconds of the database (leases compare the two);
- keys: session keys present (warns locally without them), MFA keys when a realm uses MFA, no key shorter than 32 bytes;
- build: version and commit; warns when the build is older than 30 days (its dependencies have not been rechecked by govulncheck since).

## keel (development tool)

| Command | Does |
| --- | --- |
| `make:module <name>` | Scaffolds `internal/modules/<name>` with an example resource, its migration and tests, mounts it in `internal/app/modules.go`, and runs `gen` (below) |
| `make:migration <module> <what>` | `<UTC timestamp>_<module>_<what>.sql` in every dialect folder (the module must exist); `create_<table>` uses the table template, otherwise an Up and Down to fill in. Runs `gen` |
| `make:job <module> <kind>` | Job kind `<module>.<kind>`: constant, payload type, handler, registration in the module's `Jobs`, and a test |
| `make:command <group:action>` | An `app` command in `internal/app/<group>_<action>_command.go`, registered in `appCommands` |
| `make:permission <module.action>` | Adds a permission to the owning module's `permissions.go`; the tenant realm's `admin` role holds it |
| `gen` | Migrate a scratch database for each dialect folder under `db/migrations` and regenerate the Jet types in `internal/dbgen`; export each realm's OpenAPI document to `spec/<realm>.openapi.yaml`. `--check` fails on drift in either |
| `compat` | Fails on a breaking change to the public API since the latest `v*` release tag (below) |
| `check` | Everything CI runs, stopping at the first failure: `go mod tidy` drift, format, golangci-lint, vet, the tenant-setting rule (D30), the part rules and vet with each part's off tag, govulncheck, generated-code drift, the `compat` check, tests with `-race` |
| `tidy`, `lint`, `vuln` | One CI step each: `go mod tidy` drift, the `check` steps from format to the part rules, govulncheck. CI jobs call these, never the tools directly |
| `fmt` | Format the code (`golangci-lint fmt`) |
| `test` | Tests only: `--pkg` (default `./...`), `--run`, `--engine postgres\|mysql`; an engine whose `db/migrations/<dialect>` folder the app does not keep is skipped |
| `bench` | Benchmarks compared with a baseline or with another commit on the same machine (on demand; nightly in CI) |
| `init` | Make a new app from keel: module path, name, database, optional parts (below); refuses to run twice |
| `upgrade:diff <version>` | Show the kit changes between the app's `.keel-version` and a newer keel |

### Generators
Generators write code that already passes `keel check`: the `Need`, rate-limit class, audit call and tests each convention requires. They never overwrite a file and print every file they create or change.

- **Names.** A module name must be a lower-case identifier that is not a Go keyword or predeclared name, not a reserved word in MySQL or PostgreSQL (it is the table name; `make:migration create_<table>` checks the table the same way), and not a name that clashes in Go. That last check is made on the generated code itself: every package a generator touches is parsed with its planned files, and a package-level name declared twice, or an import name that a declaration in the same package also uses, stops the run. So `codes` (a function in `internal/app`), `strings` (imported by the module's tests) and `services` (the module would declare `Service` twice) are refused with the file that clashes.
- **Atomic.** A generator plans every file and edit in memory, validates the plan, and only then writes. A registration it cannot make (for example `modules` returns a variable, not a list) fails before anything is written, and the error says what to add by hand. If a write, or the `gen` run after it, fails, the files it wrote are removed and the files it edited are restored, so the same command can be run again.
- **Regeneration.** The generators that change the schema or the operations run `gen` when the databases of the dialect folders are reachable and otherwise say to run it.

- **`make:module invoices`** writes `module.go` (the `Module` the app mounts: its operations, error mapper, jobs and commands), `permissions.go` (`invoices.read`, `invoices.write`), `handlers.go`, `service.go` (typed id `invoices.ID`, writes in one transaction with `audit.Record`), `rules.go`, `store.go` (Jet; keyset list over `paging.Sorts` by `name` and `createdAt`; update with `version`, a stale one is 409), and three tests: the rule's table test, a store test on the database, and a permission walk through the app (reads need `invoices.read`, writes `invoices.write`). The operations are `listInvoices`, `getInvoice`, `createInvoice`, `updateInvoice` and `deleteInvoice` under `/invoices` on the tenant realm, with the `api-read` and `api-write` rate-limit classes. Its `Deps` carry the database, the audit recorder, the cursor keyset and the job queue serve runs (`Jobs`), so a service enqueues in the transaction that makes its change; `Build` mounts one instance of the module, and its operations, error mapper and jobs all come from that instance. Rename and reshape the example resource; it is a starting point. The store uses the first dialect folder's Jet package (Postgres when both exist) and, with the tenancy part (`internal/kit/tenancy` present, Postgres), takes `db.Tx[db.Tenant]`.
- **Migrations under tenancy.** `create_<table>` writes the table in every dialect folder; on Postgres in its final shape in that one file: `tenant_id` (defaulting to the transaction's tenant), keys and indexes led by it, and row-level security enabled and forced with the tenant policy ([tenancy.md](tenancy.md#4-schema-rules-for-tenant-tables), D36). A child table's composite foreign key to it then has a `(tenant_id, id)` key to point at. Only the kit's own tables use a separate `<timestamp>_tenancy_<table>.sql`, because the kit is tested with and without tenancy; package test databases leave out both those and modules with tenant tables, so a module's store test uses `testdb.Tenancy(t)`.
- **`make:job invoices send_reminder`** adds `KindSendReminder = "invoices.send_reminder"`, `SendReminderPayload`, a handler method and its registration with `jobs.Typed`, and a test that the kind can be enqueued. Kinds run for the tenant they were enqueued in; mark maintenance kinds `jobs.Global()` yourself.
- **`make:command reports:rebuild`** writes a command that loads the configuration and opens the database; give it its work. A module's own commands go in its `Commands`, which receives an opener for the database.
- **`make:permission invoices.approve`** checks the code format (`<module>.<action>`, lower case, up to 128 characters) and that the module exists. The next `app setup` adds it to the existing `admin` role (every tenant's under tenancy).

### gen
`gen` follows the dialect folders the app keeps under `db/migrations`, not the databases it can reach: an app with only `mysql` needs only MySQL, and a folder whose database is not reachable is an error naming the variable to set (`APP_TEST_DATABASE_URL`, `APP_TEST_MYSQL_URL`) and the compose command that starts one.

`spec/<realm>.openapi.yaml` (tenant, operator, api) are generated files: `gen` builds `cmd/app` and writes `app openapi --realm <realm>` for each realm `route:list` names, and deletes the document of a realm that no longer exists; it fails if a document describes errors with Huma's `ErrorModel` instead of keel's `Problem`. Never edit them; change the operations and run `gen`.

### compat
`keel compat` compares `spec/api.openapi.yaml` in the working tree (which `gen --check` keeps equal to the code) with the one at the latest `v*` tag reachable from HEAD, using `oasdiff breaking`; deploy and other tags do not count, and neither do keel's own tags in an app cloned from it (those reachable from the commit in `.keel-version`). It says why when it compares nothing: no public api realm (the app removed `apikeys`, so there is no document and no `internal/kit/apikeys`), not a git repository, no commits yet, no release tag yet, or the tag has no api document. A full clone that lacks the tag `.keel-version` names (pushing an app to its own remote does not push keel's tags) has none of keel's tags either, so nothing is excluded and the app's own latest tag, if any, is compared. A shallow clone with no tags is an error, because the check could not tell. CI runs it on pull requests with the full history fetched (`fetch-depth: 0`); `check` runs it too.

### bench
`keel bench` runs every package that declares a benchmark (`go test -run '^$' -bench . -benchmem -count 6`), writes the results to `var/bench/current.txt`, and prints benchstat's comparison with a baseline. It fails on a significant change worse than `--threshold` percent (default 10) in time, bytes or allocations per op, or in throughput (`SetBytes`). `--bench` selects benchmarks and `--count` sets the runs of each.

- **Same machine only.** A baseline file is compared only when its `goos`, `goarch` and `cpu` lines match this run's; otherwise `bench` says it is not comparing. CPU models on shared CI runners differ from night to night, which is why CI never keeps results across runs.
- **Against a commit.** `keel bench --against <ref>` runs the benchmarks at `<ref>` in a temporary git worktree, then the current checkout, back to back on this machine, and compares the two. Use it to compare a branch with main (`--against main`).
- **Saved baseline.** `keel bench --save` keeps the run in `var/bench/baseline.txt` for later runs on the same machine (`--baseline` names another file). `--save` refuses to overwrite the baseline when the run found regressions; `--save --force` accepts them.
- **Nightly CI.** The job restores the SHA of the last commit whose run passed, runs `--against` it, and saves `HEAD` when the run passes. A regression fails the run and keeps the old SHA, so it fails again each night until fixed. To accept it, delete the marker (`gh cache list --key bench-last-good`, then `gh cache delete <id>`); the next night has no earlier commit and starts from there.

<!-- part:keel -->
### init
`keel init --module <path> --name <name> --db postgres|mysql [--without a,b|all] [--with notes] [--env-prefix APP_] [--dry-run] [--keep-on-failure]` turns a fresh clone of keel into an app. Run it from the repository root on a clean checkout, at a release tag:

```
git clone <keel> shop && cd shop && git checkout v1.2.0
go run ./cmd/keel init --module example.com/me/shop --name shop --db postgres --without pdf,docx,barcode
git add -A && git commit -m "keel init"
```

- **Flags.** `--module` is the Go module path. `--name` (`^[a-z][a-z0-9]{1,29}$`) names the binary's `Name`, the OpenAPI title, the Postgres roles (`<name>_owner`, `_app`, `_operator`), the compose project, database and user, the systemd unit (`deploy/systemd/<name>@.service`, `/srv/<name>`, `/etc/<name>`), nginx's upstream, the Kubernetes objects and `release.sh`'s default `DEPLOY_NAME`; the code keeps `cmd/app` and `internal/app`. `--db` keeps one dialect. `--env-prefix` (default `APP_`, `^[A-Z][A-Z0-9]*_$`, not `KEEL_`) renames every setting outside `internal/kit`; `APP_TEST_*` stays, since it belongs to the test tooling. `--dry-run` prints the plan and writes nothing; `--keep-on-failure` leaves a failed result for inspection instead of resetting.
- **Parts.** `--without` takes `tenancy`, `apikeys` (with the api realm), `webhooks` (outbound), `connections`, `files`, `mail`, `pdf`, `docx`, `xlsx`, `barcode`, `oidc`, `passkey`, `otel`, or `all`. The example module `notes` is removed unless `--with notes`, which needs Postgres, tenancy, files, mail and xlsx (D36). Tenancy needs Postgres, so `--db mysql` needs `--without tenancy`. Unknown names are refused.
- **Refusals.** Init refuses a second run (`.keel-version` exists; keel itself never has one), a checkout with changes or untracked files, a commit-less checkout, a database it cannot connect to, since `keel gen` needs it (the URL from `APP_TEST_DATABASE_URL` or `APP_TEST_MYSQL_URL`, else the compose default, is connected to before anything is written), and a symlink or anything else that is not a regular file among the paths it would change or delete. It warns when HEAD is not on a release tag, because `upgrade:diff` works from tags.
- **Plan.** Everything is planned in memory first: the removed parts' `internal/kit` directories, migrations in every dialect folder, `internal/dbgen` tables and owned files (the parts table is `cmd/keel/parts.go`); each part's Go wiring is a pair in `internal/app`, `<part>.go` (`//go:build !no<part>`) and `<part>_off.go` (`//go:build no<part>`), and init keeps the one the app builds and strips its constraint, so an app has no build tags (the example module `notes` is such a pair too, `notes.go` and `notes_off.go` with the tag `nonotes`, plus `internal/modules/notes`); the other dialect's folders and the `//go:embed` line; keel-only paths (`docs/plans`, `docs/research`, `init-matrix.yml`); whole-line markers in every file that is not Go (`<!-- part:x -->` and `<!-- /part:x -->` in Markdown, `-- part:x` and `-- /part:x` in SQL, `# part:x` and `# /part:x` elsewhere; a removed part's block goes, a kept part's markers go, `part:keel` blocks always go); the module path (imports through `go/parser`, the rest from a fixed table), name and prefix rewrites; and `.keel-version` (`git describe --tags --always`). The plan then checks itself: no part build tag, no marker and no keel module path is left, every table entry matched, no file outside `docs/`, `internal/kit`, tests and `.gitignore` holds text a name rewrite would still change (a keel name in a file the table does not cover), and under `--env-prefix` no `APP_` setting is left outside `internal/kit` but `APP_TEST_*`.
- **Run.** Init writes the plan, then runs `go mod tidy` (root and tools), `go build ./...`, `go vet ./...`, `keel gen` and `keel check` against the one engine. If the write or any of them fails, or init is interrupted (Ctrl-C), it runs `git reset --hard <HEAD>` and `git clean -fd` (no `-x`, so `.env` and other ignored files survive; the interrupt does not stop the reset). `--keep-on-failure` leaves a failed step's result instead, never an interrupted one. It ends with the removed parts, a warning when mail is gone (outside local the app then refuses to start until it passes a `Notifier` in `Deps`), and a note to stop keel's local containers before `make up`: they hold the same ports and know only keel's database names.
- **Adding a part back later.** Copy keel's `internal/kit/<part>` directories, `internal/app/<part>.go`, its migrations (with new timestamps) and its config, delete the app's `<part>_off.go`, and run `keel gen`.
- **Tested.** `keel check` builds the plan over keel's own tree for several flag sets and checks it; one test runs init on a copy with a settings prefix and builds the result; others inject a failure midway through the write and an interrupt, and check the checkout is back at HEAD. `init-matrix.yml` runs init, with gen and the full check, nightly for eight combinations (Postgres with every part, with and without notes, and with `--env-prefix SHOP_`; without tenancy; MySQL with every other part; Postgres and MySQL without every part; Postgres with tenancy alone) and weekly with each part removed alone.
<!-- /part:keel -->

### upgrade:diff
`keel upgrade:diff --keel <checkout> <version>` prints `git diff <from> <version> -- internal/kit cmd/keel` in a local keel checkout, where `<from>` is the app's `.keel-version` (written by `keel init`), leaving out the kit directories keel had at `<from>` that the app removed at init, so `git apply` does not fail on them (kit directories keel added later are included); `--stat` lists files only, and `KEEL_CHECKOUT` stands in for `--keel`. keel's module path in the diff (from the checkout's `go.mod`) is rewritten to the app's, so it applies to an app whose imports init rewrote. Limits: the checkout must hold both versions as tags (`git fetch --tags`); the name rewrites are not redone, so a hunk on a line init renamed (the local database URL in `cmd/keel/database.go`) needs a hand edit; only `internal/kit` and `cmd/keel` are covered, so changes keel made to `internal/app`, migrations or docs are read from its release notes; update `.keel-version` after applying.
