# Go conventions

## Style
- `gofumpt`, `goimports`, golangci-lint clean (config in `.golangci.yml`). Explicit over clever; early returns; small functions with one job.
- Package names are short nouns (`invoices`, `jobs`). No `utils`, `helpers`, `common`, `models`.
- Few comments. Names and types explain the code; a comment is only for a non-obvious why (a security reason, a surprising constraint), in one or two short lines. No comments that restate the code, no narrative or design essays in code (that belongs in `docs/`), no section banners. Exported identifiers get a one-line doc comment only when the name and signature do not already say what the caller can rely on; the linter does not force doc comments.
- The same goes for config and tooling files (`.env.example`, compose, Makefile, CI): a few short lines at most.
- No dead or commented-out code. No `TODO` without an owner and a reason.
- Named constants for statuses and kinds, mirrored by database check constraints.

## Type and memory safety
- **Typed ids.** Each entity has its own id type (`type InvoiceID = ids.ID[invoiceTag]`; the `=` matters, a defined type would drop the methods), so passing a customer id where an invoice id belongs does not compile. Stores convert at the Jet boundary; services and handlers only see typed ids. They marshal as UUID strings and validate on input.
- **Typed enums.** Statuses and kinds are defined string types with constants (`type InvoiceStatus string`), validated on input, mirrored by a check constraint, and switched on exhaustively (the `exhaustive` linter fails a switch that misses a case).
- **No `any` in domain code.** Generics where a function is truly generic; concrete types everywhere else. `map[string]any` only at the edge for genuinely free-form JSON, decoded into a struct as soon as its shape is known.
- **Money and time are types**, never bare `int64` or `string`: `money.Amount`, `dates.Date`, `time.Time`.
- **Memory safety.** No `unsafe` and no cgo in the code (`CGO_ENABLED=0` for every build and release; depguard forbids importing `unsafe` outside generated code). The one exception is the test step: the race detector needs cgo on Linux, so `keel check` and CI enable it only while running `go test -race`. Every test runs with `-race`, since a data race is the one way pure Go loses memory safety.
- **Nil safety.** Constructors return usable values or an error, never a half-built struct.
- **Untrusted input.** Every parser of outside input (cursors, tokens, API keys, webhook signatures, CSV, xlsx, file inspection) has a fuzz test (`go test -fuzz`): its seed corpus runs with every `go test`, 30 seconds of fuzzing per target on main and 10 minutes nightly.
- **Bounded everything.** Every read from outside has a size limit, every loop over outside data a count limit, every outbound call a timeout.

## Errors
- Wrap with context: `fmt.Errorf("load invoice %s: %w", id, err)`. Never discard an error; `_ =` needs a comment saying why.
- Domain errors are sentinels or typed errors in the module (`var ErrInvoiceLocked = errors.New("invoice is locked")`), matched with `errors.Is` and `errors.As`, and mapped to HTTP by a problem mapper the module registers. Services never return HTTP types.
- Guards return every failing check, not the first, as a typed error the mapper turns into 422 with a list.
- Panics only for programmer errors at startup (duplicate registration, missing rate-limit class). Never on input.

## Context
- `context.Context` is the first parameter of anything that does IO or reads the clock.
- Never store a context in a struct. Never use `context.Background()` inside a request path; use the request's context, or `context.WithoutCancel` for work that must finish after the client leaves (with its own timeout).

## Dependencies and state
- No global state except the default `slog` logger configured once in `main`.
- Dependencies arrive through constructors or the app's `Deps`. Interfaces are declared by the consumer, small, and only where there is a second implementation or a module boundary.
- Kit packages take configuration values, not the whole app config.

## Time
- Domain code reads `clock.Business(ctx).Now()` or `clock.Today(ctx, loc)`, never `time.Now()`.
- Expiry, leases, signatures and rate limits read `clock.Wall(ctx)`.
- Instants are `time.Time` in UTC. Calendar dates are `dates.Date`. A business's time zone is configuration, never a constant.

## Concurrency
- Every goroutine has an owner that waits for it (`errgroup`, `sync.WaitGroup`) and a context that stops it. No fire-and-forget goroutines in request paths; use a job.
- Shared maps are guarded or sharded; prefer channels only where ownership transfers.
- Tests for concurrent code use `testing/synctest` where it fits, and `-race` always.

## Rules and state machines
- Pure functions: `(current, action, actor, facts) -> (next, error)`. Services load facts, call the function, write the new state and any history row in one transaction.
- Table tests, one table per rule, with case names a reader recognises from the requirement.

## Logging
- `slog` with structured attributes, from the context logger (`logx.From(ctx)`), never `fmt.Println` or `log`.
- Never log tokens, passwords, codes, secrets, emails, phone numbers, request or response bodies. `logx` redacts by attribute key (words and adjacent word pairs in snake, kebab or camel case), never by value: a struct passed as one attribute is not inspected.
- One line per event; errors logged once, where handled, not at every layer.

## Generated code
- Never edit `internal/dbgen/`, `spec/`, or anything with a `Code generated` header. Change the source and run `make gen`.
