package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// engine is a database `keel test` and `keel gen` use: the URL from the environment, else the
// compose default when something listens on its port.
type engine struct {
	name       string
	urlVar     string
	portVar    string
	port       string
	defaultURL func(port string) string
	hint       string
}

var engines = []engine{
	{
		name: "postgres", urlVar: "APP_TEST_DATABASE_URL", portVar: "KEEL_PG_PORT", port: "5442",
		defaultURL: func(port string) string {
			return "postgres://keel:keel-local@127.0.0.1:" + port + "/keel?sslmode=disable"
		},
		hint: "COMPOSE_PROFILES=pg make up",
	},
	{
		name: "mysql", urlVar: "APP_TEST_MYSQL_URL", portVar: "KEEL_MYSQL_PORT", port: "3316",
		defaultURL: func(port string) string { return "mysql://root:keel-local@127.0.0.1:" + port + "/keel" },
		hint:       "COMPOSE_PROFILES=mysql make up",
	},
}

// url is the engine's URL from the environment, else the compose default when something listens on its port.
func (e engine) url(ctx context.Context) (string, bool) {
	if u := os.Getenv(e.urlVar); u != "" {
		return u, true
	}
	port := e.port
	if p := os.Getenv(e.portVar); p != "" {
		port = p
	}
	if !listening(ctx, port) {
		return "", false
	}
	return e.defaultURL(port), true
}

func (e engine) unreachable() string {
	port := e.port
	if p := os.Getenv(e.portVar); p != "" {
		port = p
	}
	return "nothing listens on 127.0.0.1:" + port
}

// databaseURLs resolves the engines selected by only ("" for all) and reports skipped ones on out.
func databaseURLs(ctx context.Context, out io.Writer, only string) (map[string]string, error) {
	found := map[string]string{}
	for _, e := range engines {
		if only != "" && only != e.name {
			continue
		}
		if !hasDialect(e.name) {
			_, _ = fmt.Fprintf(out, "==> skipping %s: the app has no %s/%s\n", e.name, migrationsDir, e.name)
			continue
		}
		u, ok := e.url(ctx)
		if !ok {
			_, _ = fmt.Fprintf(out, "==> skipping %s: %s (%s)\n", e.name, e.unreachable(), e.hint)
			continue
		}
		found[e.name] = u
	}
	if len(found) == 0 {
		return nil, errors.New("no test database reachable: start one with `make up` (COMPOSE_PROFILES=pg,mysql) or set APP_TEST_DATABASE_URL")
	}
	return found, nil
}

// hasDialect is true when the app keeps the engine's migrations; an app made by keel init keeps one.
func hasDialect(name string) bool {
	_, err := os.Stat(filepath.Join(migrationsDir, name)) //nolint:gosec // name is an engine from the fixed list
	return err == nil
}

// testEnv sets the URL of every resolved engine and clears the others, so testdb uses exactly these.
func testEnv(urls map[string]string) []string {
	env := make([]string, 0, len(engines))
	for _, e := range engines {
		env = append(env, e.urlVar+"="+urls[e.name])
	}
	return env
}

func listening(ctx context.Context, port string) bool {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return false
	}
	_ = conn.Close() // only probing
	return true
}

// withDatabase points a server URL at another database on the same server.
func withDatabase(rawURL, name string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.New("database URL is not a valid URL")
	}
	u.Path = "/" + name
	return u.String(), nil
}
