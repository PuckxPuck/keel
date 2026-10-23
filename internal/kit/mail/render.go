package mail

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io/fs"
	"path"
	"slices"
	"strings"
	texttemplate "text/template"
)

//go:embed templates/*
var defaults embed.FS

const (
	layoutHTML = "layout.html"
	layoutText = "layout.txt"
)

// Rendered is a template's output.
type Rendered struct {
	Subject string
	Text    string
	HTML    string
}

// Renderer renders named templates inside a layout. Each name has <name>.txt, defining "subject" and
// "content", and optionally <name>.html, defining "content". layout.txt and layout.html wrap the content.
// The app's files win over the kit defaults (reset, verify, invite and the layouts).
type Renderer struct {
	text map[string]*texttemplate.Template
	html map[string]*htmltemplate.Template
}

// NewRenderer parses every template at startup; app may be nil to use only the defaults.
func NewRenderer(app fs.FS) (*Renderer, error) {
	kit, err := fs.Sub(defaults, "templates")
	if err != nil {
		return nil, err
	}
	layers := []fs.FS{kit}
	if app != nil {
		layers = []fs.FS{app, kit}
	}
	read := func(name string) (string, bool, error) {
		for _, l := range layers {
			b, err := fs.ReadFile(l, name)
			if err == nil {
				return string(b), true, nil
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return "", false, err
			}
		}
		return "", false, nil
	}
	var names []string
	for _, l := range layers {
		files, err := fs.Glob(l, "*.txt")
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if n := strings.TrimSuffix(path.Base(f), ".txt"); f != layoutText && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	lt, _, err := read(layoutText)
	if err != nil {
		return nil, err
	}
	lh, _, err := read(layoutHTML)
	if err != nil {
		return nil, err
	}
	r := &Renderer{text: map[string]*texttemplate.Template{}, html: map[string]*htmltemplate.Template{}}
	for _, n := range names {
		body, _, err := read(n + ".txt")
		if err != nil {
			return nil, err
		}
		t, err := texttemplate.New(layoutText).Option("missingkey=error").Parse(lt)
		if err == nil {
			_, err = t.Parse(body)
		}
		if err != nil {
			return nil, fmt.Errorf("mail: template %s.txt: %w", n, err)
		}
		if t.Lookup("subject") == nil {
			return nil, fmt.Errorf("mail: template %s.txt must define subject", n)
		}
		r.text[n] = t
		htmlBody, ok, err := read(n + ".html")
		if err != nil || !ok {
			if err != nil {
				return nil, err
			}
			continue
		}
		h, err := htmltemplate.New(layoutHTML).Option("missingkey=error").Parse(lh)
		if err == nil {
			_, err = h.New("subject").Parse(t.Lookup("subject").Root.String())
		}
		if err == nil {
			_, err = h.Parse(htmlBody)
		}
		if err != nil {
			return nil, fmt.Errorf("mail: template %s.html: %w", n, err)
		}
		r.html[n] = h
	}
	return r, nil
}

var ErrUnknownTemplate = errors.New("mail: unknown template")

func (r *Renderer) Render(name string, data any) (Rendered, error) {
	t, ok := r.text[name]
	if !ok {
		return Rendered{}, fmt.Errorf("%w %q", ErrUnknownTemplate, name)
	}
	var subject, text bytes.Buffer
	if err := t.ExecuteTemplate(&subject, "subject", data); err != nil {
		return Rendered{}, fmt.Errorf("mail: render %s subject: %w", name, err)
	}
	if err := t.Execute(&text, data); err != nil {
		return Rendered{}, fmt.Errorf("mail: render %s: %w", name, err)
	}
	out := Rendered{Subject: strings.Join(strings.Fields(subject.String()), " "), Text: strings.TrimSpace(text.String()) + "\n"}
	if h, ok := r.html[name]; ok {
		var html bytes.Buffer
		if err := h.Execute(&html, data); err != nil {
			return Rendered{}, fmt.Errorf("mail: render %s html: %w", name, err)
		}
		out.HTML = html.String()
	}
	return out, nil
}
