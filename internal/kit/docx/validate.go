package docx

import (
	"archive/zip"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"strings"
)

const maxPartBytes = 32 << 20

// Validate checks a document structurally: the required parts exist and parse, every part has a
// content type, every internal relationship target exists, every style and numbering the body uses is
// defined, and fields open and close in pairs.
func Validate(r io.ReaderAt, size int64) error {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return structural("not a zip archive: %v", err)
	}
	parts := map[string]*zip.File{}
	for _, f := range zr.File {
		parts[f.Name] = f
	}
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml"} {
		if parts[name] == nil {
			return structural("missing %s", name)
		}
	}
	if err := checkContentTypes(parts); err != nil {
		return err
	}
	for name := range parts {
		if strings.HasSuffix(name, ".rels") {
			if err := checkRels(parts, name); err != nil {
				return err
			}
		}
	}
	styles, err := ids(parts["word/styles.xml"], "style", "styleId")
	if err != nil {
		return err
	}
	nums := map[string]bool{}
	if f := parts["word/numbering.xml"]; f != nil {
		if nums, err = ids(f, "num", "numId"); err != nil {
			return err
		}
	}
	return checkBody(parts["word/document.xml"], styles, nums)
}

func checkContentTypes(parts map[string]*zip.File) error {
	defaults, overrides := map[string]bool{}, map[string]bool{}
	err := each(parts["[Content_Types].xml"], func(el xml.StartElement) error {
		switch el.Name.Local {
		case "Default":
			defaults[strings.ToLower(attr(el, "Extension"))] = true
		case "Override":
			overrides[attr(el, "PartName")] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	for name := range parts {
		if name == "[Content_Types].xml" || strings.HasSuffix(name, "/") {
			continue
		}
		ext := strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))
		if !overrides["/"+name] && !defaults[ext] {
			return structural("%s has no content type", name)
		}
	}
	return nil
}

func checkRels(parts map[string]*zip.File, name string) error {
	dir := path.Dir(path.Dir(name))
	return each(parts[name], func(el xml.StartElement) error {
		if el.Name.Local != "Relationship" || attr(el, "TargetMode") == "External" {
			return nil
		}
		target := attr(el, "Target")
		full := path.Clean(path.Join(dir, target))
		if strings.HasPrefix(target, "/") {
			full = strings.TrimPrefix(target, "/")
		}
		if parts[full] == nil {
			return structural("%s points at missing part %s", name, full)
		}
		return nil
	})
}

func ids(f *zip.File, element, attribute string) (map[string]bool, error) {
	out := map[string]bool{}
	err := each(f, func(el xml.StartElement) error {
		if el.Name.Local == element {
			out[attr(el, attribute)] = true
		}
		return nil
	})
	return out, err
}

func checkBody(f *zip.File, styles, nums map[string]bool) error {
	depth, sawBody := 0, false
	err := each(f, func(el xml.StartElement) error {
		switch el.Name.Local {
		case "body":
			sawBody = true
		case "pStyle", "tblStyle":
			if v := attr(el, "val"); !styles[v] {
				return structural("style %q is not defined", v)
			}
		case "numId":
			if v := attr(el, "val"); !nums[v] {
				return structural("numbering %q is not defined", v)
			}
		case "fldChar":
			switch attr(el, "fldCharType") {
			case "begin":
				depth++
			case "end":
				depth--
				if depth < 0 {
					return structural("a field ends before it begins")
				}
			}
		}
		return nil
	})
	switch {
	case err != nil:
		return err
	case !sawBody:
		return structural("document has no body")
	case depth != 0:
		return structural("a field is never closed")
	}
	return nil
}

func each(f *zip.File, fn func(xml.StartElement) error) error {
	rc, err := f.Open()
	if err != nil {
		return structural("%s: %v", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	dec := xml.NewDecoder(io.LimitReader(rc, maxPartBytes))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return structural("%s does not parse: %v", f.Name, err)
		}
		if el, ok := tok.(xml.StartElement); ok {
			if err := fn(el); err != nil {
				return err
			}
		}
	}
}

func attr(el xml.StartElement, name string) string {
	for _, a := range el.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
