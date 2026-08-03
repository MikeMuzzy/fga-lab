package authzgen

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/format"
	"text/template"
)

//go:embed catalog.go.tmpl
var catalogTemplate string

var tmpl = template.Must(template.New("catalog").Parse(catalogTemplate))

// Render executes the template and formats the result.
//
// format.Source does not prune unused imports, so the import set in the IR must
// already be exact; a formatting failure here is almost always a template bug
// and the unformatted source is included to make it debuggable.
func Render(f *File) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, f); err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	src, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("gofmt generated source: %w\n%s", err, buf.String())
	}
	return src, nil
}

// Generate is the whole pipeline: parse, validate, render.
func Generate(filename string, src []byte, opts Options) ([]byte, error) {
	f, err := Load(filename, src, opts)
	if err != nil {
		return nil, err
	}
	return Render(f)
}
