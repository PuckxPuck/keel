package cli_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/cli"
)

func TestPrint_Text(t *testing.T) {
	table := cli.Table{
		Columns: []string{"name", "status"},
		Rows:    [][]string{{"alpha", "ok"}, {"b", "failing"}, {"short"}},
	}

	var buf bytes.Buffer
	require.NoError(t, cli.Print(&buf, false, table))

	want := "name   status\n" +
		"alpha  ok\n" +
		"b      failing\n" +
		"short  \n"
	assert.Equal(t, want, buf.String())
}

func TestPrint_JSON(t *testing.T) {
	table := cli.Table{
		Columns: []string{"name", "note"},
		Rows:    [][]string{{"alpha", `has "quotes"`}, {"beta"}},
	}

	var buf bytes.Buffer
	require.NoError(t, cli.Print(&buf, true, table))

	var got []map[string]string
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, []map[string]string{
		{"name": "alpha", "note": `has "quotes"`},
		{"name": "beta", "note": ""},
	}, got)
	assert.Contains(t, buf.String(), `{"name": "alpha", "note"`, "keys keep column order")
}

func TestPrint_EmptyRowsIsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, cli.Print(&buf, true, cli.Table{Columns: []string{"a"}}))

	assert.JSONEq(t, "[]", buf.String())
}

func TestPrint_RejectsRowWiderThanColumns(t *testing.T) {
	err := cli.Print(&bytes.Buffer{}, false, cli.Table{Columns: []string{"a"}, Rows: [][]string{{"1", "2"}}})

	require.Error(t, err)
}
