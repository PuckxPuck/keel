package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A significant change past the threshold in any unit fails; noise (~), improvements and geomeans do not.
func TestRegressions(t *testing.T) {
	table := []byte(`goos: linux
pkg: example.com/app/internal/kit/paging
,baseline,,current,,,
,sec/op,CI,sec/op,CI,vs base,P
KeysetCursor-8,8.0e-06,1%,9.6e-06,1%,+20.00%,p=0.002 n=6
Trim-8,4.0e-06,1%,4.2e-06,1%,~,p=0.400 n=6
geomean,5.6e-06,,6.3e-06,,+12.00%,

,baseline,,current,,,
,allocs/op,CI,allocs/op,CI,vs base,P
KeysetCursor-8,71,0%,60,0%,-15.49%,p=0.002 n=6
Trim-8,10,0%,11,0%,+10.00%,p=0.002 n=6

,baseline,,current,,,
,B/s,CI,B/s,CI,vs base,P
Encode-8,5.0e+08,1%,3.5e+08,1%,-30.00%,p=0.002 n=6
Decode-8,5.0e+08,1%,6.5e+08,1%,+30.00%,p=0.002 n=6
`)
	found, err := regressions(table, 10)

	require.NoError(t, err)
	assert.Equal(t, []string{
		"example.com/app/internal/kit/paging KeysetCursor-8 sec/op: +20.00%",
		"example.com/app/internal/kit/paging Encode-8 B/s: -30.00%",
	}, found)
}

// Results are comparable only when they come from the same OS, architecture and CPU.
func TestMachineClass_TellsRunnersApart(t *testing.T) {
	run := func(cpu string) []byte {
		return []byte("goos: linux\ngoarch: amd64\npkg: example.com/app/x\ncpu: " + cpu + "\nBenchmarkX-8 1 1 ns/op\n")
	}

	assert.Equal(t, "linux amd64 AMD EPYC 7763", machineClass(run("AMD EPYC 7763")))
	assert.NotEqual(t, machineClass(run("AMD EPYC 7763")), machineClass(run("Intel Xeon 8370C")))
}
