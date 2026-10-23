package main

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTestSteps_PassesPkgAndRun(t *testing.T) {
	got := testSteps("./internal/kit/money", "TestAllocate")

	assert.Equal(t, []string{"test", "-race", "-run", "TestAllocate", "./internal/kit/money"}, got[0].args)
	assert.Equal(t, []string{"test", "-race", "./..."}, testSteps("./...", "")[0].args)
}

func TestCgoIsEnabledExactlyForRaceSteps(t *testing.T) {
	for _, s := range checkSteps() {
		assert.Equal(t, slices.Contains(s.args, "-race"), s.race, s.name)
	}
}
