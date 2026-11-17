package dnssectest

import "testing"

// fakeT records Fatalf instead of ending the test, to test the failure paths of helpers.
type fakeT struct {
	*testing.T
	failed bool
}

func (f *fakeT) Fatalf(string, ...any) { f.failed = true; panic("fatal") }
func (f *fakeT) Helper()               {}
