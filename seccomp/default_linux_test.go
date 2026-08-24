// SPDX-FileCopyrightText: Copyright The Moby Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func socketTestSyscall(args ...specs.LinuxSeccompArg) *Syscall {
	return &Syscall{
		LinuxSyscall: specs.LinuxSyscall{
			Names:  []string{"socket"},
			Action: specs.ActAllow,
			Args:   args,
		},
	}
}

func TestSocketSyscallsCurrentDomains(t *testing.T) {
	want := []*Syscall{
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 38, Op: specs.OpLessThan}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 39, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 41, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 42, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 43, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 44, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 45, Op: specs.OpEqualTo}),
	}

	assertDeepEqual(t, want, socketSyscalls())
}

func TestSocketSyscallsForDomainsFallsBackToEquality(t *testing.T) {
	tests := []struct {
		name    string
		domains []uint64
		want    []*Syscall
	}{
		{
			name:    "singleton",
			domains: []uint64{39},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 39, Op: specs.OpEqualTo}),
			},
		},
		{
			name:    "later consecutive run",
			domains: []uint64{1, 2, 4, 5},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 3, Op: specs.OpLessThan}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 4, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 5, Op: specs.OpEqualTo}),
			},
		},
		{
			name:    "two-domain initial range",
			domains: []uint64{1, 2},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 3, Op: specs.OpLessThan}),
			},
		},
		{
			name:    "gap after initial domain",
			domains: []uint64{1, 3, 4},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 1, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 3, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 4, Op: specs.OpEqualTo}),
			},
		},
		{
			name:    "range not at initial domain",
			domains: []uint64{10, 11, 12},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 10, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 11, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 12, Op: specs.OpEqualTo}),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertDeepEqual(t, test.want, socketSyscallsForDomains(test.domains))
		})
	}
}

func TestSocketSyscallsHaveUniqueArgumentIndices(t *testing.T) {
	for _, syscall := range socketSyscalls() {
		seen := make(map[uint]struct{}, len(syscall.Args))
		for _, arg := range syscall.Args {
			if _, ok := seen[arg.Index]; ok {
				t.Errorf("socket syscall has repeated argument index %d", arg.Index)
			}
			seen[arg.Index] = struct{}{}
		}
	}
}
