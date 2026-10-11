package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/asymptote"
)

func TestAsymptoteReconcileCommandIsRegisteredAndHidden(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"endpoint", "asymptote", "reconcile"})
	if err != nil || cmd == nil || cmd.Name() != "reconcile" {
		t.Fatalf("endpoint asymptote reconcile not found: %v", err)
	}
	if !cmd.Hidden {
		t.Fatal("endpoint asymptote reconcile is an internal command and must stay hidden")
	}
}

func TestAsymptoteReconcileReconcilesTheRequestedMode(t *testing.T) {
	oldOpts := endpointOpts
	oldReconcile := reconcileManagedForwarder
	t.Cleanup(func() {
		endpointOpts = oldOpts
		reconcileManagedForwarder = oldReconcile
	})
	var got asymptote.ReconcileOptions
	reconcileManagedForwarder = func(opts asymptote.ReconcileOptions) (asymptote.ReconcileResult, error) {
		got = opts
		return asymptote.ReconcileResult{VectorConfig: "/fake/vector.toml", Updated: true, Restarted: true}, nil
	}
	endpointOpts.userMode, endpointOpts.systemMode = true, false
	endpointOpts.logPath = "/tmp/scratch/runtime.jsonl"
	endpointOpts.jsonOutput = false
	out := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	if err := runAsymptoteReconcile(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if !got.UserMode || got.LogPath != "/tmp/scratch/runtime.jsonl" {
		t.Fatalf("reconcile options = %+v", got)
	}
	if !strings.Contains(out.String(), "updated and the forwarder restarted") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestReportManagedForwarderStaysQuietUnlessSomethingChanged(t *testing.T) {
	for _, result := range []*asymptote.ReconcileResult{nil, {Skipped: "not connected"}, {Unchanged: true}} {
		out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
		reportManagedForwarder(out, errOut, result)
		if out.Len() != 0 || errOut.Len() != 0 {
			t.Fatalf("result %+v printed %q / %q", result, out.String(), errOut.String())
		}
	}
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	reportManagedForwarder(out, errOut, &asymptote.ReconcileResult{Warning: "kept the existing config because Vector rejected the new one"})
	if out.Len() != 0 || !strings.Contains(errOut.String(), "Warning: Beacon Cloud forwarder: kept the existing config") {
		t.Fatalf("warning printed %q / %q", out.String(), errOut.String())
	}
	out.Reset()
	reportManagedForwarder(out, errOut, &asymptote.ReconcileResult{VectorConfig: "/v.toml", Updated: true, Restarted: true})
	if !strings.Contains(out.String(), "/v.toml") {
		t.Fatalf("update printed %q", out.String())
	}
}
