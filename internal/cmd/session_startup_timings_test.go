package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

func TestSessionStartupTimings(t *testing.T) {
	created := time.Unix(1700000000, 0).UTC()
	pullStart := created.Add(5 * time.Second)
	pullStop := pullStart.Add(12 * time.Second)
	started := pullStop.Add(time.Second)
	timings := sessionStartupTimings{LambdaRoundTripMS: 3000}
	timings.recordRunning(24000, &awsclient.TaskStartup{
		CreatedAt: &created, PullStartedAt: &pullStart, PullStoppedAt: &pullStop, StartedAt: &started,
	})
	for _, check := range []struct {
		name string
		got  *int64
		want int64
	}{
		{"observed RUNNING", timings.InvokeToRunningMS, 24000},
		{"before pull", timings.ECSCreatedToPullMS, 5000},
		{"pull", timings.ECSImagePullMS, 12000},
		{"after pull", timings.ECSAfterImagePullMS, 1000},
	} {
		if check.got == nil || *check.got != check.want {
			t.Errorf("%s: got %v, want %d ms", check.name, check.got, check.want)
		}
	}
}

func TestSessionStartupPrintRequiresVerbose(t *testing.T) {
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	previousStderr, previousVerbose := os.Stderr, output.Verbose
	t.Cleanup(func() {
		os.Stderr, output.Verbose = previousStderr, previousVerbose
		_ = stderr.Close()
	})
	os.Stderr = stderr
	timings := sessionStartupTimings{LambdaRoundTripMS: 42}
	output.Verbose = false
	timings.print()
	output.Verbose = true
	timings.print()
	got, err := os.ReadFile(stderr.Name())
	if err != nil || strings.TrimSpace(string(got)) != "[debug] Startup timing: Lambda round trip 42 ms" {
		t.Fatalf("stderr = %q, err = %v; want only the verbose timing line", got, err)
	}
}

func TestSessionStartupOmissionAndZero(t *testing.T) {
	created := time.Unix(1700000000, 0).UTC()
	invalidStart := created.Add(-time.Second)
	timings := sessionStartupTimings{}
	timings.recordRunning(123, &awsclient.TaskStartup{PullStartedAt: &created, PullStoppedAt: &created, StartedAt: &invalidStart})
	got, err := json.Marshal(timings)
	want := `{"lambda_round_trip_ms":0,"invoke_to_running_ms":123,"ecs":{"pull_started_at":"2023-11-14T22:13:20Z","pull_stopped_at":"2023-11-14T22:13:20Z","started_at":"2023-11-14T22:13:19Z"},"ecs_image_pull_ms":0}`
	if err != nil || string(got) != want {
		t.Fatalf("timings = %s, err = %v; want %s", got, err, want)
	}
}
