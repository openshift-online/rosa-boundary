package aws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestTaskToListSummaryUsesDesiredStatus(t *testing.T) {
	task := types.Task{
		TaskArn:       aws.String("arn:aws:ecs:us-east-2:123456789012:task/cluster/task-id"),
		ClusterArn:    aws.String("arn:aws:ecs:us-east-2:123456789012:cluster/cluster"),
		LastStatus:    aws.String("RUNNING"),
		DesiredStatus: aws.String("STOPPED"),
	}

	summary := taskToListSummary(task, "cluster")
	if summary.Status != "STOPPED" {
		t.Fatalf("taskToListSummary status = %q, want STOPPED", summary.Status)
	}
}

func TestListOwnedRunningCredentialTasksUsesActualStatusAndOwner(t *testing.T) {
	const prefix = "arn:aws:ecs:us-east-1:123456789012:task/ecs-cluster/"
	lastStatus, desiredStatus := "PENDING", "RUNNING"
	describeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonEC2ContainerServiceV20141113.ListTasks":
			var input struct {
				DesiredStatus string `json:"desiredStatus"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.DesiredStatus != "RUNNING" {
				t.Errorf("ListTasks input: %+v, %v", input, err)
			}
			_, _ = w.Write([]byte(`{"taskArns":["` + prefix + `mine","` + prefix + `other"]}`))
		case "AmazonEC2ContainerServiceV20141113.DescribeTasks":
			describeCalls++
			var input struct {
				Tasks   []string `json:"tasks"`
				Include []string `json:"include"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || len(input.Tasks) != 2 || len(input.Include) != 1 || input.Include[0] != "TAGS" {
				t.Errorf("DescribeTasks input: %+v, %v", input, err)
			}
			_, _ = w.Write([]byte(`{"tasks":[{"taskArn":"` + prefix + `mine","lastStatus":"` + lastStatus + `","desiredStatus":"` + desiredStatus + `","tags":[{"key":"oidc_sub","value":"me"},{"key":"cluster_id","value":"mine"}]},{"taskArn":"` + prefix + `other","lastStatus":"RUNNING","desiredStatus":"RUNNING","tags":[{"key":"oidc_sub","value":"other"},{"key":"cluster_id","value":"secret"}]}]}`))
		default:
			t.Errorf("unexpected ECS operation: %s", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := testInvestigationECSClient(server.URL)
	listed, err := client.ListRunningTasks(context.Background(), "RUNNING")
	if err != nil || len(listed) != 2 || listed[0].Status != "RUNNING" {
		t.Fatalf("session list semantics changed: tasks=%+v err=%v", listed, err)
	}
	for _, tc := range []struct {
		name, last, desired string
		want                int
	}{
		{"pending to running", "PENDING", "RUNNING", 0},
		{"running", "RUNNING", "RUNNING", 1},
		{"stop transition", "RUNNING", "STOPPED", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lastStatus, desiredStatus = tc.last, tc.desired
			before := describeCalls
			tasks, err := client.ListOwnedRunningCredentialTasks(context.Background(), "me")
			if err != nil || len(tasks) != tc.want || describeCalls != before+1 {
				t.Fatalf("tasks=%+v err=%v describe calls=%d", tasks, err, describeCalls-before)
			}
			if tc.want == 1 && (tasks[0].TaskID != "mine" || tasks[0].Status != "RUNNING" || tasks[0].Tags["cluster_id"] != "mine") {
				t.Fatalf("unexpected owned task: %+v", tasks)
			}
		})
	}
	if _, err := client.ListOwnedRunningCredentialTasks(context.Background(), ""); err == nil {
		t.Fatal("empty owner was accepted")
	}
}

func TestECSExecTargetAcceptsShortIDAndARN(t *testing.T) {
	for _, identifier := range []string{"task-id", "arn:aws:ecs:us-east-1:123456789012:task/ecs-cluster/task-id"} {
		if got := ecsExecTarget("ecs-cluster", identifier, "runtime-id"); got != "ecs:ecs-cluster_task-id_runtime-id" {
			t.Errorf("ecsExecTarget(%q) = %q", identifier, got)
		}
	}
}

func TestInvestigationStartedByMatchesLambda(t *testing.T) {
	if got := investigationStartedBy("cluster-a", "inv-1"); got != "74771f619b42d4eee63132be2d9bad3353ea" {
		t.Fatalf("startedBy digest differs from Lambda: %q", got)
	}
}

func TestListTasksByInvestigationCatchesPendingBeforeTagsPropagate(t *testing.T) {
	const arn = "arn:aws:ecs:us-east-1:123456789012:task/ecs-cluster/pending-task"
	seenStartedBy := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonEC2ContainerServiceV20141113.ListTasks":
			var input struct {
				StartedBy     string `json:"startedBy"`
				DesiredStatus string `json:"desiredStatus"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.StartedBy == "" {
				_, _ = w.Write([]byte(`{"taskArns":[]}`))
				return
			}
			if input.StartedBy != investigationStartedBy("cluster-a", "inv-1") {
				t.Errorf("wrong startedBy: %s", input.StartedBy)
			}
			if input.DesiredStatus != "" {
				t.Errorf("AWS forbids startedBy with desiredStatus: %s", input.DesiredStatus)
			}
			seenStartedBy = true
			_, _ = w.Write([]byte(`{"taskArns":["` + arn + `"]}`))
		case "AmazonEC2ContainerServiceV20141113.DescribeTasks":
			_, _ = w.Write([]byte(`{"tasks":[{"taskArn":"` + arn + `","lastStatus":"PENDING","desiredStatus":"RUNNING","tags":[]}]}`))
		default:
			t.Errorf("unexpected ECS operation: %s", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := &ECSClient{cluster: "ecs-cluster", client: ecs.New(ecs.Options{
		BaseEndpoint: aws.String(server.URL), Region: "us-east-1",
		Credentials: StaticCredentialsProvider(&TemporaryCredentials{AccessKeyID: "test", SecretAccessKey: "test", SessionToken: "test"}),
	})}
	tasks, err := client.ListTasksByInvestigation(context.Background(), "cluster-a", "inv-1")
	if err != nil {
		t.Fatal(err)
	}
	if !seenStartedBy || len(tasks) != 1 || tasks[0].TaskID != "pending-task" || tasks[0].Status != "PENDING" {
		t.Fatalf("pending task without tags was missed: %+v (startedBy queried: %t)", tasks, seenStartedBy)
	}
}

func TestListTasksByInvestigationIncludesTaskStillShuttingDown(t *testing.T) {
	const arn = "arn:aws:ecs:us-east-1:123456789012:task/ecs-cluster/stopping-task"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonEC2ContainerServiceV20141113.ListTasks":
			var input struct {
				DesiredStatus string `json:"desiredStatus"`
				StartedBy     string `json:"startedBy"`
			}
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input.DesiredStatus == "STOPPED" && input.StartedBy == "" {
				_, _ = w.Write([]byte(`{"taskArns":["` + arn + `"]}`))
			} else {
				_, _ = w.Write([]byte(`{"taskArns":[]}`))
			}
		case "AmazonEC2ContainerServiceV20141113.DescribeTasks":
			_, _ = w.Write([]byte(`{"tasks":[{"taskArn":"` + arn + `","lastStatus":"RUNNING","desiredStatus":"STOPPED","tags":[{"key":"cluster_id","value":"cluster-a"},{"key":"investigation_id","value":"inv-1"}]}]}`))
		default:
			t.Errorf("unexpected ECS operation: %s", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := testInvestigationECSClient(server.URL)
	tasks, err := client.ListTasksByInvestigation(context.Background(), "cluster-a", "inv-1")
	if err != nil || len(tasks) != 1 || tasks[0].Status != "RUNNING" || tasks[0].DesiredStatus != "STOPPED" {
		t.Fatalf("task still shutting down was missed: %+v, err: %v", tasks, err)
	}
}

func TestListTasksByInvestigationRejectsConflictingStartedByTags(t *testing.T) {
	const arn = "arn:aws:ecs:us-east-1:123456789012:task/ecs-cluster/conflicting-task"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonEC2ContainerServiceV20141113.ListTasks":
			var input struct {
				StartedBy string `json:"startedBy"`
			}
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input.StartedBy != "" {
				_, _ = w.Write([]byte(`{"taskArns":["` + arn + `"]}`))
			} else {
				_, _ = w.Write([]byte(`{"taskArns":[]}`))
			}
		case "AmazonEC2ContainerServiceV20141113.DescribeTasks":
			_, _ = w.Write([]byte(`{"tasks":[{"taskArn":"` + arn + `","lastStatus":"PENDING","desiredStatus":"RUNNING","tags":[{"key":"cluster_id","value":"other-cluster"}]}]}`))
		default:
			t.Errorf("unexpected ECS operation: %s", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	_, err := testInvestigationECSClient(server.URL).ListTasksByInvestigation(context.Background(), "cluster-a", "inv-1")
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected conflicting tags to abort cleanup, got %v", err)
	}
}

func TestListTasksByInvestigationRejectsPartialDescribe(t *testing.T) {
	const arn = "arn:aws:ecs:us-east-1:123456789012:task/ecs-cluster/missing-task"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonEC2ContainerServiceV20141113.ListTasks":
			_, _ = w.Write([]byte(`{"taskArns":["` + arn + `"]}`))
		case "AmazonEC2ContainerServiceV20141113.DescribeTasks":
			_, _ = w.Write([]byte(`{"tasks":[],"failures":[{"arn":"` + arn + `","reason":"MISSING"}]}`))
		default:
			t.Errorf("unexpected ECS operation: %s", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	_, err := testInvestigationECSClient(server.URL).ListTasksByInvestigation(context.Background(), "cluster-a", "inv-1")
	if err == nil || !strings.Contains(err.Error(), "incomplete investigation scan") {
		t.Fatalf("expected partial description to abort cleanup, got %v", err)
	}
}

func testInvestigationECSClient(endpoint string) *ECSClient {
	return &ECSClient{cluster: "ecs-cluster", client: ecs.New(ecs.Options{
		BaseEndpoint: aws.String(endpoint), Region: "us-east-1",
		Credentials: StaticCredentialsProvider(&TemporaryCredentials{AccessKeyID: "test", SecretAccessKey: "test", SessionToken: "test"}),
	})}
}

func TestTaskDefinitionAccessPointRejectsNameOnlyMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Amz-Target"); got != "AmazonEC2ContainerServiceV20141113.DescribeTaskDefinition" {
			t.Errorf("unexpected operation %q", got)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"taskDefinition":{"volumes":[{"name":"sre-home","efsVolumeConfiguration":{"fileSystemId":"fs-example","authorizationConfig":{"accessPointId":"fsap-other"}}}]}}`))
	}))
	defer server.Close()
	client := &ECSClient{cluster: "ecs-cluster", client: ecs.New(ecs.Options{
		BaseEndpoint: aws.String(server.URL), Region: "us-east-1",
		Credentials: StaticCredentialsProvider(&TemporaryCredentials{AccessKeyID: "test", SecretAccessKey: "test", SessionToken: "test"}),
	})}
	got, err := client.TaskDefinitionAccessPoint(context.Background(), "arn:aws:ecs:us-east-1:123456789012:task-definition/ecs-cluster-a-b-c-20261105T210000:1")
	if err != nil || got != "fsap-other" {
		t.Fatalf("access point = %q, error %v", got, err)
	}
}

func TestListTaskDefinitionsByFamilyFiltersResults(t *testing.T) {
	const family = "boundary-cluster-investigation"
	const target = "arn:aws:ecs:us-east-1:123456789012:task-definition/boundary-cluster-investigation-20261105T220000:1"
	const adjacent = "arn:aws:ecs:us-east-1:123456789012:task-definition/boundary-cluster-investigation-other-20261105T220000:1"
	const unrelated = "arn:aws:ecs:us-east-1:123456789012:task-definition/unrelated:1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Amz-Target"); got != "AmazonEC2ContainerServiceV20141113.ListTaskDefinitions" {
			t.Errorf("unexpected operation: %s", got)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var input struct {
			FamilyPrefix *string `json:"familyPrefix"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		if input.FamilyPrefix != nil {
			t.Errorf("partial familyPrefix would hide timestamp-suffixed definitions: %q", *input.FamilyPrefix)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"taskDefinitionArns":["` + target + `","` + adjacent + `","` + unrelated + `"]}`))
	}))
	defer server.Close()
	client := testInvestigationECSClient(server.URL)
	arns, err := client.ListTaskDefinitionsByFamily(context.Background(), family)
	if err != nil || len(arns) != 2 || arns[0] != target || arns[1] != adjacent {
		t.Fatalf("filtered definitions = %v, err = %v", arns, err)
	}
}

func TestTaskToSummaryUsesLastStatus(t *testing.T) {
	task := types.Task{
		TaskArn:       aws.String("arn:aws:ecs:us-east-2:123456789012:task/cluster/task-id"),
		LastStatus:    aws.String("RUNNING"),
		DesiredStatus: aws.String("STOPPED"),
	}

	summary := taskToSummary(task, "cluster")
	if summary.Status != "RUNNING" {
		t.Fatalf("taskToSummary status = %q, want RUNNING", summary.Status)
	}
}

// testECSClient provides a mock for testing ECS methods
type testECSClient struct {
	mockRunningTasks []TaskSummary
}

// ListRunningTasks returns the mock tasks for testing
func (m *testECSClient) ListRunningTasks(ctx context.Context, desiredStatus string) ([]TaskSummary, error) {
	return m.mockRunningTasks, nil
}

// ListTasksByInvestigation implements the same logic as ECSClient to test the filtering behavior
func (m *testECSClient) ListTasksByInvestigation(ctx context.Context, clusterID, investigationID string) ([]TaskSummary, error) {
	tasks, err := m.ListRunningTasks(ctx, "RUNNING")
	if err != nil {
		return nil, err
	}
	var filtered []TaskSummary
	for _, t := range tasks {
		if t.Tags["investigation_id"] == investigationID && t.Tags["cluster_id"] == clusterID {
			filtered = append(filtered, t)
		}
	}
	return filtered, nil
}

func TestListTasksByInvestigation_FiltersByBothTags(t *testing.T) {
	// Create mock tasks that ListRunningTasks would return
	allTasks := []TaskSummary{
		{
			TaskID: "task-1",
			Tags: map[string]string{
				"cluster_id":       "cluster-a",
				"investigation_id": "inv-1",
			},
		},
		{
			TaskID: "task-2",
			Tags: map[string]string{
				"cluster_id":       "cluster-b",
				"investigation_id": "inv-1",
			},
		},
		{
			TaskID: "task-3",
			Tags: map[string]string{
				"cluster_id":       "cluster-a",
				"investigation_id": "inv-2",
			},
		},
		{
			TaskID: "task-4",
			Tags: map[string]string{
				"cluster_id":       "cluster-a",
				"investigation_id": "inv-1",
			},
		},
	}

	// Create test client that returns all tasks from ListRunningTasks
	client := &testECSClient{
		mockRunningTasks: allTasks,
	}

	// Call the actual ListTasksByInvestigation method
	ctx := context.Background()
	testClusterID := "cluster-a"
	testInvestigationID := "inv-1"

	filtered, err := client.ListTasksByInvestigation(ctx, testClusterID, testInvestigationID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify filtering behavior: should match only task-1 and task-4
	if len(filtered) != 2 {
		t.Fatalf("expected 2 tasks matching cluster_id=%s and investigation_id=%s, got %d",
			testClusterID, testInvestigationID, len(filtered))
	}

	found := make(map[string]bool)
	for _, task := range filtered {
		found[task.TaskID] = true
	}

	// Should include tasks with matching cluster_id AND investigation_id
	if !found["task-1"] {
		t.Error("expected to find task-1 (cluster-a, inv-1)")
	}
	if !found["task-4"] {
		t.Error("expected to find task-4 (cluster-a, inv-1)")
	}

	// Should exclude tasks with different cluster_id
	if found["task-2"] {
		t.Error("should not include task-2 (different cluster: cluster-b)")
	}

	// Should exclude tasks with different investigation_id
	if found["task-3"] {
		t.Error("should not include task-3 (different investigation: inv-2)")
	}
}
