package cmd

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

const testSeal = "fe156137-c122-45cd-9fe7-adb2d2240c0a"
const receipt = `{"schema_version":1,"cluster_id":"cluster","investigation_id":"inv","access_point_id":"fsap-1","seal":"` + testSeal + `","status":"verified","manifest_ref":"operator-manifest"}`

func sealedPlan() closePlan {
	return closePlan{ClusterID: "cluster", InvestigationID: "inv", AccessPointID: "fsap-1", Seal: testSeal, VerifiedSeal: testSeal, Bucket: "regional-audit", VisibleStopped: []string{"task-old"}, TaskDefinitions: []string{"def"}}
}

func TestCloseReceiptValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body        string
		unreadable, valid bool
	}{
		{"verified", receipt, false, true},
		{"denied", receipt, true, false},
		{"absent", "", false, false},
		{"wrong version", strings.Replace(receipt, ":1,", ":2,", 1), false, false},
		{"wrong cluster", strings.Replace(receipt, `"cluster"`, `"other"`, 1), false, false},
		{"wrong investigation", strings.Replace(receipt, `"inv"`, `"other"`, 1), false, false},
		{"wrong access point", strings.Replace(receipt, "fsap-1", "fsap-2", 1), false, false},
		{"old seal", strings.Replace(receipt, testSeal, "other", 1), false, false},
		{"transfer report", strings.Replace(receipt, "verified", "uploaded", 1), false, false},
		{"no manifest", strings.Replace(receipt, "operator-manifest", "  ", 1), false, false},
		{"trailing data", receipt + "{}", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := sealedPlan()
			p.checkReceipt(context.Background(), func(_ context.Context, b, ap, s string) ([]byte, error) {
				if b != p.Bucket || ap != p.AccessPointID || s != testSeal {
					t.Fatal("wrong receipt lookup")
				}
				if tc.unreadable {
					return nil, errors.New("denied")
				}
				return []byte(tc.body), nil
			})
			if (p.ReceiptDigest != "") != tc.valid || (p.FinalizationBlocked == "") != tc.valid {
				t.Fatalf("incorrect receipt decision: %+v", p)
			}
		})
	}
	for _, change := range []func(*closePlan){
		func(p *closePlan) { p.VerifiedSeal = "other" },
		func(p *closePlan) { p.Seal = "" },
		func(p *closePlan) { p.Seal = "../other"; p.VerifiedSeal = p.Seal },
		func(p *closePlan) { p.Bucket = "" },
		func(p *closePlan) { p.SessionsWaiting = []string{"writer"} },
	} {
		p := sealedPlan()
		change(&p)
		p.checkReceipt(context.Background(), nil)
		if p.FinalizationBlocked == "" || p.ReceiptDigest != "" {
			t.Fatal("allowed invalid operator state")
		}
	}
}

type closeCalls []string

func (c *closeCalls) StopTask(_ context.Context, id, _ string) error {
	*c = append(*c, "stop:"+id)
	return nil
}
func (c *closeCalls) WaitForStopped(_ context.Context, id string) error {
	*c = append(*c, "wait:"+id)
	return nil
}
func (c *closeCalls) DeregisterTaskDefinition(_ context.Context, id string) error {
	*c = append(*c, "deregister:"+id)
	return nil
}

func TestCloseGatedMutations(t *testing.T) {
	oldYes, oldForce, oldDry, oldFormat := closeYes, closeForce, closeDryRun, closeOutputFormat
	t.Cleanup(func() { closeYes, closeForce, closeDryRun, closeOutputFormat = oldYes, oldForce, oldDry, oldFormat })
	closeYes = true
	closeOutputFormat = "text"
	for _, tc := range []struct {
		name                                                string
		dry, active, valid, revoke, changedReceipt, unknown bool
		want                                                []string
		errText                                             string
	}{
		{name: "dry run", dry: true, active: true},
		{name: "unverified stopped", errText: "task-old"},
		{name: "empty ECS is not proof", unknown: true, errText: "older IDs may be unknown"},
		{name: "forced stop cannot finalize", active: true, want: []string{"stop:writer", "wait:writer"}, errText: "writer"},
		{name: "verified", valid: true, want: []string{"deregister:def", "delete:fsap-1"}},
		{name: "receipt replaced under same seal", valid: true, changedReceipt: true, want: []string{"deregister:def"}, errText: "retaining access point"},
		{name: "receipt revoked before deletion", valid: true, revoke: true, want: []string{"deregister:def"}, errText: "retaining access point"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closeForce, closeDryRun = tc.active, tc.dry
			var calls closeCalls
			resolve := func() (closePlan, error) {
				p := sealedPlan()
				if tc.unknown {
					p.VisibleStopped = nil
				}
				if tc.active {
					p.SessionIDs = []string{"writer"}
				}
				if len(calls) > 0 && calls[len(calls)-1] == "deregister:def" {
					p.TaskDefinitions = nil
					if tc.revoke {
						p.VerifiedSeal = ""
					}
				}
				p.checkReceipt(context.Background(), func(context.Context, string, string, string) ([]byte, error) {
					if tc.valid {
						if tc.changedReceipt && len(calls) > 0 {
							return []byte(receipt + "\n"), nil
						}
						return []byte(receipt), nil
					}
					return nil, errors.New("no trusted evidence")
				})
				return p, nil
			}
			err := closeInvestigation(context.Background(), resolve, &calls, func(_ context.Context, id string) error { calls = append(calls, "delete:"+id); return nil })
			if (tc.errText == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.errText)) {
				t.Fatalf("err=%v; want %q", err, tc.errText)
			}
			if !slices.Equal([]string(calls), tc.want) {
				t.Fatalf("calls=%v want %v", calls, tc.want)
			}
		})
	}
}
