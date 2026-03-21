//go:build integration

package modelsecurity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec/internal/testutil"
)

func newIntegrationClient(t *testing.T) *Client {
	t.Helper()
	testutil.LoadProjectEnv(t)
	testutil.RequireEnv(t, "PANW_MGMT_CLIENT_ID", "PANW_MGMT_CLIENT_SECRET", "PANW_MGMT_TSG_ID")

	client, err := NewClient(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestIntegration_SecurityGroups_CRUD(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	groupName := fmt.Sprintf("test-group-%d", time.Now().UnixNano())

	// 1. Create group
	created, err := client.SecurityGroups.Create(ctx, ModelSecurityGroupCreateRequest{
		Name:       groupName,
		SourceType: SourceTypeLocal,
	})
	if err != nil {
		t.Fatalf("Create security group: %v", err)
	}
	t.Logf("Created security group: uuid=%s name=%s", created.UUID, created.Name)

	// Register cleanup to delete even on failure
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		if delErr := client.SecurityGroups.Delete(cleanCtx, created.UUID); delErr != nil {
			t.Logf("WARNING: cleanup delete security group %s failed: %v", created.UUID, delErr)
		} else {
			t.Logf("Cleanup: deleted security group %s", created.UUID)
		}
	})

	if created.UUID == "" {
		t.Fatal("Created group has empty UUID")
	}
	if created.Name != groupName {
		t.Errorf("Name mismatch: got %q want %q", created.Name, groupName)
	}

	// 2. List groups, verify new group appears
	listResp, err := client.SecurityGroups.List(ctx, GroupListOpts{Limit: 50})
	if err != nil {
		t.Fatalf("List security groups: %v", err)
	}
	t.Logf("Listed %d security groups", len(listResp.Items))

	found := false
	for _, g := range listResp.Items {
		if g.UUID == created.UUID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created group not found in list")
	}

	// 3. Get group by UUID
	got, err := client.SecurityGroups.Get(ctx, created.UUID)
	if err != nil {
		t.Fatalf("Get security group: %v", err)
	}
	t.Logf("Got security group: uuid=%s name=%s state=%s", got.UUID, got.Name, got.State)

	if got.Name != groupName {
		t.Errorf("Get name mismatch: got %q want %q", got.Name, groupName)
	}

	// 4. Update group description
	updatedDesc := "test-updated-description"
	updated, err := client.SecurityGroups.Update(ctx, created.UUID, ModelSecurityGroupUpdateRequest{
		Description: updatedDesc,
	})
	if err != nil {
		t.Fatalf("Update security group: %v", err)
	}
	t.Logf("Updated security group: uuid=%s description=%q", updated.UUID, updated.Description)

	if updated.Description != updatedDesc {
		t.Errorf("Description mismatch: got %q want %q", updated.Description, updatedDesc)
	}

	// 5. List rule instances for the group
	riResp, err := client.SecurityGroups.ListRuleInstances(ctx, created.UUID, RuleInstanceListOpts{Limit: 10})
	if err != nil {
		t.Fatalf("List rule instances: %v", err)
	}
	t.Logf("Rule instances for group: %d items", len(riResp.Items))

	// If rule instances exist, get the first one
	if len(riResp.Items) > 0 {
		ri := riResp.Items[0]
		t.Logf("First rule instance: uuid=%s state=%s", ri.UUID, ri.State)

		gotRI, err := client.SecurityGroups.GetRuleInstance(ctx, created.UUID, ri.UUID)
		if err != nil {
			t.Logf("WARNING: Get rule instance %s: %v", ri.UUID, err)
		} else {
			t.Logf("Got rule instance: uuid=%s state=%s", gotRI.UUID, gotRI.State)
		}
	}

	// 6. Delete is handled by t.Cleanup above
	t.Log("SecurityGroups CRUD complete (delete via cleanup)")
}

func TestIntegration_SecurityRules_Read(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List rules
	resp, err := client.SecurityRules.List(ctx, RuleListOpts{Limit: 10})
	if err != nil {
		t.Fatalf("List security rules: %v", err)
	}
	t.Logf("SecurityRules: %d items", len(resp.Items))

	for i, r := range resp.Items {
		t.Logf("  Rule[%d]: uuid=%s name=%q type=%s defaultState=%s", i, r.UUID, r.Name, r.RuleType, r.DefaultState)
	}

	// Get first rule by UUID if available
	if len(resp.Items) > 0 {
		first := resp.Items[0]
		got, err := client.SecurityRules.Get(ctx, first.UUID)
		if err != nil {
			t.Fatalf("Get security rule %s: %v", first.UUID, err)
		}
		t.Logf("Got rule: uuid=%s name=%q description=%q", got.UUID, got.Name, got.Description)
		t.Logf("  CompatibleSources: %v", got.CompatibleSources)
		t.Logf("  EditableFields: %d", len(got.EditableFields))
	}
}

func TestIntegration_Scans_Read(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// List scans (read-only)
	resp, err := client.Scans.List(ctx, ScanListOpts{Limit: 5})
	if err != nil {
		t.Fatalf("List scans: %v", err)
	}
	t.Logf("ModelSecurity Scans: %d items", len(resp.Items))

	if len(resp.Items) == 0 {
		t.Log("No scans found, skipping detail tests")
		return
	}

	// Get first scan details
	first := resp.Items[0]
	t.Logf("First scan: uuid=%s modelURI=%s outcome=%s", first.UUID, first.ModelURI, first.EvalOutcome)

	scan, err := client.Scans.Get(ctx, first.UUID)
	if err != nil {
		t.Fatalf("Get scan %s: %v", first.UUID, err)
	}
	t.Logf("Scan detail: uuid=%s sourceType=%s scannerVersion=%s", scan.UUID, scan.SourceType, scan.ScannerVersion)

	// Get evaluations
	evals, err := client.Scans.GetEvaluations(ctx, first.UUID, EvaluationListOpts{Limit: 5})
	if err != nil {
		t.Logf("WARNING: GetEvaluations for scan %s: %v", first.UUID, err)
	} else {
		t.Logf("Evaluations: %d items", len(evals.Items))
		for i, e := range evals.Items {
			t.Logf("  Eval[%d]: uuid=%s result=%s ruleName=%q", i, e.UUID, e.Result, e.RuleName)
		}
	}

	// Get violations
	violations, err := client.Scans.GetViolations(ctx, first.UUID, ViolationListOpts{Limit: 5})
	if err != nil {
		t.Logf("WARNING: GetViolations for scan %s: %v", first.UUID, err)
	} else {
		t.Logf("Violations: %d items", len(violations.Items))
		for i, v := range violations.Items {
			t.Logf("  Violation[%d]: uuid=%s description=%q", i, v.UUID, v.Description)
		}
	}

	// Get files
	files, err := client.Scans.GetFiles(ctx, first.UUID, FileListOpts{Limit: 5})
	if err != nil {
		t.Logf("WARNING: GetFiles for scan %s: %v", first.UUID, err)
	} else {
		t.Logf("Files: %d items", len(files.Items))
		for i, f := range files.Items {
			t.Logf("  File[%d]: uuid=%s path=%s result=%s", i, f.UUID, f.Path, f.Result)
		}
	}
}

func TestIntegration_PyPIAuth(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.GetPyPIAuth(ctx)
	if err != nil {
		t.Fatalf("GetPyPIAuth: %v", err)
	}
	t.Logf("PyPI auth URL: %s", resp.URL)
	t.Logf("PyPI auth ExpiresAt: %s", resp.ExpiresAt)

	if resp.URL == "" {
		t.Error("PyPI auth URL is empty")
	}
}

func TestIntegration_Labels_CRUD(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Get a scan UUID to work with
	scans, err := client.Scans.List(ctx, ScanListOpts{Limit: 1})
	if err != nil {
		t.Fatalf("List scans: %v", err)
	}
	if len(scans.Items) == 0 {
		t.Skip("No scans available, skipping labels CRUD test")
	}

	scanUUID := scans.Items[0].UUID
	t.Logf("Using scan %s for labels CRUD", scanUUID)

	testKey := fmt.Sprintf("test-key-%d", time.Now().UnixNano())
	testValue := "test-value"

	// Cleanup: delete our test labels at end
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		if delErr := client.Scans.DeleteLabels(cleanCtx, scanUUID, []string{testKey}); delErr != nil {
			t.Logf("WARNING: cleanup delete labels for scan %s key %s: %v", scanUUID, testKey, delErr)
		} else {
			t.Logf("Cleanup: deleted labels key=%s from scan %s", testKey, scanUUID)
		}
	})

	// 1. Add labels
	addResp, err := client.Scans.AddLabels(ctx, scanUUID, LabelsCreateRequest{
		Labels: []Label{{Key: testKey, Value: testValue}},
	})
	if err != nil {
		t.Fatalf("AddLabels: %v", err)
	}
	t.Logf("AddLabels response: %d labels", len(addResp.Labels))

	// 2. Get label keys
	keys, err := client.Scans.GetLabelKeys(ctx, LabelListOpts{Limit: 50})
	if err != nil {
		t.Fatalf("GetLabelKeys: %v", err)
	}
	t.Logf("Label keys: %v", keys.Items)

	foundKey := false
	for _, k := range keys.Items {
		if k == testKey {
			foundKey = true
			break
		}
	}
	if !foundKey {
		t.Logf("WARNING: test key %q not found in label keys (may need propagation time)", testKey)
	}

	// 3. Get label values for our key
	vals, err := client.Scans.GetLabelValues(ctx, testKey, LabelListOpts{Limit: 50})
	if err != nil {
		t.Logf("WARNING: GetLabelValues for key %s: %v", testKey, err)
	} else {
		t.Logf("Label values for %q: %v", testKey, vals.Items)
	}

	// 4. Set labels (replace)
	setResp, err := client.Scans.SetLabels(ctx, scanUUID, LabelsCreateRequest{
		Labels: []Label{{Key: testKey, Value: "test-updated-value"}},
	})
	if err != nil {
		t.Fatalf("SetLabels: %v", err)
	}
	t.Logf("SetLabels response: %d labels", len(setResp.Labels))

	// 5. Delete labels is handled by t.Cleanup
	t.Log("Labels CRUD complete (delete via cleanup)")
}
