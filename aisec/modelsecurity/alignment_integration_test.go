//go:build integration

package modelsecurity

import (
	"context"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/modelsecurity/schema"
	"testing"
	"time"
)

func TestIntegration_ModelInventoryAndSnapshots(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	t.Run("models", func(t *testing.T) {
		list, err := c.Models.List(ctx, ModelListOpts{Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("models=%d", len(list.Models))
		if len(list.Models) == 0 {
			return
		}
		id := list.Models[0].UUID
		if _, err := c.Models.Get(ctx, id); err != nil {
			t.Fatal(err)
		}
		versions, err := c.Models.ListVersions(ctx, id, ModelVersionListOpts{Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("versions=%d", len(versions.ModelVersions))
		if len(versions.ModelVersions) > 0 {
			id := versions.ModelVersions[0].UUID
			if _, err := c.ModelVersions.Get(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err := c.ModelVersions.ListFiles(ctx, id, PageOpts{Limit: 2}); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("custom_rules", func(t *testing.T) {
		list, err := c.CustomRules.List(ctx, CustomRuleListOpts{Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("custom_rules=%d", len(list.CustomRules))
	})
	t.Run("custom_rule_snapshots", func(t *testing.T) {
		list, err := c.CustomRules.ListVersions(ctx, SnapshotListOpts{Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("snapshots=%d", len(list.Versions))
	})
	t.Run("security_rule_snapshots", func(t *testing.T) {
		list, err := c.SecurityRules.ListVersions(ctx, SnapshotListOpts{Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("snapshots=%d", len(list.Versions))
	})
}

// A custom rule cannot be deleted upstream: this test archives its disposable
// rule during cleanup and deletes the disposable security group.
func TestIntegration_CustomRules_LifecycleAndAssignments(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	group, err := c.SecurityGroups.Create(ctx, ModelSecurityGroupCreateRequest{Name: fmt.Sprintf("sdk-contract-%d", time.Now().UnixNano()), SourceType: SourceTypeLocal})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.SecurityGroups.Delete(clean, group.UUID); err != nil {
			t.Errorf("group cleanup: %v", err)
		}
	})
	condition, err := schema.NewCustomRuleCreateRequestConditionFromLabelCondition(schema.LabelCondition{Type: "label", Key: "sdk_contract", Operator: "exists"})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := c.CustomRules.Create(ctx, schema.CustomRuleCreateRequest{Name: fmt.Sprintf("sdk-contract-%d", time.Now().UnixNano()), CompatibleSources: []schema.SourceType{"LOCAL"}, Condition: condition, ViolationMessage: "SDK contract test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.CustomRules.Archive(clean, rule.UUID); err != nil {
			t.Errorf("rule archive cleanup: %v", err)
		}
	})
	if _, err := c.CustomRules.Get(ctx, rule.UUID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CustomRules.Update(ctx, rule.UUID, schema.CustomRuleUpdateRequest{Description: aisec.Value("updated"), RemediationMessage: aisec.Null[string]()}); err != nil {
		t.Fatal(err)
	}
	assigned, err := c.CustomRules.AssignSecurityGroups(ctx, rule.UUID, schema.BatchAssignCustomRuleRequest{Assignments: []schema.CustomRuleAssignment{{SecurityGroupUUID: group.UUID, State: "BLOCKING"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(assigned.Results) != 1 || assigned.Results[0].SecurityGroupUUID != group.UUID {
		t.Fatalf("assignment count or group mismatch")
	}
	if message, ok := assigned.Results[0].Error.Get(); ok && message != "" {
		t.Fatalf("assignment failed: %s", message)
	}
	ri, ok := assigned.Results[0].RuleInstanceUUID.Get()
	if !ok || ri == "" {
		t.Fatalf("assignment has no rule instance; status=%s", assigned.Results[0].Status)
	}
	if _, err := c.SecurityGroups.GetRuleInstanceDetails(ctx, group.UUID, ri); err != nil {
		t.Fatal(err)
	}
	groups, err := c.CustomRules.ListSecurityGroups(ctx, rule.UUID, PageOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range groups.SecurityGroups {
		if g.UUID == group.UUID {
			found = true
		}
	}
	if !found {
		t.Fatal("assigned group missing")
	}
	if _, err := c.SecurityGroups.ListRuleInstanceVersions(ctx, group.UUID, SnapshotListOpts{Limit: 2}); err != nil {
		t.Fatal(err)
	}
	if err := c.CustomRules.RemoveAssignment(ctx, rule.UUID, group.UUID); err != nil {
		t.Fatal(err)
	}
	if err := c.CustomRules.Archive(ctx, rule.UUID); err != nil {
		t.Fatal(err)
	}
	got, err := c.CustomRules.Get(ctx, rule.UUID)
	if err != nil || !got.IsArchived {
		t.Fatalf("archive state=%v error=%v", got, err)
	}
	if err := c.CustomRules.Unarchive(ctx, rule.UUID); err != nil {
		t.Fatal(err)
	}
	got, err = c.CustomRules.Get(ctx, rule.UUID)
	if err != nil || got.IsArchived {
		t.Fatalf("unarchive state=%v error=%v", got, err)
	}
}
