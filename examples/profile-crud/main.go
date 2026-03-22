// Example: full CRUD lifecycle for security profiles using the management API.
//
// Requires environment variables:
//
//	PANW_MGMT_CLIENT_ID, PANW_MGMT_CLIENT_SECRET, PANW_MGMT_TSG_ID
//
// Usage:
//
//	source .env  # or export the vars manually
//	go run ./examples/profile-crud/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec/management"
)

func main() {
	// ── 1. Initialize client ──────────────────────────────────────────────
	fmt.Println("═══ Security Profile CRUD Example ═══")
	fmt.Println()
	fmt.Println("── Step 1: Initialize management client")

	client, err := management.NewClient(management.Opts{
		ClientID:     os.Getenv("PANW_MGMT_CLIENT_ID"),
		ClientSecret: os.Getenv("PANW_MGMT_CLIENT_SECRET"),
		TsgID:        os.Getenv("PANW_MGMT_TSG_ID"),
	})
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}
	fmt.Println("   Client initialized successfully")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	profileName := fmt.Sprintf("sdk-example-%d", time.Now().UnixNano())

	// ── 2. Create ─────────────────────────────────────────────────────────
	fmt.Println("── Step 2: Create profile")
	created, err := client.Profiles.Create(ctx, management.CreateProfileRequest{
		ProfileName: profileName,
		Policy: &management.ProfilePolicy{
			AiSecurityProfiles: []management.AiSecurityProfileConfig{
				{
					ModelType: "default",
					ModelConfiguration: &management.ModelConfiguration{
						MaskDataInStorage: false,
						Latency: &management.LatencyConfig{
							InlineTimeoutAction: management.ProfileActionBlock,
							MaxInlineLatency:    5,
						},
						ModelProtection: []management.ModelProtectionConfig{
							{
								Name:   "prompt-injection",
								Action: management.ProfileActionBlock,
							},
						},
						AgentProtection: []management.AgentProtectionConfig{
							{
								Name:   "agent-security",
								Action: management.ProfileActionAlert,
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("Profiles.Create: %v", err)
	}
	printJSON("   Created", created)
	fmt.Println()

	// Ensure cleanup
	defer func() {
		fmt.Println("── Step 7: Cleanup (force delete)")
		delCtx, delCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer delCancel()
		resp, err := client.Profiles.ForceDelete(delCtx, created.ProfileID, "sdk-example")
		if err != nil {
			fmt.Printf("   ForceDelete: %v\n", err)
		} else {
			fmt.Printf("   ForceDelete: %s\n", resp.Message)
		}
	}()

	// ── 3. List ───────────────────────────────────────────────────────────
	fmt.Println("── Step 3: List profiles")
	listResp, err := client.Profiles.List(ctx, management.ListOpts{Limit: 100})
	if err != nil {
		log.Fatalf("Profiles.List: %v", err)
	}
	fmt.Printf("   Total profiles: %d\n", len(listResp.Items))
	for i, p := range listResp.Items {
		fmt.Printf("   [%d] id=%s name=%s revision=%d active=%v\n",
			i, p.ProfileID, p.ProfileName, p.Revision, p.Active)
	}
	fmt.Println()

	// ── 4. GetByID ────────────────────────────────────────────────────────
	fmt.Println("── Step 4: Get by ID")
	byID, err := client.Profiles.GetByID(ctx, created.ProfileID)
	if err != nil {
		log.Fatalf("Profiles.GetByID: %v", err)
	}
	printJSON("   GetByID", byID)
	fmt.Println()

	// ── 5. GetByName ──────────────────────────────────────────────────────
	fmt.Println("── Step 5: Get by Name")
	byName, err := client.Profiles.GetByName(ctx, profileName)
	if err != nil {
		log.Fatalf("Profiles.GetByName: %v", err)
	}
	printJSON("   GetByName", byName)
	fmt.Println()

	// ── 6. Update ─────────────────────────────────────────────────────────
	fmt.Println("── Step 6: Update profile")
	updated, err := client.Profiles.Update(ctx, created.ProfileID, management.UpdateProfileRequest{
		ProfileName: profileName,
		Policy: &management.ProfilePolicy{
			AiSecurityProfiles: []management.AiSecurityProfileConfig{
				{
					ModelType: "default",
					ModelConfiguration: &management.ModelConfiguration{
						MaskDataInStorage: false,
						Latency: &management.LatencyConfig{
							InlineTimeoutAction: management.ProfileActionBlock,
							MaxInlineLatency:    10,
						},
						ModelProtection: []management.ModelProtectionConfig{
							{
								Name:   "prompt-injection",
								Action: management.ProfileActionBlock,
							},
							{
								Name:   "contextual-grounding",
								Action: management.ProfileActionBlock,
							},
							{
								Name:   "toxic-content",
								Action: management.ProfileAction(management.ToxicContentHighBlockModerateAllow),
							},
						},
						AgentProtection: []management.AgentProtectionConfig{
							{
								Name:   "agent-security",
								Action: management.ProfileActionBlock,
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("Profiles.Update: %v", err)
	}
	printJSON("   Updated", updated)
	fmt.Println()

	// Step 7 (delete) runs in the deferred cleanup above.
}

func printJSON(label string, v any) {
	b, _ := json.MarshalIndent(v, "   ", "  ")
	fmt.Printf("%s: %s\n", label, string(b))
}
