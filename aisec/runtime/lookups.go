package runtime

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"strings"
)

// Get reads a custom topic by UUID using the supported paginated inventory.
func (c *TopicsClient) Get(ctx context.Context, id string) (*CustomTopic, error) {
	if !aisec.IsValidUUID(id) {
		return nil, aisec.NewAISecSDKError("topic ID must be a UUID", aisec.UserRequestPayloadError)
	}
	var found *CustomTopic
	err := paginate(func(opts ListOpts) ([]CustomTopic, int, error) {
		page, err := c.List(ctx, opts)
		if err != nil {
			return nil, 0, err
		}
		return page.Items, page.NextOffset, nil
	}, func(topic CustomTopic) bool {
		if topic.TopicID == id {
			copy := topic
			found = &copy
			return true
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, notFound("topic", id)
	}
	return found, nil
}

// GetByName reads a custom topic by its exact display name.
func (c *TopicsClient) GetByName(ctx context.Context, name string) (*CustomTopic, error) {
	if strings.TrimSpace(name) == "" {
		return nil, aisec.NewAISecSDKError("topic name is required", aisec.UserRequestPayloadError)
	}
	var found *CustomTopic
	err := paginate(func(opts ListOpts) ([]CustomTopic, int, error) {
		page, err := c.List(ctx, opts)
		if err != nil {
			return nil, 0, err
		}
		return page.Items, page.NextOffset, nil
	}, func(topic CustomTopic) bool {
		if topic.TopicName == name && (found == nil || topic.Revision > found.Revision) {
			copy := topic
			found = &copy
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, notFound("topic", name)
	}
	return found, nil
}
