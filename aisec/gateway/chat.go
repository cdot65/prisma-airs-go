package gateway

import (
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

// ChatTextMessage is a native text message; multimodal/tool messages use the full parity schema models.
type ChatTextMessage struct{ Role, Content string }

// NewChatRequest builds and validates a text-only chat request without JSON-string input.
func NewChatRequest(model string, messages ...ChatTextMessage) (parity.GatewayInferenceInputCreateChatCompletionRequest, error) {
	result := parity.GatewayInferenceInputCreateChatCompletionRequest{}
	value, err := parity.NewGatewayInferenceInputCreateChatCompletionRequestModelFromString(model)
	if err != nil {
		return result, err
	}
	result.Model = value
	result.Messages = make([]parity.GatewayInferenceInputCreateChatCompletionRequestMessagesItem, 0, len(messages))
	for _, message := range messages {
		switch message.Role {
		case "system", "developer", "user", "assistant":
		default:
			return result, invalidInput("text chat role must be system, developer, user or assistant")
		}
		data, err := json.Marshal(map[string]string{"role": message.Role, "content": message.Content})
		if err != nil {
			return result, err
		}
		var item parity.GatewayInferenceInputCreateChatCompletionRequestMessagesItem
		if err = json.Unmarshal(data, &item); err != nil {
			return result, aisec.WrapError("invalid text chat message", aisec.UserRequestPayloadError, err)
		}
		result.Messages = append(result.Messages, item)
	}
	if err = parity.Validate("GatewayInferenceInputCreateChatCompletionRequestSchema", result); err != nil {
		return result, aisec.WrapError("invalid chat request", aisec.UserRequestPayloadError, err)
	}
	return result, nil
}
