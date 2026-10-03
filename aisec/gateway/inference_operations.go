package gateway

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
	"net/url"
)

// CreateCompletion calls POST /completions using the explicitly configured runtime key.
func (c *InferenceClient) CreateCompletion(ctx context.Context, body parity.GatewayInferenceInputCreateCompletionRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceCreateCompletionResponse, error) {
	if hasStream(body) {
		return nil, invalidInput("use the corresponding Stream method for streaming requests")
	}
	return inferenceJSON[parity.GatewayInferenceCreateCompletionResponse](ctx, c, "POST", aisec.GatewayInferenceCompletionsPath, nil, body, "GatewayInferenceInputCreateCompletionRequestSchema", "GatewayInferenceCreateCompletionResponseSchema", opts)
}

// CreatePromptCompletion calls POST /prompts/{promptId}/completions using the explicitly configured runtime key.
func (c *InferenceClient) CreatePromptCompletion(ctx context.Context, promptId string, body parity.GatewayInferenceInputCreatePromptCompletionRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceCreatePromptCompletionResponse, error) {
	if err := validateResourceID(promptId); err != nil {
		return nil, err
	}
	if hasStream(body) {
		return nil, invalidInput("use the corresponding Stream method for streaming requests")
	}
	return inferenceJSON[parity.GatewayInferenceCreatePromptCompletionResponse](ctx, c, "POST", aisec.GatewayInferencePromptsPath+"/"+seg(promptId)+aisec.GatewayInferenceCompletionsPath, nil, body, "GatewayInferenceInputCreatePromptCompletionRequestSchema", "GatewayInferenceCreatePromptCompletionResponseSchema", opts)
}

// CreatePromptRender calls POST /prompts/{promptId}/render using the explicitly configured runtime key.
func (c *InferenceClient) CreatePromptRender(ctx context.Context, promptId string, body parity.GatewayInferenceInputCreatePromptRenderRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceCreatePromptRenderResponse, error) {
	if err := validateResourceID(promptId); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceCreatePromptRenderResponse](ctx, c, "POST", aisec.GatewayInferencePromptsPath+"/"+seg(promptId)+aisec.GatewayInferenceRenderPath, nil, body, "GatewayInferenceInputCreatePromptRenderRequestSchema", "GatewayInferenceCreatePromptRenderResponseSchema", opts)
}

// CreateChatCompletion calls POST /chat/completions using the explicitly configured runtime key.
func (c *InferenceClient) CreateChatCompletion(ctx context.Context, body parity.GatewayInferenceInputCreateChatCompletionRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceCreateChatCompletionResponse, error) {
	if hasStream(body) {
		return nil, invalidInput("use the corresponding Stream method for streaming requests")
	}
	return inferenceJSON[parity.GatewayInferenceCreateChatCompletionResponse](ctx, c, "POST", aisec.GatewayInferenceChatCompletionsPath, nil, body, "GatewayInferenceInputCreateChatCompletionRequestSchema", "GatewayInferenceCreateChatCompletionResponseSchema", opts)
}

// CreateEmbedding calls POST /embeddings using the explicitly configured runtime key.
func (c *InferenceClient) CreateEmbedding(ctx context.Context, body parity.GatewayInferenceInputCreateEmbeddingRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceCreateEmbeddingResponse, error) {
	return inferenceJSON[parity.GatewayInferenceCreateEmbeddingResponse](ctx, c, "POST", aisec.GatewayInferenceEmbeddingsPath, nil, body, "GatewayInferenceInputCreateEmbeddingRequestSchema", "GatewayInferenceCreateEmbeddingResponseSchema", opts)
}

// CreateResponse calls POST /responses using the explicitly configured runtime key.
func (c *InferenceClient) CreateResponse(ctx context.Context, body parity.GatewayInferenceInputCreateResponse, opts InferenceRequestOptions) (*parity.GatewayInferenceResponse, error) {
	if hasStream(body) {
		return nil, invalidInput("use the corresponding Stream method for streaming requests")
	}
	return inferenceJSON[parity.GatewayInferenceResponse](ctx, c, "POST", aisec.GatewayInferenceResponsesPath, nil, body, "GatewayInferenceInputCreateResponseSchema", "GatewayInferenceResponseSchema", opts)
}

// CreateImage calls POST /images/generations using the explicitly configured runtime key.
func (c *InferenceClient) CreateImage(ctx context.Context, body parity.GatewayInferenceInputCreateImageRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceImagesResponse, error) {
	return inferenceJSON[parity.GatewayInferenceImagesResponse](ctx, c, "POST", aisec.GatewayInferenceImagesGenerationsPath, nil, body, "GatewayInferenceInputCreateImageRequestSchema", "GatewayInferenceImagesResponseSchema", opts)
}

// CreateImageEdit calls POST /images/edits using the explicitly configured runtime key.
func (c *InferenceClient) CreateImageEdit(ctx context.Context, body parity.GatewayInferenceInputCreateImageEditRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceImagesResponse, error) {
	return inferenceMultipart[parity.GatewayInferenceImagesResponse](ctx, c, "POST", aisec.GatewayInferenceImagesEditsPath, body, "GatewayInferenceInputCreateImageEditRequestSchema", "GatewayInferenceImagesResponseSchema", opts)
}

// CreateImageVariation calls POST /images/variations using the explicitly configured runtime key.
func (c *InferenceClient) CreateImageVariation(ctx context.Context, body parity.GatewayInferenceInputCreateImageVariationRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceImagesResponse, error) {
	return inferenceMultipart[parity.GatewayInferenceImagesResponse](ctx, c, "POST", aisec.GatewayInferenceImagesVariationsPath, body, "GatewayInferenceInputCreateImageVariationRequestSchema", "GatewayInferenceImagesResponseSchema", opts)
}

// CreateRerank calls POST /rerank using the explicitly configured runtime key.
func (c *InferenceClient) CreateRerank(ctx context.Context, body parity.GatewayInferenceInputCreateRerankRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceCreateRerankResponse, error) {
	return inferenceJSON[parity.GatewayInferenceCreateRerankResponse](ctx, c, "POST", aisec.GatewayInferenceRerankPath, nil, body, "GatewayInferenceInputCreateRerankRequestSchema", "GatewayInferenceCreateRerankResponseSchema", opts)
}

// CreateOcr calls POST /ocr using the explicitly configured runtime key.
func (c *InferenceClient) CreateOcr(ctx context.Context, body parity.GatewayInferenceInputCreateOcrRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceCreateOcrResponse, error) {
	return inferenceJSON[parity.GatewayInferenceCreateOcrResponse](ctx, c, "POST", aisec.GatewayInferenceOcrPath, nil, body, "GatewayInferenceInputCreateOcrRequestSchema", "GatewayInferenceCreateOcrResponseSchema", opts)
}

// CreateSpeech calls POST /audio/speech using the explicitly configured runtime key.
func (c *InferenceClient) CreateSpeech(ctx context.Context, body parity.GatewayInferenceInputCreateSpeechRequest, opts InferenceRequestOptions) (*BinaryResponse, error) {
	return inferenceBinary(ctx, c, "POST", aisec.GatewayInferenceAudioSpeechPath, body, "GatewayInferenceInputCreateSpeechRequestSchema", opts)
}

// CreateTranscription calls POST /audio/transcriptions using the explicitly configured runtime key.
func (c *InferenceClient) CreateTranscription(ctx context.Context, body parity.GatewayInferenceInputCreateTranscriptionRequest, opts InferenceRequestOptions) (*AudioResponse, error) {
	return inferenceAudio(ctx, c, aisec.GatewayInferenceAudioTranscriptionsPath, body, "GatewayInferenceInputCreateTranscriptionRequestSchema", body.ResponseFormat, opts)
}

// CreateTranslation calls POST /audio/translations using the explicitly configured runtime key.
func (c *InferenceClient) CreateTranslation(ctx context.Context, body parity.GatewayInferenceInputCreateTranslationRequest, opts InferenceRequestOptions) (*AudioResponse, error) {
	return inferenceAudio(ctx, c, aisec.GatewayInferenceAudioTranslationsPath, body, "GatewayInferenceInputCreateTranslationRequestSchema", body.ResponseFormat, opts)
}

// ListFiles calls GET /files using the explicitly configured runtime key.
func (c *InferenceClient) ListFiles(ctx context.Context, queryOpts parity.GatewayInferenceInputListFilesQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListFilesResponse, error) {
	if err := parity.Validate("GatewayInferenceInputListFilesQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListFilesResponse](ctx, c, "GET", aisec.GatewayInferenceFilesPath, query, nil, "", "GatewayInferenceListFilesResponseSchema", opts)
}

// CreateFile calls POST /files using the explicitly configured runtime key.
func (c *InferenceClient) CreateFile(ctx context.Context, body parity.GatewayInferenceInputCreateFileRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceOpenAIFile, error) {
	return inferenceMultipart[parity.GatewayInferenceOpenAIFile](ctx, c, "POST", aisec.GatewayInferenceFilesPath, body, "GatewayInferenceInputCreateFileRequestSchema", "GatewayInferenceOpenAIFileSchema", opts)
}

// DeleteFile calls DELETE /files/{file_id} using the explicitly configured runtime key.
func (c *InferenceClient) DeleteFile(ctx context.Context, file_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceDeleteFileResponse, error) {
	if err := validateResourceID(file_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceDeleteFileResponse](ctx, c, "DELETE", aisec.GatewayInferenceFilesPath+"/"+seg(file_id)+"", nil, nil, "", "GatewayInferenceDeleteFileResponseSchema", opts)
}

// RetrieveFile calls GET /files/{file_id} using the explicitly configured runtime key.
func (c *InferenceClient) RetrieveFile(ctx context.Context, file_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceOpenAIFile, error) {
	if err := validateResourceID(file_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceOpenAIFile](ctx, c, "GET", aisec.GatewayInferenceFilesPath+"/"+seg(file_id)+"", nil, nil, "", "GatewayInferenceOpenAIFileSchema", opts)
}

// DownloadFile calls GET /files/{file_id}/content using the explicitly configured runtime key.
func (c *InferenceClient) DownloadFile(ctx context.Context, file_id string, opts InferenceRequestOptions) (*BinaryResponse, error) {
	if err := validateResourceID(file_id); err != nil {
		return nil, err
	}
	return inferenceBinary(ctx, c, "GET", aisec.GatewayInferenceFilesPath+"/"+seg(file_id)+aisec.GatewayInferenceContentPath, nil, "", opts)
}

// CreateFineTuningJob calls POST /fine_tuning/jobs using the explicitly configured runtime key.
func (c *InferenceClient) CreateFineTuningJob(ctx context.Context, body parity.GatewayInferenceInputCreateFineTuningJobRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceFineTuningJob, error) {
	return inferenceJSON[parity.GatewayInferenceFineTuningJob](ctx, c, "POST", aisec.GatewayInferenceFineTuningJobsPath, nil, body, "GatewayInferenceInputCreateFineTuningJobRequestSchema", "GatewayInferenceFineTuningJobSchema", opts)
}

// ListPaginatedFineTuningJobs calls GET /fine_tuning/jobs using the explicitly configured runtime key.
func (c *InferenceClient) ListPaginatedFineTuningJobs(ctx context.Context, queryOpts parity.GatewayInferenceInputListPaginatedFineTuningJobsQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListPaginatedFineTuningJobsResponse, error) {
	if err := parity.Validate("GatewayInferenceInputListPaginatedFineTuningJobsQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListPaginatedFineTuningJobsResponse](ctx, c, "GET", aisec.GatewayInferenceFineTuningJobsPath, query, nil, "", "GatewayInferenceListPaginatedFineTuningJobsResponseSchema", opts)
}

// RetrieveFineTuningJob calls GET /fine_tuning/jobs/{fine_tuning_job_id} using the explicitly configured runtime key.
func (c *InferenceClient) RetrieveFineTuningJob(ctx context.Context, fine_tuning_job_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceFineTuningJob, error) {
	if err := validateResourceID(fine_tuning_job_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceFineTuningJob](ctx, c, "GET", aisec.GatewayInferenceFineTuningJobsPath+"/"+seg(fine_tuning_job_id)+"", nil, nil, "", "GatewayInferenceFineTuningJobSchema", opts)
}

// ListFineTuningEvents calls GET /fine_tuning/jobs/{fine_tuning_job_id}/events using the explicitly configured runtime key.
func (c *InferenceClient) ListFineTuningEvents(ctx context.Context, fine_tuning_job_id string, queryOpts parity.GatewayInferenceInputListFineTuningEventsQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListFineTuningJobEventsResponse, error) {
	if err := validateResourceID(fine_tuning_job_id); err != nil {
		return nil, err
	}
	if err := parity.Validate("GatewayInferenceInputListFineTuningEventsQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListFineTuningJobEventsResponse](ctx, c, "GET", aisec.GatewayInferenceFineTuningJobsPath+"/"+seg(fine_tuning_job_id)+aisec.GatewayInferenceEventsPath, query, nil, "", "GatewayInferenceListFineTuningJobEventsResponseSchema", opts)
}

// CancelFineTuningJob calls POST /fine_tuning/jobs/{fine_tuning_job_id}/cancel using the explicitly configured runtime key.
func (c *InferenceClient) CancelFineTuningJob(ctx context.Context, fine_tuning_job_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceFineTuningJob, error) {
	if err := validateResourceID(fine_tuning_job_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceFineTuningJob](ctx, c, "POST", aisec.GatewayInferenceFineTuningJobsPath+"/"+seg(fine_tuning_job_id)+aisec.GatewayInferenceCancelPath, nil, nil, "", "GatewayInferenceFineTuningJobSchema", opts)
}

// ListFineTuningJobCheckpoints calls GET /fine_tuning/jobs/{fine_tuning_job_id}/checkpoints using the explicitly configured runtime key.
func (c *InferenceClient) ListFineTuningJobCheckpoints(ctx context.Context, fine_tuning_job_id string, queryOpts parity.GatewayInferenceInputListFineTuningJobCheckpointsQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListFineTuningJobCheckpointsResponse, error) {
	if err := validateResourceID(fine_tuning_job_id); err != nil {
		return nil, err
	}
	if err := parity.Validate("GatewayInferenceInputListFineTuningJobCheckpointsQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListFineTuningJobCheckpointsResponse](ctx, c, "GET", aisec.GatewayInferenceFineTuningJobsPath+"/"+seg(fine_tuning_job_id)+aisec.GatewayInferenceCheckpointsPath, query, nil, "", "GatewayInferenceListFineTuningJobCheckpointsResponseSchema", opts)
}

// ListModels calls GET /models using the explicitly configured runtime key.
func (c *InferenceClient) ListModels(ctx context.Context, queryOpts parity.GatewayInferenceInputListModelsQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListModelsResponse, error) {
	if err := parity.Validate("GatewayInferenceInputListModelsQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListModelsResponse](ctx, c, "GET", aisec.GatewayInferenceModelsPath, query, nil, "", "GatewayInferenceListModelsResponseSchema", opts)
}

// RetrieveModel calls GET /models/{model} using the explicitly configured runtime key.
func (c *InferenceClient) RetrieveModel(ctx context.Context, model string, opts InferenceRequestOptions) (*parity.GatewayInferenceModel, error) {
	if err := validateResourceID(model); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceModel](ctx, c, "GET", aisec.GatewayInferenceModelsPath+"/"+seg(model)+"", nil, nil, "", "GatewayInferenceModelSchema", opts)
}

// DeleteModel calls DELETE /models/{model} using the explicitly configured runtime key.
func (c *InferenceClient) DeleteModel(ctx context.Context, model string, opts InferenceRequestOptions) (*parity.GatewayInferenceDeleteModelResponse, error) {
	if err := validateResourceID(model); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceDeleteModelResponse](ctx, c, "DELETE", aisec.GatewayInferenceModelsPath+"/"+seg(model)+"", nil, nil, "", "GatewayInferenceDeleteModelResponseSchema", opts)
}

// CreateModeration calls POST /moderations using the explicitly configured runtime key.
func (c *InferenceClient) CreateModeration(ctx context.Context, body parity.GatewayInferenceInputCreateModerationRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceCreateModerationResponse, error) {
	return inferenceJSON[parity.GatewayInferenceCreateModerationResponse](ctx, c, "POST", aisec.GatewayInferenceModerationsPath, nil, body, "GatewayInferenceInputCreateModerationRequestSchema", "GatewayInferenceCreateModerationResponseSchema", opts)
}

// GetResponse calls GET /responses/{response_id} using the explicitly configured runtime key.
func (c *InferenceClient) GetResponse(ctx context.Context, response_id string, queryOpts parity.GatewayInferenceInputGetResponseQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceResponse, error) {
	if err := validateResourceID(response_id); err != nil {
		return nil, err
	}
	if err := parity.Validate("GatewayInferenceInputGetResponseQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceResponse](ctx, c, "GET", aisec.GatewayInferenceResponsesPath+"/"+seg(response_id)+"", query, nil, "", "GatewayInferenceResponseSchema", opts)
}

// DeleteResponse deletes a runtime response; successful bodies are discarded.
func (c *InferenceClient) DeleteResponse(ctx context.Context, response_id string, opts InferenceRequestOptions) error {
	if err := validateResourceID(response_id); err != nil {
		return err
	}
	_, err := inferenceText(ctx, c, "DELETE", aisec.GatewayInferenceResponsesPath+"/"+seg(response_id)+"", nil, "", opts)
	return err
}

// ListInputItems calls GET /responses/{response_id}/input_items using the explicitly configured runtime key.
func (c *InferenceClient) ListInputItems(ctx context.Context, response_id string, queryOpts parity.GatewayInferenceInputListInputItemsQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceResponseItemList, error) {
	if err := validateResourceID(response_id); err != nil {
		return nil, err
	}
	if err := parity.Validate("GatewayInferenceInputListInputItemsQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceResponseItemList](ctx, c, "GET", aisec.GatewayInferenceResponsesPath+"/"+seg(response_id)+aisec.GatewayInferenceInputItemsPath, query, nil, "", "GatewayInferenceResponseItemListSchema", opts)
}

// ListVectorStores calls GET /vector_stores using the explicitly configured runtime key.
func (c *InferenceClient) ListVectorStores(ctx context.Context, queryOpts parity.GatewayInferenceInputListVectorStoresQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListVectorStoresResponse, error) {
	if err := parity.Validate("GatewayInferenceInputListVectorStoresQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListVectorStoresResponse](ctx, c, "GET", aisec.GatewayInferenceVectorStoresPath, query, nil, "", "GatewayInferenceListVectorStoresResponseSchema", opts)
}

// CreateVectorStore calls POST /vector_stores using the explicitly configured runtime key.
func (c *InferenceClient) CreateVectorStore(ctx context.Context, body parity.GatewayInferenceInputCreateVectorStoreRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceVectorStoreObject, error) {
	return inferenceJSON[parity.GatewayInferenceVectorStoreObject](ctx, c, "POST", aisec.GatewayInferenceVectorStoresPath, nil, body, "GatewayInferenceInputCreateVectorStoreRequestSchema", "GatewayInferenceVectorStoreObjectSchema", opts)
}

// GetVectorStore calls GET /vector_stores/{vector_store_id} using the explicitly configured runtime key.
func (c *InferenceClient) GetVectorStore(ctx context.Context, vector_store_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceVectorStoreObject, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceVectorStoreObject](ctx, c, "GET", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+"", nil, nil, "", "GatewayInferenceVectorStoreObjectSchema", opts)
}

// ModifyVectorStore calls POST /vector_stores/{vector_store_id} using the explicitly configured runtime key.
func (c *InferenceClient) ModifyVectorStore(ctx context.Context, vector_store_id string, body parity.GatewayInferenceInputUpdateVectorStoreRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceVectorStoreObject, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceVectorStoreObject](ctx, c, "POST", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+"", nil, body, "GatewayInferenceInputUpdateVectorStoreRequestSchema", "GatewayInferenceVectorStoreObjectSchema", opts)
}

// DeleteVectorStore calls DELETE /vector_stores/{vector_store_id} using the explicitly configured runtime key.
func (c *InferenceClient) DeleteVectorStore(ctx context.Context, vector_store_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceDeleteVectorStoreResponse, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceDeleteVectorStoreResponse](ctx, c, "DELETE", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+"", nil, nil, "", "GatewayInferenceDeleteVectorStoreResponseSchema", opts)
}

// ListVectorStoreFiles calls GET /vector_stores/{vector_store_id}/files using the explicitly configured runtime key.
func (c *InferenceClient) ListVectorStoreFiles(ctx context.Context, vector_store_id string, queryOpts parity.GatewayInferenceInputListVectorStoreFilesQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListVectorStoreFilesResponse, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	if err := parity.Validate("GatewayInferenceInputListVectorStoreFilesQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListVectorStoreFilesResponse](ctx, c, "GET", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+aisec.GatewayInferenceFilesPath, query, nil, "", "GatewayInferenceListVectorStoreFilesResponseSchema", opts)
}

// CreateVectorStoreFile calls POST /vector_stores/{vector_store_id}/files using the explicitly configured runtime key.
func (c *InferenceClient) CreateVectorStoreFile(ctx context.Context, vector_store_id string, body parity.GatewayInferenceInputCreateVectorStoreFileRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceVectorStoreFileObject, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceVectorStoreFileObject](ctx, c, "POST", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+aisec.GatewayInferenceFilesPath, nil, body, "GatewayInferenceInputCreateVectorStoreFileRequestSchema", "GatewayInferenceVectorStoreFileObjectSchema", opts)
}

// GetVectorStoreFile calls GET /vector_stores/{vector_store_id}/files/{file_id} using the explicitly configured runtime key.
func (c *InferenceClient) GetVectorStoreFile(ctx context.Context, vector_store_id string, file_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceVectorStoreFileObject, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	if err := validateResourceID(file_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceVectorStoreFileObject](ctx, c, "GET", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+aisec.GatewayInferenceFilesPath+"/"+seg(file_id)+"", nil, nil, "", "GatewayInferenceVectorStoreFileObjectSchema", opts)
}

// DeleteVectorStoreFile calls DELETE /vector_stores/{vector_store_id}/files/{file_id} using the explicitly configured runtime key.
func (c *InferenceClient) DeleteVectorStoreFile(ctx context.Context, vector_store_id string, file_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceDeleteVectorStoreFileResponse, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	if err := validateResourceID(file_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceDeleteVectorStoreFileResponse](ctx, c, "DELETE", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+aisec.GatewayInferenceFilesPath+"/"+seg(file_id)+"", nil, nil, "", "GatewayInferenceDeleteVectorStoreFileResponseSchema", opts)
}

// CreateVectorStoreFileBatch calls POST /vector_stores/{vector_store_id}/file_batches using the explicitly configured runtime key.
func (c *InferenceClient) CreateVectorStoreFileBatch(ctx context.Context, vector_store_id string, body parity.GatewayInferenceInputCreateVectorStoreFileBatchRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceVectorStoreFileBatchObject, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceVectorStoreFileBatchObject](ctx, c, "POST", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+aisec.GatewayInferenceFileBatchesPath, nil, body, "GatewayInferenceInputCreateVectorStoreFileBatchRequestSchema", "GatewayInferenceVectorStoreFileBatchObjectSchema", opts)
}

// GetVectorStoreFileBatch calls GET /vector_stores/{vector_store_id}/file_batches/{batch_id} using the explicitly configured runtime key.
func (c *InferenceClient) GetVectorStoreFileBatch(ctx context.Context, vector_store_id string, batch_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceVectorStoreFileBatchObject, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	if err := validateResourceID(batch_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceVectorStoreFileBatchObject](ctx, c, "GET", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+aisec.GatewayInferenceFileBatchesPath+"/"+seg(batch_id)+"", nil, nil, "", "GatewayInferenceVectorStoreFileBatchObjectSchema", opts)
}

// CancelVectorStoreFileBatch calls POST /vector_stores/{vector_store_id}/file_batches/{batch_id}/cancel using the explicitly configured runtime key.
func (c *InferenceClient) CancelVectorStoreFileBatch(ctx context.Context, vector_store_id string, batch_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceVectorStoreFileBatchObject, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	if err := validateResourceID(batch_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceVectorStoreFileBatchObject](ctx, c, "POST", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+aisec.GatewayInferenceFileBatchesPath+"/"+seg(batch_id)+aisec.GatewayInferenceCancelPath, nil, nil, "", "GatewayInferenceVectorStoreFileBatchObjectSchema", opts)
}

// ListFilesInVectorStoreBatch calls GET /vector_stores/{vector_store_id}/file_batches/{batch_id}/files using the explicitly configured runtime key.
func (c *InferenceClient) ListFilesInVectorStoreBatch(ctx context.Context, vector_store_id string, batch_id string, queryOpts parity.GatewayInferenceInputListFilesInVectorStoreBatchQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListVectorStoreFilesResponse, error) {
	if err := validateResourceID(vector_store_id); err != nil {
		return nil, err
	}
	if err := validateResourceID(batch_id); err != nil {
		return nil, err
	}
	if err := parity.Validate("GatewayInferenceInputListFilesInVectorStoreBatchQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListVectorStoreFilesResponse](ctx, c, "GET", aisec.GatewayInferenceVectorStoresPath+"/"+seg(vector_store_id)+aisec.GatewayInferenceFileBatchesPath+"/"+seg(batch_id)+aisec.GatewayInferenceFilesPath, query, nil, "", "GatewayInferenceListVectorStoreFilesResponseSchema", opts)
}

// CreateBatch calls POST /batches using the explicitly configured runtime key.
func (c *InferenceClient) CreateBatch(ctx context.Context, body parity.GatewayInferenceInputCreateBatchRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceBatch, error) {
	return inferenceJSON[parity.GatewayInferenceBatch](ctx, c, "POST", aisec.GatewayInferenceBatchesPath, nil, body, "GatewayInferenceInputCreateBatchRequestSchema", "GatewayInferenceBatchSchema", opts)
}

// ListBatches calls GET /batches using the explicitly configured runtime key.
func (c *InferenceClient) ListBatches(ctx context.Context, queryOpts parity.GatewayInferenceInputListBatchesQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceListBatchesResponse, error) {
	if err := parity.Validate("GatewayInferenceInputListBatchesQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceListBatchesResponse](ctx, c, "GET", aisec.GatewayInferenceBatchesPath, query, nil, "", "GatewayInferenceListBatchesResponseSchema", opts)
}

// GetBatchOutput calls GET /batches/{batch_id}/output using the explicitly configured runtime key.
func (c *InferenceClient) GetBatchOutput(ctx context.Context, batch_id string, opts InferenceRequestOptions) (*BinaryResponse, error) {
	if err := validateResourceID(batch_id); err != nil {
		return nil, err
	}
	return inferenceBinary(ctx, c, "GET", aisec.GatewayInferenceBatchesPath+"/"+seg(batch_id)+aisec.GatewayInferenceOutputPath, nil, "", opts)
}

// RetrieveBatch calls GET /batches/{batch_id} using the explicitly configured runtime key.
func (c *InferenceClient) RetrieveBatch(ctx context.Context, batch_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceBatch, error) {
	if err := validateResourceID(batch_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceBatch](ctx, c, "GET", aisec.GatewayInferenceBatchesPath+"/"+seg(batch_id)+"", nil, nil, "", "GatewayInferenceBatchSchema", opts)
}

// CancelBatch calls POST /batches/{batch_id}/cancel using the explicitly configured runtime key.
func (c *InferenceClient) CancelBatch(ctx context.Context, batch_id string, opts InferenceRequestOptions) (*parity.GatewayInferenceBatch, error) {
	if err := validateResourceID(batch_id); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceBatch](ctx, c, "POST", aisec.GatewayInferenceBatchesPath+"/"+seg(batch_id)+aisec.GatewayInferenceCancelPath, nil, nil, "", "GatewayInferenceBatchSchema", opts)
}

// CreateFeedback calls POST /feedback using the explicitly configured runtime key.
func (c *InferenceClient) CreateFeedback(ctx context.Context, body parity.GatewayInferenceInputFeedbackRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceFeedbackResponse, error) {
	return inferenceJSON[parity.GatewayInferenceFeedbackResponse](ctx, c, "POST", aisec.GatewayInferenceFeedbackPath, nil, body, "GatewayInferenceInputFeedbackRequestSchema", "GatewayInferenceFeedbackResponseSchema", opts)
}

// UpdateFeedback calls PUT /feedback/{id} using the explicitly configured runtime key.
func (c *InferenceClient) UpdateFeedback(ctx context.Context, id string, body parity.GatewayInferenceInputFeedbackUpdateRequest, opts InferenceRequestOptions) (*parity.GatewayInferenceFeedbackResponse, error) {
	if !aisec.IsValidUUID(id) {
		return nil, invalidInput("feedback ID must be a UUID")
	}
	return inferenceJSON[parity.GatewayInferenceFeedbackResponse](ctx, c, "PUT", aisec.GatewayInferenceFeedbackPath+"/"+seg(id)+"", nil, body, "GatewayInferenceInputFeedbackUpdateRequestSchema", "GatewayInferenceFeedbackResponseSchema", opts)
}

// CreateLogs calls POST /logs using the explicitly configured runtime key.
func (c *InferenceClient) CreateLogs(ctx context.Context, body parity.GatewayInferenceInputCreateLogsRequest, opts InferenceRequestOptions) (*string, error) {
	return inferenceText(ctx, c, "POST", aisec.GatewayInferenceLogsPath, body, "GatewayInferenceInputCreateLogsRequestSchema", opts)
}

// GetLog calls GET /logs/{logId} using the explicitly configured runtime key.
func (c *InferenceClient) GetLog(ctx context.Context, logId string, queryOpts parity.GatewayInferenceInputGetLogQuery, opts InferenceRequestOptions) (*parity.GatewayInferenceLogObject, error) {
	if err := validateResourceID(logId); err != nil {
		return nil, err
	}
	if err := parity.Validate("GatewayInferenceInputGetLogQuerySchema", queryOpts); err != nil {
		return nil, aisec.WrapError("invalid runtime query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(queryOpts, nil)
	if err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayInferenceLogObject](ctx, c, "GET", aisec.GatewayInferenceLogsPath+"/"+seg(logId)+"", query, nil, "", "GatewayInferenceLogObjectSchema", opts)
}

// QueryOptions preserves typed query serialization for runtime resources.
type QueryOptions = url.Values
