package evidencebinding

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	ImmuDBProviderName = "immudb"
	immuSafeSetPath    = "/v1/immurestproxy/item/safe"
	immuSafeGetPath    = "/v1/immurestproxy/item/safe/get"
)

type ImmuDBAnchor struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func (p ImmuDBAnchor) Name() string { return ImmuDBProviderName }

func (p ImmuDBAnchor) Anchor(ctx context.Context, head Head) (AnchorReceipt, error) {
	statement, err := NewAnchorStatement(head)
	if err != nil {
		return AnchorReceipt{}, err
	}
	canonical, err := statement.CanonicalBytes()
	if err != nil {
		return AnchorReceipt{}, err
	}
	key := immuDBAnchorKey(statement)
	request := struct {
		KV struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"kv"`
	}{}
	request.KV.Key = base64.StdEncoding.EncodeToString([]byte(key))
	request.KV.Value = base64.StdEncoding.EncodeToString(canonical)
	idempotencyKey, err := anchorIdempotencyKey(statement)
	if err != nil {
		return AnchorReceipt{}, err
	}
	if _, err := p.postJSON(ctx, immuSafeSetPath, request, idempotencyKey); err != nil {
		return AnchorReceipt{}, err
	}
	proofResponse, err := p.readVerified(ctx, request.KV.Key, canonical)
	if err != nil {
		return AnchorReceipt{}, err
	}
	return AnchorReceipt{
		Version: AnchorVersion, Provider: p.Name(), Statement: statement,
		ExternalID: key, ProofSHA256: anchorProofSHA256(proofResponse), Committed: true,
	}, nil
}

func (p ImmuDBAnchor) Verify(ctx context.Context, head Head, receipt AnchorReceipt) error {
	if err := receipt.ValidateFor(p.Name(), head); err != nil {
		return err
	}
	canonical, err := receipt.Statement.CanonicalBytes()
	if err != nil {
		return err
	}
	encodedKey := base64.StdEncoding.EncodeToString([]byte(receipt.ExternalID))
	_, err = p.readVerified(ctx, encodedKey, canonical)
	return err
}

func immuDBAnchorKey(statement AnchorStatement) string {
	return fmt.Sprintf("weaverssh:evidence:%s:%020d", url.PathEscape(statement.StreamID), statement.Sequence)
}

func (p ImmuDBAnchor) readVerified(ctx context.Context, encodedKey string, expected []byte) ([]byte, error) {
	response, err := p.postJSON(ctx, immuSafeGetPath, struct {
		Key string `json:"key"`
	}{Key: encodedKey}, "")
	if err != nil {
		return nil, err
	}
	values := collectJSONStringFields(response, "value")
	if len(values) != 1 {
		return nil, fmt.Errorf("%w: immudb verified response contains %d value fields", ErrInvalidAnchor, len(values))
	}
	decoded, err := base64.StdEncoding.DecodeString(values[0])
	if err != nil {
		return nil, fmt.Errorf("%w: immudb value is not base64", ErrInvalidAnchor)
	}
	if !bytes.Equal(decoded, expected) {
		return nil, ErrAnchorMismatch
	}
	return response, nil
}

func (p ImmuDBAnchor) postJSON(ctx context.Context, path string, body any, idempotencyKey string) ([]byte, error) {
	base := strings.TrimRight(strings.TrimSpace(p.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("%w: immudb base URL required", ErrInvalidAnchor)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if token := strings.TrimSpace(p.Token); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: immudb status %d", ErrAnchorRejected, response.StatusCode)
	}
	return data, nil
}

func collectJSONStringFields(data []byte, field string) []string {
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil
	}
	var values []string
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == field {
					if text, ok := child.(string); ok {
						values = append(values, text)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(document)
	return values
}
