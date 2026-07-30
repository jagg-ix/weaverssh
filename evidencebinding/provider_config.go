package evidencebinding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const AnchorProviderConfigVersion = "weaverssh.evidence-provider-config.v1"

type AnchorProviderConfigFile struct {
	Version   string                 `json:"version"`
	Threshold int                    `json:"threshold"`
	Providers []AnchorProviderConfig `json:"providers"`
}

type AnchorProviderConfig struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	BaseURL        string `json:"base_url"`
	Token          string `json:"token,omitempty"`
	TokenEnv       string `json:"token_env,omitempty"`
	Channel        string `json:"channel,omitempty"`
	Chaincode      string `json:"chaincode,omitempty"`
	Contract       string `json:"contract,omitempty"`
	SubmitFunction string `json:"submit_function,omitempty"`
	QueryFunction  string `json:"query_function,omitempty"`
}

func DecodeAnchorProviderConfig(reader io.Reader) (AnchorProviderConfigFile, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var config AnchorProviderConfigFile
	if err := decoder.Decode(&config); err != nil {
		return AnchorProviderConfigFile{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return AnchorProviderConfigFile{}, fmt.Errorf("%w: trailing provider configuration", ErrInvalidAnchor)
		}
		return AnchorProviderConfigFile{}, err
	}
	if err := config.Validate(); err != nil {
		return AnchorProviderConfigFile{}, err
	}
	return config, nil
}

func DecodeAnchorProviderConfigBytes(data []byte) (AnchorProviderConfigFile, error) {
	return DecodeAnchorProviderConfig(bytes.NewReader(data))
}

func LoadAnchorProviderConfig(path string) (AnchorProviderConfigFile, error) {
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return AnchorProviderConfigFile{}, err
	}
	defer file.Close()
	return DecodeAnchorProviderConfig(file)
}

func (c AnchorProviderConfigFile) Validate() error {
	if c.Version != AnchorProviderConfigVersion || len(c.Providers) == 0 {
		return fmt.Errorf("%w: provider configuration version and providers are required", ErrInvalidAnchor)
	}
	threshold := c.Threshold
	if threshold == 0 {
		threshold = len(c.Providers)
	}
	if threshold <= 0 || threshold > len(c.Providers) {
		return ErrAnchorThreshold
	}
	seen := make(map[string]struct{}, len(c.Providers))
	for _, provider := range c.Providers {
		name := strings.TrimSpace(provider.Name)
		providerType := strings.ToLower(strings.TrimSpace(provider.Type))
		if name == "" || strings.TrimSpace(provider.BaseURL) == "" {
			return fmt.Errorf("%w: provider name and base_url are required", ErrInvalidAnchor)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("%w: duplicate provider %s", ErrInvalidAnchor, name)
		}
		seen[name] = struct{}{}
		switch providerType {
		case ImmuDBProviderName:
		case FabricProviderName:
			if strings.TrimSpace(provider.Channel) == "" || strings.TrimSpace(provider.Chaincode) == "" {
				return fmt.Errorf("%w: fabric provider %s requires channel and chaincode", ErrInvalidAnchor, name)
			}
		default:
			return fmt.Errorf("%w: unsupported provider type %q", ErrInvalidAnchor, provider.Type)
		}
	}
	return nil
}

func (c AnchorProviderConfigFile) Build(client *http.Client, getenv func(string) string) ([]AnchorProvider, AnchorThresholdPolicy, error) {
	if err := c.Validate(); err != nil {
		return nil, AnchorThresholdPolicy{}, err
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	providers := make([]AnchorProvider, 0, len(c.Providers))
	for _, configured := range c.Providers {
		token := strings.TrimSpace(configured.Token)
		if envName := strings.TrimSpace(configured.TokenEnv); envName != "" {
			token = strings.TrimSpace(getenv(envName))
			if token == "" {
				return nil, AnchorThresholdPolicy{}, fmt.Errorf("%w: provider %s token environment %s is empty", ErrInvalidAnchor, configured.Name, envName)
			}
		}
		var provider AnchorProvider
		switch strings.ToLower(strings.TrimSpace(configured.Type)) {
		case ImmuDBProviderName:
			provider = ImmuDBAnchor{BaseURL: configured.BaseURL, Token: token, Client: client}
		case FabricProviderName:
			provider = FabricAnchor{
				BaseURL: configured.BaseURL, Token: token, Channel: configured.Channel,
				Chaincode: configured.Chaincode, Contract: configured.Contract,
				SubmitFunction: configured.SubmitFunction, QueryFunction: configured.QueryFunction,
				Client: client,
			}
		}
		providers = append(providers, NamedAnchorProvider{ProviderName: configured.Name, Inner: provider})
	}
	threshold := c.Threshold
	if threshold == 0 {
		threshold = len(providers)
	}
	policy, err := NewAnchorThresholdPolicy(providers, threshold)
	if err != nil {
		return nil, AnchorThresholdPolicy{}, err
	}
	return providers, policy, nil
}

// NamedAnchorProvider permits multiple independently operated instances of the
// same provider type to participate in one threshold policy without allowing a
// receipt from one instance to be replayed as another instance's receipt.
type NamedAnchorProvider struct {
	ProviderName string
	Inner        AnchorProvider
}

func (p NamedAnchorProvider) Name() string { return strings.TrimSpace(p.ProviderName) }

func (p NamedAnchorProvider) Anchor(ctx context.Context, head Head) (AnchorReceipt, error) {
	if p.Inner == nil || p.Name() == "" {
		return AnchorReceipt{}, ErrInvalidAnchor
	}
	receipt, err := p.Inner.Anchor(ctx, head)
	if err != nil {
		return AnchorReceipt{}, err
	}
	receipt.Provider = p.Name()
	if err := receipt.ValidateFor(p.Name(), head); err != nil {
		return AnchorReceipt{}, err
	}
	return receipt, nil
}

func (p NamedAnchorProvider) Verify(ctx context.Context, head Head, receipt AnchorReceipt) error {
	if p.Inner == nil || p.Name() == "" {
		return ErrInvalidAnchor
	}
	if err := receipt.ValidateFor(p.Name(), head); err != nil {
		return err
	}
	delegated := receipt
	delegated.Provider = p.Inner.Name()
	return p.Inner.Verify(ctx, head, delegated)
}
