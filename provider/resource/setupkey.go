package resource

import (
	"context"
	"fmt"

	"github.com/excavador/pulumi-netbird/provider/config"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
	p "github.com/pulumi/pulumi-go-provider"
	"github.com/pulumi/pulumi-go-provider/infer"
)

/* ---------- Resource ---------- */

// SetupKey represents a resource for managing NetBird setup keys.
type SetupKey struct{}

// Annotate adds a description to the SetupKey resource type.
func (s *SetupKey) Annotate(a infer.Annotator) {
	a.Describe(&s, "Manages a NetBird setup key.")
}

/* ---------- Pulumi Types ---------- */

// SetupKeyArgs represents the input arguments for creating a setup key.
type SetupKeyArgs struct {
	Name                string   `pulumi:"name"`
	Type                string   `pulumi:"type"`      // "one-off" | "reusable"
	ExpiresIn           int      `pulumi:"expiresIn"` // seconds
	AutoGroups          []string `pulumi:"autoGroups"`
	UsageLimit          int      `pulumi:"usageLimit"` // 0 = unlimited
	Ephemeral           *bool    `pulumi:"ephemeral,optional"`
	AllowExtraDNSLabels *bool    `pulumi:"allowExtraDnsLabels,optional"`
}

// Annotate provides documentation for SetupKeyArgs fields.
func (a *SetupKeyArgs) Annotate(an infer.Annotator) {
	an.Describe(&a.Name, "Setup key name.")
	an.Describe(&a.Type, "Setup key type: 'one-off' or 'reusable'.")
	an.Describe(&a.ExpiresIn, "Expiration time in seconds.")
	an.Describe(&a.AutoGroups, "List of group IDs to auto-assign to peers.")
	an.Describe(&a.UsageLimit, "Usage limit (0 = unlimited).")
	an.Describe(&a.Ephemeral, "Whether peers registered with this key are ephemeral.")
	an.Describe(&a.AllowExtraDNSLabels, "Allow extra DNS labels to be added to peers.")
}

// SetupKeyState represents the state/output of a setup key resource.
type SetupKeyState struct {
	SetupKeyArgs
	Key       *string `pulumi:"key,optional"`
	Valid     *bool   `pulumi:"valid,optional"`
	Revoked   *bool   `pulumi:"revoked,optional"`
	UsedTimes *int    `pulumi:"usedTimes,optional"`
	LastUsed  *string `pulumi:"lastUsed,optional"`
	Expires   *string `pulumi:"expires,optional"`
	State     *string `pulumi:"state,optional"`
	UpdatedAt *string `pulumi:"updatedAt,optional"`
}

/* ---------- CRUD ---------- */

// Create creates a new NetBird setup key.
func (*SetupKey) Create(ctx context.Context, req infer.CreateRequest[SetupKeyArgs]) (infer.CreateResponse[SetupKeyState], error) {
	p.GetLogger(ctx).Debugf("Create:SetupKey name=%s, type=%s", req.Inputs.Name, req.Inputs.Type)

	if req.DryRun {
		return infer.CreateResponse[SetupKeyState]{
			ID: "preview",
			Output: SetupKeyState{
				SetupKeyArgs: req.Inputs,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.CreateResponse[SetupKeyState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	// Use CreateSetupKeyRequest for creation
	createReq := nbapi.CreateSetupKeyRequest{
		Name:                req.Inputs.Name,
		Type:                req.Inputs.Type,
		ExpiresIn:           req.Inputs.ExpiresIn,
		AutoGroups:          req.Inputs.AutoGroups,
		UsageLimit:          req.Inputs.UsageLimit,
		Ephemeral:           req.Inputs.Ephemeral,
		AllowExtraDnsLabels: req.Inputs.AllowExtraDNSLabels,
	}

	setupKey, err := client.SetupKeys.Create(ctx, createReq)
	if err != nil {
		return infer.CreateResponse[SetupKeyState]{}, fmt.Errorf("creating setup key failed: %w", err)
	}

	p.GetLogger(ctx).Debugf("Create:SetupKeyAPI name=%s, id=%s", setupKey.Name, setupKey.Id)

	// Convert time.Time to string
	key := setupKey.Key
	expires := setupKey.Expires.Format("2006-01-02T15:04:05Z07:00")
	lastUsed := setupKey.LastUsed.Format("2006-01-02T15:04:05Z07:00")
	updatedAt := setupKey.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
	state := setupKey.State
	revoked := setupKey.Revoked
	usedTimes := setupKey.UsedTimes

	// Note: SetupKey doesn't have a Valid field in the API, using State instead
	valid := state == "valid"

	stateObj := SetupKeyState{
		SetupKeyArgs: req.Inputs,
		Key:          &key,
		Valid:        &valid,
		Revoked:      &revoked,
		UsedTimes:    &usedTimes,
		LastUsed:     &lastUsed,
		Expires:      &expires,
		State:        &state,
		UpdatedAt:    &updatedAt,
	}

	return infer.CreateResponse[SetupKeyState]{
		ID:     setupKey.Id,
		Output: stateObj,
	}, nil
}

// Read fetches the current state of a setup key resource from NetBird.
func (*SetupKey) Read(ctx context.Context, id string, state SetupKeyState) (SetupKeyState, error) {
	p.GetLogger(ctx).Debugf("Read:SetupKey id=%s", id)

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return state, fmt.Errorf("error getting NetBird client: %w", err)
	}

	setupKey, err := client.SetupKeys.Get(ctx, id)
	if err != nil {
		return state, fmt.Errorf("reading setup key failed: %w", err)
	}

	p.GetLogger(ctx).Debugf("Read:SetupKeyAPI name=%s, id=%s", setupKey.Name, setupKey.Id)

	state.Name = setupKey.Name
	state.Type = setupKey.Type
	state.AutoGroups = setupKey.AutoGroups
	state.UsageLimit = setupKey.UsageLimit
	ephemeral := setupKey.Ephemeral
	state.Ephemeral = &ephemeral
	allowExtraDNS := setupKey.AllowExtraDnsLabels
	state.AllowExtraDNSLabels = &allowExtraDNS

	// Output fields
	key := setupKey.Key
	state.Key = &key
	revoked := setupKey.Revoked
	state.Revoked = &revoked
	usedTimes := setupKey.UsedTimes
	state.UsedTimes = &usedTimes
	expires := setupKey.Expires.Format("2006-01-02T15:04:05Z07:00")
	state.Expires = &expires
	lastUsed := setupKey.LastUsed.Format("2006-01-02T15:04:05Z07:00")
	state.LastUsed = &lastUsed
	stateStr := setupKey.State
	state.State = &stateStr
	updatedAt := setupKey.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
	state.UpdatedAt = &updatedAt
	valid := stateStr == "valid"
	state.Valid = &valid

	return state, nil
}

// Update updates the state of the setup key if needed.
func (*SetupKey) Update(ctx context.Context, req infer.UpdateRequest[SetupKeyArgs, SetupKeyState]) (infer.UpdateResponse[SetupKeyState], error) {
	p.GetLogger(ctx).Debugf("Update:SetupKey[%s] name=%s", req.ID, req.Inputs.Name)

	// Check for non-updatable field changes (would require replace)
	if req.Inputs.Name != req.State.Name ||
		req.Inputs.Type != req.State.Type ||
		req.Inputs.ExpiresIn != req.State.ExpiresIn ||
		req.Inputs.UsageLimit != req.State.UsageLimit ||
		boolVal(req.Inputs.Ephemeral) != boolVal(req.State.Ephemeral) ||
		boolVal(req.Inputs.AllowExtraDNSLabels) != boolVal(req.State.AllowExtraDNSLabels) {
		p.GetLogger(ctx).Warningf("Update:SetupKey[%s] non-updatable fields changed, resource needs replacement", req.ID)
		return infer.UpdateResponse[SetupKeyState]{}, fmt.Errorf("non-updatable fields changed, resource needs replacement")
	}

	if req.DryRun {
		return infer.UpdateResponse[SetupKeyState]{
			Output: SetupKeyState{
				SetupKeyArgs: req.Inputs,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.UpdateResponse[SetupKeyState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	// Only AutoGroups and Revoked can be updated
	updateReq := nbapi.SetupKeyRequest{
		AutoGroups: req.Inputs.AutoGroups,
		Revoked:    req.State.Revoked != nil && *req.State.Revoked,
	}

	updated, err := client.SetupKeys.Update(ctx, req.ID, updateReq)
	if err != nil {
		return infer.UpdateResponse[SetupKeyState]{}, fmt.Errorf("updating setup key failed: %w", err)
	}

	out := req.State
	out.AutoGroups = req.Inputs.AutoGroups
	revoked := updated.Revoked
	out.Revoked = &revoked
	stateStr := updated.State
	out.State = &stateStr
	valid := stateStr == "valid"
	out.Valid = &valid
	updatedAt := updated.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
	out.UpdatedAt = &updatedAt

	return infer.UpdateResponse[SetupKeyState]{Output: out}, nil
}

// Delete removes a setup key from NetBird.
func (*SetupKey) Delete(ctx context.Context, req infer.DeleteRequest[SetupKeyState]) (infer.DeleteResponse, error) {
	p.GetLogger(ctx).Debugf("Delete:SetupKey[%s]", req.ID)

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	err = client.SetupKeys.Delete(ctx, req.ID)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("deleting setup key failed: %w", err)
	}

	return infer.DeleteResponse{}, nil
}

/* ---------- Helper Functions ---------- */

// boolVal safely converts a pointer to bool to a bool value.
func boolVal(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}
