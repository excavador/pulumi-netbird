package resource

import (
	"context"
	"fmt"

	"github.com/excavador/pulumi-netbird/provider/config"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
	p "github.com/pulumi/pulumi-go-provider"
	"github.com/pulumi/pulumi-go-provider/infer"
)

// Token represents a NetBird personal access token resource.
type Token struct{}

// Annotate describes the resource and its fields.
func (t *Token) Annotate(a infer.Annotator) {
	a.Describe(t, "A NetBird personal access token (PAT) for a user.")
}

// TokenArgs defines input arguments for creating a NetBird token.
type TokenArgs struct {
	// UserID is the unique identifier of the user who owns the token.
	UserID string `pulumi:"userId"`
	// Name is the name of the token.
	Name string `pulumi:"name"`
	// ExpiresIn is the expiration time in days (1-365).
	ExpiresIn int `pulumi:"expiresIn"`
}

// Annotate adds descriptions for SDK schema generation.
func (args *TokenArgs) Annotate(annotator infer.Annotator) {
	annotator.Describe(&args.UserID, "The unique identifier of the user who owns the token.")
	annotator.Describe(&args.Name, "Name of the token.")
	annotator.Describe(&args.ExpiresIn, "Expiration time in days (1-365).")
}

// TokenState represents the stored state of a NetBird token in Pulumi.
type TokenState struct {
	TokenArgs

	// PlainToken is the plain text representation of the generated token.
	// Only available immediately after creation.
	PlainToken *string `provider:"secret" pulumi:"plainToken,optional"`
	// CreatedAt is the date the token was created.
	CreatedAt *string `pulumi:"createdAt,optional"`
	// CreatedBy is the user ID of the user who created the token.
	CreatedBy *string `pulumi:"createdBy,optional"`
	// ExpirationDate is the date the token expires.
	ExpirationDate *string `pulumi:"expirationDate,optional"`
	// LastUsed is the date the token was last used.
	LastUsed *string `pulumi:"lastUsed,optional"`
}

// Annotate documents the stored state for the Pulumi schema.
func (state *TokenState) Annotate(annotator infer.Annotator) {
	annotator.Describe(&state.UserID, "The unique identifier of the user who owns the token.")
	annotator.Describe(&state.Name, "Name of the token.")
	annotator.Describe(&state.ExpiresIn, "Expiration time in days (1-365).")
	annotator.Describe(&state.PlainToken, "Plain text representation of the generated token. Only available after creation.")
	annotator.Describe(&state.CreatedAt, "Date the token was created.")
	annotator.Describe(&state.CreatedBy, "User ID of the user who created the token.")
	annotator.Describe(&state.ExpirationDate, "Date the token expires.")
	annotator.Describe(&state.LastUsed, "Date the token was last used.")
}

// Create creates a new NetBird personal access token.
func (*Token) Create(ctx context.Context, req infer.CreateRequest[TokenArgs]) (infer.CreateResponse[TokenState], error) {
	p.GetLogger(ctx).Debugf("Create:Token name=%s, userId=%s", req.Inputs.Name, req.Inputs.UserID)

	if req.DryRun {
		return infer.CreateResponse[TokenState]{
			ID: "preview",
			Output: TokenState{
				TokenArgs:      req.Inputs,
				PlainToken:     nil,
				CreatedAt:      nil,
				CreatedBy:      nil,
				ExpirationDate: nil,
				LastUsed:       nil,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.CreateResponse[TokenState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	token, err := client.Tokens.Create(ctx, req.Inputs.UserID, nbapi.PersonalAccessTokenRequest{
		Name:      req.Inputs.Name,
		ExpiresIn: req.Inputs.ExpiresIn,
	})
	if err != nil {
		return infer.CreateResponse[TokenState]{}, fmt.Errorf("creating token failed: %w", err)
	}

	p.GetLogger(ctx).Debugf("Create:TokenAPI name=%s, id=%s", token.PersonalAccessToken.Name, token.PersonalAccessToken.Id)

	// Convert time.Time to string
	createdAt := token.PersonalAccessToken.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
	expirationDate := token.PersonalAccessToken.ExpirationDate.Format("2006-01-02T15:04:05Z07:00")
	createdBy := token.PersonalAccessToken.CreatedBy
	plainToken := token.PlainToken

	var lastUsed *string

	if token.PersonalAccessToken.LastUsed != nil {
		lastUsedStr := token.PersonalAccessToken.LastUsed.Format("2006-01-02T15:04:05Z07:00")
		lastUsed = &lastUsedStr
	}

	return infer.CreateResponse[TokenState]{
		ID: token.PersonalAccessToken.Id,
		Output: TokenState{
			TokenArgs:      req.Inputs,
			PlainToken:     &plainToken,
			CreatedAt:      &createdAt,
			CreatedBy:      &createdBy,
			ExpirationDate: &expirationDate,
			LastUsed:       lastUsed,
		},
	}, nil
}

// Read fetches the current state of a token from NetBird.
func (*Token) Read(ctx context.Context, req infer.ReadRequest[TokenArgs, TokenState]) (infer.ReadResponse[TokenArgs, TokenState], error) {
	p.GetLogger(ctx).Debugf("Read:Token[%s] userId=%s", req.ID, req.State.UserID)

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.ReadResponse[TokenArgs, TokenState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	token, err := client.Tokens.Get(ctx, req.State.UserID, req.ID)
	if err != nil {
		return infer.ReadResponse[TokenArgs, TokenState]{}, fmt.Errorf("reading token failed: %w", err)
	}

	p.GetLogger(ctx).Debugf("Read:TokenAPI[%s] name=%s", token.Id, token.Name)

	// Convert time.Time to string
	createdAt := token.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
	expirationDate := token.ExpirationDate.Format("2006-01-02T15:04:05Z07:00")
	createdBy := token.CreatedBy

	var lastUsed *string

	if token.LastUsed != nil {
		lastUsedStr := token.LastUsed.Format("2006-01-02T15:04:05Z07:00")
		lastUsed = &lastUsedStr
	}

	// Note: PlainToken is only available at creation time, preserve from state
	return infer.ReadResponse[TokenArgs, TokenState]{
		ID: req.ID,
		Inputs: TokenArgs{
			UserID:    req.State.UserID,
			Name:      token.Name,
			ExpiresIn: req.State.ExpiresIn, // Not returned by API, preserve from state
		},
		State: TokenState{
			TokenArgs: TokenArgs{
				UserID:    req.State.UserID,
				Name:      token.Name,
				ExpiresIn: req.State.ExpiresIn,
			},
			PlainToken:     req.State.PlainToken, // Preserve from state, not available from API
			CreatedAt:      &createdAt,
			CreatedBy:      &createdBy,
			ExpirationDate: &expirationDate,
			LastUsed:       lastUsed,
		},
	}, nil
}

// Delete removes a token from NetBird.
func (*Token) Delete(ctx context.Context, req infer.DeleteRequest[TokenState]) (infer.DeleteResponse, error) {
	p.GetLogger(ctx).Debugf("Delete:Token[%s] userId=%s", req.ID, req.State.UserID)

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	err = client.Tokens.Delete(ctx, req.State.UserID, req.ID)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("deleting token failed: %w", err)
	}

	return infer.DeleteResponse{}, nil
}

// Diff detects changes between inputs and prior state.
// Tokens cannot be updated, so any change requires replacement.
func (*Token) Diff(ctx context.Context, req infer.DiffRequest[TokenArgs, TokenState]) (infer.DiffResponse, error) {
	p.GetLogger(ctx).Debugf("Diff:Token[%s]", req.ID)

	diff := map[string]p.PropertyDiff{}

	// Any change to inputs requires replacement since tokens cannot be updated
	if req.Inputs.UserID != req.State.UserID {
		diff["userId"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.UpdateReplace,
		}
	}

	if req.Inputs.Name != req.State.Name {
		diff["name"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.UpdateReplace,
		}
	}

	if req.Inputs.ExpiresIn != req.State.ExpiresIn {
		diff["expiresIn"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.UpdateReplace,
		}
	}

	return infer.DiffResponse{
		DeleteBeforeReplace: true,
		HasChanges:          len(diff) > 0,
		DetailedDiff:        diff,
	}, nil
}

// Check provides input validation and default setting.
func (*Token) Check(ctx context.Context, req infer.CheckRequest) (infer.CheckResponse[TokenArgs], error) {
	p.GetLogger(ctx).Debugf("Check:Token old=%s, new=%s", req.OldInputs.GoString(), req.NewInputs.GoString())
	args, failures, err := infer.DefaultCheck[TokenArgs](ctx, req.NewInputs)

	// Validate expiresIn range (1-365 days)
	if args.ExpiresIn < 1 || args.ExpiresIn > 365 {
		failures = append(failures, p.CheckFailure{
			Property: "expiresIn",
			Reason:   "expiresIn must be between 1 and 365 days",
		})
	}

	return infer.CheckResponse[TokenArgs]{
		Inputs:   args,
		Failures: failures,
	}, err
}

// WireDependencies explicitly defines input/output relationships.
func (*Token) WireDependencies(field infer.FieldSelector, args *TokenArgs, state *TokenState) {
	field.OutputField(&state.UserID).DependsOn(field.InputField(&args.UserID))
	field.OutputField(&state.Name).DependsOn(field.InputField(&args.Name))
	field.OutputField(&state.ExpiresIn).DependsOn(field.InputField(&args.ExpiresIn))
}
