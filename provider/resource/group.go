package resource

import (
	"context"
	"fmt"

	"github.com/excavador/pulumi-netbird/provider/config"
	nbapi "github.com/netbirdio/netbird/shared/management/http/api"
	p "github.com/pulumi/pulumi-go-provider"
	"github.com/pulumi/pulumi-go-provider/infer"
)

// TEST: InputDiff: false

// Group represents a resource for managing NetBird groups.
type Group struct{}

// Annotate adds a description to the Group resource type.
func (g *Group) Annotate(a infer.Annotator) {
	a.Describe(&g, "A NetBird group, which represents a collection of peers.")
}

// GroupArgs defines input fields for creating or updating a group.
type GroupArgs struct {
	Name string `pulumi:"name"`
}

// Annotate provides documentation for GroupArgs fields.
func (g *GroupArgs) Annotate(a infer.Annotator) {
	a.Describe(&g.Name, "The name of the NetBird group.")
}

// GroupState represents the output state of a group resource.
type GroupState struct {
	GroupArgs
}

// Create creates a new NetBird group.
func (*Group) Create(ctx context.Context, req infer.CreateRequest[GroupArgs]) (infer.CreateResponse[GroupState], error) {
	p.GetLogger(ctx).Debugf("Create:Group name=%s", req.Inputs.Name)

	if req.DryRun {
		return infer.CreateResponse[GroupState]{
			ID: "preview",
			Output: GroupState{
				GroupArgs: req.Inputs,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.CreateResponse[GroupState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	var emptyResources []nbapi.Resource

	group, err := client.Groups.Create(ctx, nbapi.GroupRequest{
		Name:      req.Inputs.Name,
		Peers:     nil, // Explicitly nil - peers are managed dynamically, not via IaC (exhaustruct requires field)
		Resources: &emptyResources,
	})
	if err != nil {
		return infer.CreateResponse[GroupState]{}, fmt.Errorf("creating group failed: %w", err)
	}

	p.GetLogger(ctx).Debugf("Create:GroupAPI name=%s, id=%s", group.Name, group.Id)

	state := GroupState{
		GroupArgs: req.Inputs,
	}

	return infer.CreateResponse[GroupState]{
		ID:     group.Id,
		Output: state,
	}, nil
}

// Read fetches the current state of a group resource from NetBird.
func (*Group) Read(ctx context.Context, groupID string, state GroupState) (GroupState, error) {
	p.GetLogger(ctx).Debugf("Read:Group id=%s", groupID)

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return state, fmt.Errorf("error getting NetBird client: %w", err)
	}

	group, err := client.Groups.Get(ctx, groupID)
	if err != nil {
		return state, fmt.Errorf("reading group failed: %w", err)
	}

	p.GetLogger(ctx).Debugf("Read:GroupAPI name=%s, id=%s", group.Name, group.Id)

	state.Name = group.Name

	return state, nil
}

// Update updates the state of the group if needed.
func (*Group) Update(ctx context.Context, req infer.UpdateRequest[GroupArgs, GroupState]) (infer.UpdateResponse[GroupState], error) {
	p.GetLogger(ctx).Debugf("Update:Group[%s] name=%s", req.ID, req.Inputs.Name)

	if req.DryRun {
		return infer.UpdateResponse[GroupState]{
			Output: GroupState{
				GroupArgs: req.Inputs,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.UpdateResponse[GroupState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	var emptyResources []nbapi.Resource

	_, err = client.Groups.Update(ctx, req.ID, nbapi.GroupRequest{
		Name:      req.Inputs.Name,
		Peers:     nil, // Explicitly nil - peers are managed dynamically, not via IaC (exhaustruct requires field)
		Resources: &emptyResources,
	})
	if err != nil {
		return infer.UpdateResponse[GroupState]{}, fmt.Errorf("updating group failed: %w", err)
	}

	out := req.State
	out.Name = req.Inputs.Name

	return infer.UpdateResponse[GroupState]{Output: out}, nil
}

// Delete removes a group from NetBird.
func (*Group) Delete(ctx context.Context, req infer.DeleteRequest[GroupState]) (infer.DeleteResponse, error) {
	p.GetLogger(ctx).Debugf("Delete:Group[%s]", req.ID)

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	err = client.Groups.Delete(ctx, req.ID)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("deleting group failed: %w", err)
	}

	return infer.DeleteResponse{}, nil
}
