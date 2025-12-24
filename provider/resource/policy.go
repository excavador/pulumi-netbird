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

// debugNilStr is used for debug logging when a value is nil.
const debugNilStr = "nil"

// Policy defines the Pulumi resource handler for NetBird policy resources.
type Policy struct{}

// Annotate adds a description annotation for the Policy type for generated SDKs.
func (policy *Policy) Annotate(annotator infer.Annotator) {
	annotator.Describe(policy, "A NetBird policy defining rules for communication between peers.")
}

// PolicyArgs defines the user-supplied arguments for creating/updating a Policy resource.
// NOTE: NetBird API has a bug where it silently drops all rules except the first one.
// Therefore, this resource explicitly supports only a single rule per policy.
// If you need multiple protocols (e.g., TCP and UDP for DNS), create separate policies.
type PolicyArgs struct {
	Name                string         `pulumi:"name"`                    // Policy name (required)
	Description         *string        `pulumi:"description,optional"`    // Optional description
	Enabled             bool           `pulumi:"enabled"`                 // Whether the policy is enabled
	Rule                PolicyRuleArgs `pulumi:"rule"`                    // Single rule for the policy (NetBird API limitation)
	SourcePostureChecks *[]string      `pulumi:"posture_checks,optional"` // Optional list of posture check IDs
}

// Annotate adds field descriptions to PolicyArgs for generated SDKs.
func (policy *PolicyArgs) Annotate(annotator infer.Annotator) {
	annotator.Describe(&policy.Name, "Name Policy name identifier")
	annotator.Describe(&policy.Description, "Description Policy friendly description, optional")
	annotator.Describe(&policy.Enabled, "Enabled Policy status")
	annotator.Describe(&policy.Rule, "Rule Policy rule definition (single rule per policy due to NetBird API limitation)")
	annotator.Describe(&policy.SourcePostureChecks, "SourcePostureChecks Posture checks ID's applied to policy source groups, optional")
}

// PolicyState represents the state of a Policy resource stored in Pulumi state.
// NOTE: NetBird API only supports a single rule per policy (see PolicyArgs comment).
type PolicyState struct {
	Name                string          `pulumi:"name"`
	Description         *string         `pulumi:"description,optional"`
	Enabled             bool            `pulumi:"enabled"`
	Rule                PolicyRuleState `pulumi:"rule"`
	SourcePostureChecks *[]string       `pulumi:"posture_checks,optional"`
}

// Annotate adds descriptive annotations to the PolicyState fields for use in generated SDKs.
func (policy *PolicyState) Annotate(annotator infer.Annotator) {
	annotator.Describe(&policy.Name, "Name Policy name identifier")
	annotator.Describe(&policy.Description, "Description Policy friendly description, optional")
	annotator.Describe(&policy.Enabled, "Enabled Policy status")
	annotator.Describe(&policy.Rule, "Rule Policy rule definition (single rule per policy due to NetBird API limitation)")
	annotator.Describe(&policy.SourcePostureChecks, "SourcePostureChecks Posture checks ID's applied to policy source groups, optional")
}

// PolicyRuleArgs represents user input for an individual rule in a policy.
type PolicyRuleArgs struct {
	ID                  *string          `pulumi:"id,optional"`                  // Optional rule ID (used for updates)
	Name                string           `pulumi:"name"`                         // Rule name
	Description         *string          `pulumi:"description,optional"`         // Optional rule description
	Bidirectional       bool             `pulumi:"bidirectional"`                // Whether the rule is bidirectional
	Action              RuleAction       `pulumi:"action"`                       // Rule action (accept/drop)
	Enabled             bool             `pulumi:"enabled"`                      // Whether the rule is enabled
	Protocol            Protocol         `pulumi:"protocol"`                     // Network protocol
	Ports               *[]string        `pulumi:"ports,optional"`               // Optional list of specific ports
	PortRanges          *[]RulePortRange `pulumi:"portRanges,optional"`          // Optional list of port ranges
	Sources             *[]string        `pulumi:"sources,optional"`             // Optional list of source group IDs
	Destinations        *[]string        `pulumi:"destinations,optional"`        // Optional list of destination group IDs
	SourceResource      *Resource        `pulumi:"sourceResource,optional"`      // Optional single source resource
	DestinationResource *Resource        `pulumi:"destinationResource,optional"` // Optional single destination resource
}

// Annotate adds descriptive annotations to the PolicyRuleArgs fields for use in generated SDKs.
func (policy *PolicyRuleArgs) Annotate(annotator infer.Annotator) {
	annotator.Describe(&policy.ID, "ID Policy rule.")
	annotator.Describe(&policy.Name, "Name Policy rule name identifier")
	annotator.Describe(&policy.Description, "Description Policy rule friendly description")
	annotator.Describe(&policy.Bidirectional, "Bidirectional Define if the rule is applicable in both directions, sources, and destinations.")
	annotator.Describe(&policy.Action, "Action Policy rule accept or drops packets")
	annotator.Describe(&policy.Enabled, "Enabled Policy rule status")
	annotator.Describe(&policy.Protocol, "Protocol Policy rule type of the traffic")
	annotator.Describe(&policy.Ports, "Ports Policy rule affected ports")
	annotator.Describe(&policy.PortRanges, "PortRanges Policy rule affected ports ranges list")
	annotator.Describe(&policy.Sources, "Sources Policy rule source group IDs")
	annotator.Describe(&policy.Destinations, "Destinations Policy rule destination group IDs")
	annotator.Describe(&policy.SourceResource, "SourceResource for the rule")
	annotator.Describe(&policy.DestinationResource, "DestinationResource for the rule ")
}

// PolicyRuleState represents the state of an individual rule within a policy.
// Note: Sources and Destinations are stored as string IDs (matching PolicyRuleArgs)
// to prevent phantom diffs when Pulumi compares state vs inputs.
type PolicyRuleState struct {
	ID                  *string          `pulumi:"id,optional"`
	Name                string           `pulumi:"name"`
	Description         *string          `pulumi:"description,optional"`
	Bidirectional       bool             `pulumi:"bidirectional"`
	Action              RuleAction       `pulumi:"action"`
	Enabled             bool             `pulumi:"enabled"`
	Protocol            Protocol         `pulumi:"protocol"`
	Ports               *[]string        `pulumi:"ports,optional"`
	PortRanges          *[]RulePortRange `pulumi:"portRanges,optional"`
	Sources             *[]string        `pulumi:"sources,optional"`      // Group IDs (same type as inputs)
	Destinations        *[]string        `pulumi:"destinations,optional"` // Group IDs (same type as inputs)
	SourceResource      *Resource        `pulumi:"sourceResource,optional"`
	DestinationResource *Resource        `pulumi:"destinationResource,optional"`
}

// Annotate adds descriptive annotations to the PolicyRuleState fields for use in generated SDKs.
func (policy *PolicyRuleState) Annotate(annotator infer.Annotator) {
	annotator.Describe(&policy.ID, "ID Policy rule.")
	annotator.Describe(&policy.Name, "Name Policy rule name identifier")
	annotator.Describe(&policy.Description, "Description Policy rule friendly description")
	annotator.Describe(&policy.Bidirectional, "Bidirectional Define if the rule is applicable in both directions, sources, and destinations.")
	annotator.Describe(&policy.Action, "Action Policy rule accept or drops packets")
	annotator.Describe(&policy.Enabled, "Enabled Policy rule status")
	annotator.Describe(&policy.Protocol, "Protocol Policy rule type of the traffic")
	annotator.Describe(&policy.Ports, "Ports Policy rule affected ports")
	annotator.Describe(&policy.PortRanges, "PortRanges Policy rule affected ports ranges list")
	annotator.Describe(&policy.Sources, "Sources Policy rule source group IDs")
	annotator.Describe(&policy.Destinations, "Destinations Policy rule destination group IDs")
	annotator.Describe(&policy.SourceResource, "SourceResource for the rule")
	annotator.Describe(&policy.DestinationResource, "DestinationResource for the rule ")
}

// RulePortRange type.
type RulePortRange struct {
	Start int `pulumi:"start"`
	End   int `pulumi:"end"`
}

// Annotate adds descriptive annotations to the RulePortRange fields for use in generated SDKs.
func (r *RulePortRange) Annotate(a infer.Annotator) {
	a.Describe(&r.Start, "Start of port range")
	a.Describe(&r.End, "End of port range")
}

// RuleAction defines the allowed actions for a rule (accept/drop).
// This wraps the nbapi type to allow method definitions (like Values()).
type RuleAction string

// RuleActi2yyonAccept and RuleActionDrop represent possible actions for a policy rule.
// RuleActionAccept allows traffic, while RuleActionDrop blocks traffic.
const (
	RuleActionAccept RuleAction = RuleAction(nbapi.PolicyRuleActionAccept)
	RuleActionDrop   RuleAction = RuleAction(nbapi.PolicyRuleActionDrop)
)

// Values returns the valid enum values for RuleAction, used by Pulumi for schema generation and validation.
func (RuleAction) Values() []infer.EnumValue[RuleAction] {
	return []infer.EnumValue[RuleAction]{
		{Name: "Accept", Value: RuleActionAccept, Description: "Accept action"},
		{Name: "Drop", Value: RuleActionDrop, Description: "Drop action"},
	}
}

// Protocol defines the allowed network protocols for a policy rule.
type Protocol string

// Enum constants for supported network protocols.
const (
	ProtocolAll  Protocol = Protocol(nbapi.PolicyRuleProtocolAll)
	ProtocolIcmp Protocol = Protocol(nbapi.PolicyRuleProtocolIcmp)
	ProtocolTCP  Protocol = Protocol(nbapi.PolicyRuleProtocolTcp)
	ProtocolUDP  Protocol = Protocol(nbapi.PolicyRuleProtocolUdp)
)

// Values returns valid protocol values for Pulumi enum support.
func (Protocol) Values() []infer.EnumValue[Protocol] {
	return []infer.EnumValue[Protocol]{
		{Name: "All", Value: ProtocolAll, Description: "All protocols"},
		{Name: "ICMP", Value: ProtocolIcmp, Description: "ICMP protocol"},
		{Name: "TCP", Value: ProtocolTCP, Description: "TCP protocol"},
		{Name: "UDP", Value: ProtocolUDP, Description: "UDP protocol"},
	}
}

// Create creates a new NetBird policy.
// NOTE: NetBird API only supports a single rule per policy.
func (*Policy) Create(ctx context.Context, req infer.CreateRequest[PolicyArgs]) (infer.CreateResponse[PolicyState], error) {
	p.GetLogger(ctx).Debugf("Create:Policy")

	rule := req.Inputs.Rule

	// Handle dry-run (preview) mode by constructing a preview PolicyState.
	if req.DryRun {
		return infer.CreateResponse[PolicyState]{
			ID: "preview",
			Output: PolicyState{
				Name:                req.Inputs.Name,
				Description:         req.Inputs.Description,
				Enabled:             req.Inputs.Enabled,
				Rule:                buildPreviewRuleState(rule),
				SourcePostureChecks: req.Inputs.SourcePostureChecks,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.CreateResponse[PolicyState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	// Convert single rule to API format (wrapped in slice for API compatibility)
	apiRule := nbapi.PolicyRuleUpdate{
		Id:                  rule.ID,
		Name:                rule.Name,
		Description:         rule.Description,
		Bidirectional:       rule.Bidirectional,
		Action:              nbapi.PolicyRuleUpdateAction(rule.Action),
		Enabled:             rule.Enabled,
		Protocol:            nbapi.PolicyRuleUpdateProtocol(rule.Protocol),
		Ports:               rule.Ports,
		PortRanges:          toAPIPortRanges(rule.PortRanges),
		Sources:             rule.Sources,
		Destinations:        rule.Destinations,
		SourceResource:      toAPIResource(rule.SourceResource),
		DestinationResource: toAPIResource(rule.DestinationResource),
	}

	p.GetLogger(ctx).Debugf("Create:Policy: Name=%s Rule.Name=%s Rule.Protocol=%s", req.Inputs.Name, rule.Name, rule.Protocol)

	created, err := client.Policies.Create(ctx, nbapi.PolicyUpdate{
		Name:                req.Inputs.Name,
		Description:         req.Inputs.Description,
		Enabled:             req.Inputs.Enabled,
		Rules:               []nbapi.PolicyRuleUpdate{apiRule},
		SourcePostureChecks: req.Inputs.SourcePostureChecks,
	})
	if err != nil {
		return infer.CreateResponse[PolicyState]{}, fmt.Errorf("creating policy failed: %w", err)
	}

	// Fail-fast: NetBird API must return exactly 1 rule
	if len(created.Rules) != 1 {
		return infer.CreateResponse[PolicyState]{}, fmt.Errorf(
			"NetBird API returned %d rules, expected exactly 1 (policy: %s)",
			len(created.Rules), req.Inputs.Name,
		)
	}

	apiReturnedRule := created.Rules[0]
	p.GetLogger(ctx).Debugf("Create:Policy: API returned rule ID=%s Name=%s Protocol=%s",
		*apiReturnedRule.Id, apiReturnedRule.Name, apiReturnedRule.Protocol)

	// Convert API response to PolicyRuleState
	ruleState := PolicyRuleState{
		ID:                  apiReturnedRule.Id,
		Name:                apiReturnedRule.Name,
		Description:         apiReturnedRule.Description,
		Bidirectional:       apiReturnedRule.Bidirectional,
		Action:              RuleAction(apiReturnedRule.Action),
		Enabled:             apiReturnedRule.Enabled,
		Protocol:            Protocol(apiReturnedRule.Protocol),
		Ports:               apiReturnedRule.Ports,
		PortRanges:          fromAPIPortRanges(apiReturnedRule.PortRanges),
		Sources:             groupMinimumsToIDs(apiReturnedRule.Sources),
		Destinations:        groupMinimumsToIDs(apiReturnedRule.Destinations),
		SourceResource:      fromAPIResource(apiReturnedRule.SourceResource),
		DestinationResource: fromAPIResource(apiReturnedRule.DestinationResource),
	}

	return infer.CreateResponse[PolicyState]{
		ID: *created.Id,
		Output: PolicyState{
			Name:                created.Name,
			Description:         created.Description,
			Enabled:             created.Enabled,
			Rule:                ruleState,
			SourcePostureChecks: &created.SourcePostureChecks,
		},
	}, nil
}

// Read reads a Policy from NetBird.
// NOTE: NetBird API only supports a single rule per policy.
func (*Policy) Read(ctx context.Context, req infer.ReadRequest[PolicyArgs, PolicyState]) (infer.ReadResponse[PolicyArgs, PolicyState], error) {
	p.GetLogger(ctx).Debugf("Read:Policy[%s]", req.ID)

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.ReadResponse[PolicyArgs, PolicyState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	policy, err := client.Policies.Get(ctx, req.ID)
	if err != nil {
		return infer.ReadResponse[PolicyArgs, PolicyState]{}, fmt.Errorf("reading policy failed: %w", err)
	}

	// Fail-fast: NetBird API must return exactly 1 rule
	if len(policy.Rules) != 1 {
		return infer.ReadResponse[PolicyArgs, PolicyState]{}, fmt.Errorf(
			"NetBird API returned %d rules, expected exactly 1 (policy: %s)",
			len(policy.Rules), req.ID,
		)
	}

	rule := policy.Rules[0]

	// Log what API returns for debugging
	apiSourcesStr := formatSliceForDebug(rule.Sources)
	p.GetLogger(ctx).Debugf("Read:Policy[%s] API returned Rule: Name=%s Sources=%s", req.ID, rule.Name, apiSourcesStr)

	// Convert API groups to string IDs (same format as inputs to avoid phantom diffs)
	sourceIDs := groupMinimumsToIDs(rule.Sources)
	destIDs := groupMinimumsToIDs(rule.Destinations)

	// Build state (with string IDs - same type as inputs)
	ruleState := PolicyRuleState{
		ID:                  rule.Id,
		Name:                rule.Name,
		Description:         rule.Description,
		Bidirectional:       rule.Bidirectional,
		Action:              RuleAction(rule.Action),
		Enabled:             rule.Enabled,
		Protocol:            Protocol(rule.Protocol),
		Ports:               rule.Ports,
		PortRanges:          fromAPIPortRanges(rule.PortRanges),
		Sources:             sourceIDs,
		Destinations:        destIDs,
		SourceResource:      fromAPIResource(rule.SourceResource),
		DestinationResource: fromAPIResource(rule.DestinationResource),
	}

	// Build inputs (same as state, without rule ID)
	inputRule := PolicyRuleArgs{
		ID:                  nil, // Don't include rule ID in inputs
		Name:                rule.Name,
		Description:         rule.Description,
		Bidirectional:       rule.Bidirectional,
		Action:              RuleAction(rule.Action),
		Enabled:             rule.Enabled,
		Protocol:            Protocol(rule.Protocol),
		Ports:               rule.Ports,
		PortRanges:          fromAPIPortRanges(rule.PortRanges),
		Sources:             sourceIDs,
		Destinations:        destIDs,
		SourceResource:      fromAPIResource(rule.SourceResource),
		DestinationResource: fromAPIResource(rule.DestinationResource),
	}

	return infer.ReadResponse[PolicyArgs, PolicyState]{
		ID: req.ID,
		Inputs: PolicyArgs{
			Name:                policy.Name,
			Description:         policy.Description,
			Enabled:             policy.Enabled,
			Rule:                inputRule,
			SourcePostureChecks: &policy.SourcePostureChecks,
		},
		State: PolicyState{
			Name:                policy.Name,
			Description:         policy.Description,
			Enabled:             policy.Enabled,
			Rule:                ruleState,
			SourcePostureChecks: &policy.SourcePostureChecks,
		},
	}, nil
}

// Update updates an existing NetBird policy.
// NOTE: NetBird API only supports a single rule per policy.
func (*Policy) Update(ctx context.Context, req infer.UpdateRequest[PolicyArgs, PolicyState]) (infer.UpdateResponse[PolicyState], error) {
	p.GetLogger(ctx).Debugf("Update:Policy[%s]", req.ID)

	rule := req.Inputs.Rule

	if req.DryRun {
		return infer.UpdateResponse[PolicyState]{
			Output: PolicyState{
				Name:                req.Inputs.Name,
				Description:         req.Inputs.Description,
				Enabled:             req.Inputs.Enabled,
				Rule:                buildPreviewRuleState(rule),
				SourcePostureChecks: req.Inputs.SourcePostureChecks,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.UpdateResponse[PolicyState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	// Build API rule, preserving rule ID from state if available
	apiRule := buildAPIRuleForUpdate(rule, req.State.Rule)

	p.GetLogger(ctx).Debugf("Update:Policy[%s]: Rule.Name=%s Rule.Protocol=%s", req.ID, rule.Name, rule.Protocol)

	updated, err := client.Policies.Update(ctx, req.ID, nbapi.PolicyCreate{
		Name:                req.Inputs.Name,
		Description:         req.Inputs.Description,
		Enabled:             req.Inputs.Enabled,
		Rules:               []nbapi.PolicyRuleUpdate{apiRule},
		SourcePostureChecks: req.Inputs.SourcePostureChecks,
	})
	if err != nil {
		return infer.UpdateResponse[PolicyState]{}, fmt.Errorf("updating policy failed: %w", err)
	}

	// Fail-fast: NetBird API must return exactly 1 rule
	if len(updated.Rules) != 1 {
		return infer.UpdateResponse[PolicyState]{}, fmt.Errorf(
			"NetBird API returned %d rules, expected exactly 1 (policy: %s)",
			len(updated.Rules), req.ID,
		)
	}

	apiReturnedRule := updated.Rules[0]
	ruleState := buildRuleStateFromAPIResponse(ctx, req.ID, apiReturnedRule, rule)

	return infer.UpdateResponse[PolicyState]{
		Output: PolicyState{
			Name:                updated.Name,
			Description:         updated.Description,
			Enabled:             updated.Enabled,
			Rule:                ruleState,
			SourcePostureChecks: &updated.SourcePostureChecks,
		},
	}, nil
}

// Delete removes a Policy from NetBird.
func (*Policy) Delete(ctx context.Context, req infer.DeleteRequest[PolicyState]) (infer.DeleteResponse, error) {
	p.GetLogger(ctx).Debugf("Delete:Policy[%s]", req.ID)

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	err = client.Policies.Delete(ctx, req.ID)
	if err != nil {
		return infer.DeleteResponse{}, fmt.Errorf("deleting policy failed: %w", err)
	}

	return infer.DeleteResponse{}, nil
}

// Diff detects changes between inputs and prior state.
func (*Policy) Diff(ctx context.Context, req infer.DiffRequest[PolicyArgs, PolicyState]) (infer.DiffResponse, error) {
	p.GetLogger(ctx).Debugf("Diff:Policy[%s]", req.ID)

	diff := map[string]p.PropertyDiff{}

	if req.Inputs.Name != req.State.Name {
		diff["name"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.Update,
		}
	}

	if strPtr(req.Inputs.Description) != strPtr(req.State.Description) {
		diff["description"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.Update,
		}
	}

	if req.Inputs.Enabled != req.State.Enabled {
		diff["enabled"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.Update,
		}
	}
	// Rule Diff (single rule)
	input := req.Inputs.Rule
	state := req.State.Rule

	p.GetLogger(ctx).Debugf("Diff:Policy[%s]:Rule input=%+v state=%+v", req.ID, input, state)

	// Log actual values being compared for debugging
	inputSourcesStr := formatStringSliceForDebug(input.Sources)
	stateSourcesStr := formatStringSliceForDebug(state.Sources)

	p.GetLogger(ctx).Debugf("Diff:Policy[%s]:Rule Sources - input=%s state=%s equal=%v",
		req.ID, inputSourcesStr, stateSourcesStr, equalSlicePtr(input.Sources, state.Sources))

	inputDestsStr := formatStringSliceForDebug(input.Destinations)
	stateDestsStr := formatStringSliceForDebug(state.Destinations)

	p.GetLogger(ctx).Debugf("Diff:Policy[%s]:Rule Destinations - input=%s state=%s equal=%v",
		req.ID, inputDestsStr, stateDestsStr, equalSlicePtr(input.Destinations, state.Destinations))

	// Compare all fields except rule ID (which is API-managed and not part of user inputs)
	// Note: input.ID may be nil (from Read) or set (from user), but we ignore it in comparison
	// Sources and Destinations are now both *[]string, so direct comparison works
	if input.Name != state.Name ||
		!equalPtr(input.Description, state.Description) ||
		input.Bidirectional != state.Bidirectional ||
		input.Action != state.Action ||
		input.Enabled != state.Enabled ||
		input.Protocol != state.Protocol ||
		!equalSlicePtr(input.Ports, state.Ports) ||
		!equalPortRangePtr(input.PortRanges, state.PortRanges) ||
		!equalSlicePtr(input.Sources, state.Sources) ||
		!equalSlicePtr(input.Destinations, state.Destinations) ||
		!equalResourcePtr(input.SourceResource, state.SourceResource) ||
		!equalResourcePtr(input.DestinationResource, state.DestinationResource) {

		p.GetLogger(ctx).Debugf("Diff:Policy[%s]:Rule differs - Name:%v Desc:%v Bidir:%v Action:%v Enabled:%v Protocol:%v Ports:%v PortRanges:%v Sources:%v Destinations:%v SrcRes:%v DstRes:%v",
			req.ID,
			input.Name != state.Name,
			!equalPtr(input.Description, state.Description),
			input.Bidirectional != state.Bidirectional,
			input.Action != state.Action,
			input.Enabled != state.Enabled,
			input.Protocol != state.Protocol,
			!equalSlicePtr(input.Ports, state.Ports),
			!equalPortRangePtr(input.PortRanges, state.PortRanges),
			!equalSlicePtr(input.Sources, state.Sources),
			!equalSlicePtr(input.Destinations, state.Destinations),
			!equalResourcePtr(input.SourceResource, state.SourceResource),
			!equalResourcePtr(input.DestinationResource, state.DestinationResource))

		diff["rule"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.Update,
		}
	}

	if !equalSlicePtr(req.Inputs.SourcePostureChecks, req.State.SourcePostureChecks) {
		diff["postureChecks"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.Update,
		}
	}

	p.GetLogger(ctx).Debugf("Diff:Policy[%s] diff=%d", req.ID, len(diff))

	return infer.DiffResponse{
		DeleteBeforeReplace: false,
		HasChanges:          len(diff) > 0,
		DetailedDiff:        diff,
	}, nil
}

// Check provides input validation and default setting.
func (*Policy) Check(ctx context.Context, req infer.CheckRequest) (infer.CheckResponse[PolicyArgs], error) {
	p.GetLogger(ctx).Debugf("Check:Policy old=%s, new=%s", req.OldInputs.GoString(), req.NewInputs.GoString())
	args, failures, err := infer.DefaultCheck[PolicyArgs](ctx, req.NewInputs)

	return infer.CheckResponse[PolicyArgs]{
		Inputs:   args,
		Failures: failures,
	}, err
}

// WireDependencies explicitly defines input/output relationships.
func (*Policy) WireDependencies(f infer.FieldSelector, args *PolicyArgs, state *PolicyState) {
	f.OutputField(&state.Name).DependsOn(f.InputField(&args.Name))
	f.OutputField(&state.Description).DependsOn(f.InputField(&args.Description))
	f.OutputField(&state.Enabled).DependsOn(f.InputField(&args.Enabled))
	f.OutputField(&state.Rule).DependsOn(f.InputField(&args.Rule))
	f.OutputField(&state.SourcePostureChecks).DependsOn(f.InputField(&args.SourcePostureChecks))
}

// Converts a slice of RulePortRange from state model to API model.
func toAPIPortRanges(rulePortRange *[]RulePortRange) *[]nbapi.RulePortRange {
	if rulePortRange == nil {
		return nil
	}

	out := make([]nbapi.RulePortRange, len(*rulePortRange))
	for rulePRIndex, rulePR := range *rulePortRange {
		out[rulePRIndex] = nbapi.RulePortRange{Start: rulePR.Start, End: rulePR.End}
	}

	return &out
}

// Converts a slice of API RulePortRange to state model.
func fromAPIPortRanges(reulePortRangeAPI *[]nbapi.RulePortRange) *[]RulePortRange {
	if reulePortRangeAPI == nil {
		return nil
	}

	out := make([]RulePortRange, len(*reulePortRangeAPI))
	for rulePRIndex, rulePR := range *reulePortRangeAPI {
		out[rulePRIndex] = RulePortRange{Start: rulePR.Start, End: rulePR.End}
	}

	return &out
}

// groupMinimumsToIDs converts a slice of nbapi.GroupMinimum to string IDs.
// This is used to store state in the same format as inputs (preventing phantom diffs).
func groupMinimumsToIDs(groups *[]nbapi.GroupMinimum) *[]string {
	if groups == nil {
		return nil
	}

	ids := make([]string, len(*groups))
	for i, g := range *groups {
		ids[i] = g.Id
	}

	return &ids
}

func equalPortRangePtr(portRangeA, portRangeB *[]RulePortRange) bool {
	if portRangeA == nil && portRangeB == nil {
		return true
	}

	if portRangeA == nil || portRangeB == nil || len(*portRangeA) != len(*portRangeB) {
		return false
	}

	for i := range *portRangeA {
		if (*portRangeA)[i] != (*portRangeB)[i] {
			return false
		}
	}

	return true
}

// formatSliceForDebug formats a GroupMinimum slice for debug logging.
func formatSliceForDebug(groups *[]nbapi.GroupMinimum) string {
	switch {
	case groups == nil:
		return debugNilStr
	case len(*groups) == 0:
		return "[]"
	default:
		return fmt.Sprintf("%v", *groups)
	}
}

// formatStringSliceForDebug formats a string slice for debug logging.
func formatStringSliceForDebug(slice *[]string) string {
	if slice == nil {
		return debugNilStr
	}

	return fmt.Sprintf("%v", *slice)
}

// buildPreviewRuleState constructs PolicyRuleState for dry-run/preview mode.
func buildPreviewRuleState(rule PolicyRuleArgs) PolicyRuleState {
	// For preview, just copy the string IDs directly (state uses same type as inputs)
	return PolicyRuleState{
		ID:                  rule.ID,
		Name:                rule.Name,
		Description:         rule.Description,
		Bidirectional:       rule.Bidirectional,
		Action:              rule.Action,
		Enabled:             rule.Enabled,
		Protocol:            rule.Protocol,
		Ports:               rule.Ports,
		PortRanges:          rule.PortRanges,
		Sources:             rule.Sources,      // Same type, direct copy
		Destinations:        rule.Destinations, // Same type, direct copy
		SourceResource:      rule.SourceResource,
		DestinationResource: rule.DestinationResource,
	}
}

// buildAPIRuleForUpdate converts input rule to API format for update.
func buildAPIRuleForUpdate(inputRule PolicyRuleArgs, stateRule PolicyRuleState) nbapi.PolicyRuleUpdate {
	ruleID := inputRule.ID
	// If rule ID not in inputs, try to get it from state (for existing rule)
	if ruleID == nil {
		ruleID = stateRule.ID
	}

	return nbapi.PolicyRuleUpdate{
		Id:                  ruleID,
		Name:                inputRule.Name,
		Description:         inputRule.Description,
		Bidirectional:       inputRule.Bidirectional,
		Action:              nbapi.PolicyRuleUpdateAction(inputRule.Action),
		Enabled:             inputRule.Enabled,
		Protocol:            nbapi.PolicyRuleUpdateProtocol(inputRule.Protocol),
		Ports:               inputRule.Ports,
		PortRanges:          toAPIPortRanges(inputRule.PortRanges),
		Sources:             inputRule.Sources,
		Destinations:        inputRule.Destinations,
		SourceResource:      toAPIResource(inputRule.SourceResource),
		DestinationResource: toAPIResource(inputRule.DestinationResource),
	}
}

// buildRuleStateFromAPIResponse converts API response rule to PolicyRuleState.
func buildRuleStateFromAPIResponse(
	ctx context.Context,
	policyID string,
	apiRule nbapi.PolicyRule,
	inputRule PolicyRuleArgs,
) PolicyRuleState {
	apiSourcesStr := formatSliceForDebug(apiRule.Sources)
	p.GetLogger(ctx).Debugf("Update:Policy[%s]:Rule API returned Sources=%s after update", policyID, apiSourcesStr)

	sources := reconstructIDsFromAPISingle(ctx, policyID, apiRule.Sources, inputRule.Sources, "Sources")
	destinations := reconstructIDsFromAPISingle(ctx, policyID, apiRule.Destinations, inputRule.Destinations, "Destinations")

	return PolicyRuleState{
		ID:                  apiRule.Id,
		Name:                apiRule.Name,
		Description:         apiRule.Description,
		Bidirectional:       apiRule.Bidirectional,
		Action:              RuleAction(apiRule.Action),
		Enabled:             apiRule.Enabled,
		Protocol:            Protocol(apiRule.Protocol),
		Ports:               apiRule.Ports,
		PortRanges:          fromAPIPortRanges(apiRule.PortRanges),
		Sources:             sources,
		Destinations:        destinations,
		SourceResource:      fromAPIResource(apiRule.SourceResource),
		DestinationResource: fromAPIResource(apiRule.DestinationResource),
	}
}

// reconstructIDsFromAPISingle handles the case where API returns nil but we sent groups.
// Returns string IDs (same as inputs).
func reconstructIDsFromAPISingle(
	ctx context.Context,
	policyID string,
	apiGroups *[]nbapi.GroupMinimum,
	inputIDs *[]string,
	fieldName string,
) *[]string {
	ids := groupMinimumsToIDs(apiGroups)
	if ids == nil && inputIDs != nil {
		// API returned nil but we sent groups - use input IDs
		idsCopy := make([]string, len(*inputIDs))
		copy(idsCopy, *inputIDs)
		ids = &idsCopy

		p.GetLogger(ctx).Debugf("Update:Policy[%s]:Rule reconstructed %s from inputs (API returned nil)", policyID, fieldName)
	}

	return ids
}
