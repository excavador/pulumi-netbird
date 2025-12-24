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
type PolicyArgs struct {
	Name                string           `pulumi:"name"`                    // Policy name (required)
	Description         *string          `pulumi:"description,optional"`    // Optional description
	Enabled             bool             `pulumi:"enabled"`                 // Whether the policy is enabled
	Rules               []PolicyRuleArgs `pulumi:"rules"`                   // List of rules defined in the policy
	SourcePostureChecks *[]string        `pulumi:"posture_checks,optional"` // Optional list of posture check IDs
}

// Annotate adds field descriptions to PolicyArgs for generated SDKs.
func (policy *PolicyArgs) Annotate(annotator infer.Annotator) {
	annotator.Describe(&policy.Name, "Name Policy name identifier")
	annotator.Describe(&policy.Description, "Description Policy friendly description, optional")
	annotator.Describe(&policy.Enabled, "Enabled Policy status")
	annotator.Describe(&policy.Rules, "Rules Policy rule object for policy UI editor")
	annotator.Describe(&policy.SourcePostureChecks, "SourcePostureChecks Posture checks ID's applied to policy source groups, optional")
}

// PolicyState represents the state of a Policy resource stored in Pulumi state.
type PolicyState struct {
	Name                string            `pulumi:"name"`
	Description         *string           `pulumi:"description,optional"`
	Enabled             bool              `pulumi:"enabled"`
	Rules               []PolicyRuleState `pulumi:"rules"`
	SourcePostureChecks *[]string         `pulumi:"posture_checks,optional"`
}

// Annotate adds descriptive annotations to the PolicyState fields for use in generated SDKs.
func (policy *PolicyState) Annotate(annotator infer.Annotator) {
	annotator.Describe(&policy.Name, "Name Policy name identifier")
	annotator.Describe(&policy.Description, "Description Policy friendly description, optional")
	annotator.Describe(&policy.Enabled, "Enabled Policy status")
	annotator.Describe(&policy.Rules, "Rules Policy rule object for policy UI editor")
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
func (*Policy) Create(ctx context.Context, req infer.CreateRequest[PolicyArgs]) (infer.CreateResponse[PolicyState], error) {
	p.GetLogger(ctx).Debugf("Create:Policy")

	// Handle dry-run (preview) mode by constructing a preview PolicyState.
	if req.DryRun {
		rules := buildPreviewRuleStates(req.Inputs.Rules)

		return infer.CreateResponse[PolicyState]{
			ID: "preview",
			Output: PolicyState{
				Name:                req.Inputs.Name,
				Description:         req.Inputs.Description,
				Enabled:             req.Inputs.Enabled,
				Rules:               rules,
				SourcePostureChecks: req.Inputs.SourcePostureChecks,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.CreateResponse[PolicyState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	// Convert input rules to nbapi.PolicyRuleUpdate
	apiRules := make([]nbapi.PolicyRuleUpdate, len(req.Inputs.Rules))
	for i, rule := range req.Inputs.Rules {
		apiRules[i] = nbapi.PolicyRuleUpdate{
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
	}

	created, err := client.Policies.Create(ctx, nbapi.PolicyUpdate{
		Name:                req.Inputs.Name,
		Description:         req.Inputs.Description,
		Enabled:             req.Inputs.Enabled,
		Rules:               apiRules,
		SourcePostureChecks: req.Inputs.SourcePostureChecks,
	})
	if err != nil {
		return infer.CreateResponse[PolicyState]{}, fmt.Errorf("creating policy failed: %w", err)
	}

	// Convert created rules to PolicyRuleState
	rules := make([]PolicyRuleState, len(created.Rules))
	for ruleIndex, rule := range created.Rules {
		rules[ruleIndex] = PolicyRuleState{
			ID:                  rule.Id,
			Name:                rule.Name,
			Description:         rule.Description,
			Bidirectional:       rule.Bidirectional,
			Action:              RuleAction(rule.Action),
			Enabled:             rule.Enabled,
			Protocol:            Protocol(rule.Protocol),
			Ports:               rule.Ports,
			PortRanges:          fromAPIPortRanges(rule.PortRanges),
			Sources:             groupMinimumsToIDs(rule.Sources),
			Destinations:        groupMinimumsToIDs(rule.Destinations),
			SourceResource:      fromAPIResource(rule.SourceResource),
			DestinationResource: fromAPIResource(rule.DestinationResource),
		}
	}

	return infer.CreateResponse[PolicyState]{
		ID: *created.Id,
		Output: PolicyState{
			Name:                created.Name,
			Description:         created.Description,
			Enabled:             created.Enabled,
			Rules:               rules,
			SourcePostureChecks: &created.SourcePostureChecks,
		},
	}, nil
}

// Read reads a Policy from NetBird.
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

	rules := make([]PolicyRuleState, len(policy.Rules))
	inputRules := make([]PolicyRuleArgs, len(policy.Rules))

	for ruleIndex, rule := range policy.Rules {
		// Log what API returns for debugging
		apiSourcesStr := formatSliceForDebug(rule.Sources)

		p.GetLogger(ctx).Debugf("Read:Policy[%s]:Rules[%d] API returned Sources=%s", req.ID, ruleIndex, apiSourcesStr)

		// Convert API groups to string IDs (same format as inputs to avoid phantom diffs)
		sourceIDs := groupMinimumsToIDs(rule.Sources)
		destIDs := groupMinimumsToIDs(rule.Destinations)

		// Build state (with string IDs - same type as inputs)
		rules[ruleIndex] = PolicyRuleState{
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
		inputRules[ruleIndex] = PolicyRuleArgs{
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
	}

	return infer.ReadResponse[PolicyArgs, PolicyState]{
		ID: req.ID,
		Inputs: PolicyArgs{
			Name:                policy.Name,
			Description:         policy.Description,
			Enabled:             policy.Enabled,
			Rules:               inputRules,
			SourcePostureChecks: &policy.SourcePostureChecks,
		},
		State: PolicyState{
			Name:                policy.Name,
			Description:         policy.Description,
			Enabled:             policy.Enabled,
			Rules:               rules,
			SourcePostureChecks: &policy.SourcePostureChecks,
		},
	}, nil
}

// Update updates an existing NetBird policy.
func (*Policy) Update(ctx context.Context, req infer.UpdateRequest[PolicyArgs, PolicyState]) (infer.UpdateResponse[PolicyState], error) {
	p.GetLogger(ctx).Debugf("Update:Policy[%s]", req.ID)

	if req.DryRun {
		rules := buildPreviewRuleStates(req.Inputs.Rules)

		return infer.UpdateResponse[PolicyState]{
			Output: PolicyState{
				Name:                req.Inputs.Name,
				Description:         req.Inputs.Description,
				Enabled:             req.Inputs.Enabled,
				Rules:               rules,
				SourcePostureChecks: req.Inputs.SourcePostureChecks,
			},
		}, nil
	}

	client, err := config.GetNetBirdClient(ctx)
	if err != nil {
		return infer.UpdateResponse[PolicyState]{}, fmt.Errorf("error getting NetBird client: %w", err)
	}

	apiRules := buildAPIRulesForUpdate(req.Inputs.Rules, req.State.Rules)

	updated, err := client.Policies.Update(ctx, req.ID, nbapi.PolicyCreate{
		Name:                req.Inputs.Name,
		Description:         req.Inputs.Description,
		Enabled:             req.Inputs.Enabled,
		Rules:               apiRules,
		SourcePostureChecks: req.Inputs.SourcePostureChecks,
	})
	if err != nil {
		return infer.UpdateResponse[PolicyState]{}, fmt.Errorf("updating policy failed: %w", err)
	}

	rules := buildRuleStatesFromAPIResponse(ctx, req.ID, updated.Rules, req.Inputs.Rules)

	return infer.UpdateResponse[PolicyState]{
		Output: PolicyState{
			Name:                updated.Name,
			Description:         updated.Description,
			Enabled:             updated.Enabled,
			Rules:               rules,
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
	// Rules Diff
	if len(req.Inputs.Rules) != len(req.State.Rules) {
		diff["rules"] = p.PropertyDiff{
			InputDiff: false,
			Kind:      p.Update,
		}
	} else {
		equal := true

		for ruleIndex := range req.Inputs.Rules {
			input := req.Inputs.Rules[ruleIndex]
			state := req.State.Rules[ruleIndex]

			p.GetLogger(ctx).Debugf("Diff:Policy[%s]:Rules[%d] input=%+v state=%+v", req.ID, ruleIndex, input, state)

			// Log actual values being compared for debugging
			inputSourcesStr := formatStringSliceForDebug(input.Sources)
			stateSourcesStr := formatStringSliceForDebug(state.Sources)

			p.GetLogger(ctx).Debugf("Diff:Policy[%s]:Rules[%d] Sources - input=%s state=%s equal=%v",
				req.ID, ruleIndex, inputSourcesStr, stateSourcesStr, equalSlicePtr(input.Sources, state.Sources))

			inputDestsStr := formatStringSliceForDebug(input.Destinations)
			stateDestsStr := formatStringSliceForDebug(state.Destinations)

			p.GetLogger(ctx).Debugf("Diff:Policy[%s]:Rules[%d] Destinations - input=%s state=%s equal=%v",
				req.ID, ruleIndex, inputDestsStr, stateDestsStr, equalSlicePtr(input.Destinations, state.Destinations))

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
				equal = false

				p.GetLogger(ctx).Debugf("Diff:Policy[%s]:Rules[%d] differs - Name:%v Desc:%v Bidir:%v Action:%v Enabled:%v Protocol:%v Ports:%v PortRanges:%v Sources:%v Destinations:%v SrcRes:%v DstRes:%v",
					req.ID, ruleIndex,
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

				break
			}
		}

		if !equal {
			diff["rules"] = p.PropertyDiff{
				InputDiff: false,
				Kind:      p.Update,
			}
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
	f.OutputField(&state.Rules).DependsOn(f.InputField(&args.Rules))
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

// buildPreviewRuleStates constructs PolicyRuleState slice for dry-run/preview mode.
func buildPreviewRuleStates(inputRules []PolicyRuleArgs) []PolicyRuleState {
	rules := make([]PolicyRuleState, len(inputRules))

	for ruleIndex, rule := range inputRules {
		// For preview, just copy the string IDs directly (state uses same type as inputs)
		rules[ruleIndex] = PolicyRuleState{
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

	return rules
}

// buildAPIRulesForUpdate converts input rules to API format for update.
func buildAPIRulesForUpdate(inputRules []PolicyRuleArgs, stateRules []PolicyRuleState) []nbapi.PolicyRuleUpdate {
	apiRules := make([]nbapi.PolicyRuleUpdate, len(inputRules))

	for ruleIndex, rule := range inputRules {
		ruleID := rule.ID
		// If rule ID not in inputs, try to get it from state (for existing rules)
		if ruleID == nil && ruleIndex < len(stateRules) {
			ruleID = stateRules[ruleIndex].ID
		}

		apiRules[ruleIndex] = nbapi.PolicyRuleUpdate{
			Id:                  ruleID,
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
	}

	return apiRules
}

// buildRuleStatesFromAPIResponse converts API response rules to PolicyRuleState slice.
func buildRuleStatesFromAPIResponse(
	ctx context.Context,
	policyID string,
	apiRules []nbapi.PolicyRule,
	inputRules []PolicyRuleArgs,
) []PolicyRuleState {
	rules := make([]PolicyRuleState, len(apiRules))

	for ruleIndex, rule := range apiRules {
		apiSourcesStr := formatSliceForDebug(rule.Sources)
		p.GetLogger(ctx).Debugf("Update:Policy[%s]:Rules[%d] API returned Sources=%s after update", policyID, ruleIndex, apiSourcesStr)

		sources := reconstructIDsFromAPI(ctx, policyID, ruleIndex, rule.Sources, getInputSources(inputRules, ruleIndex), "Sources")
		destinations := reconstructIDsFromAPI(ctx, policyID, ruleIndex, rule.Destinations, getInputDestinations(inputRules, ruleIndex), "Destinations")

		rules[ruleIndex] = PolicyRuleState{
			ID:                  rule.Id,
			Name:                rule.Name,
			Description:         rule.Description,
			Bidirectional:       rule.Bidirectional,
			Action:              RuleAction(rule.Action),
			Enabled:             rule.Enabled,
			Protocol:            Protocol(rule.Protocol),
			Ports:               rule.Ports,
			PortRanges:          fromAPIPortRanges(rule.PortRanges),
			Sources:             sources,
			Destinations:        destinations,
			SourceResource:      fromAPIResource(rule.SourceResource),
			DestinationResource: fromAPIResource(rule.DestinationResource),
		}
	}

	return rules
}

// reconstructIDsFromAPI handles the case where API returns nil but we sent groups.
// Returns string IDs (same as inputs).
func reconstructIDsFromAPI(
	ctx context.Context,
	policyID string,
	ruleIndex int,
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

		p.GetLogger(ctx).Debugf("Update:Policy[%s]:Rules[%d] reconstructed %s from inputs (API returned nil)", policyID, ruleIndex, fieldName)
	}

	return ids
}

// getInputSources safely retrieves sources from input rules at the given index.
func getInputSources(inputRules []PolicyRuleArgs, index int) *[]string {
	if index < len(inputRules) {
		return inputRules[index].Sources
	}

	return nil
}

// getInputDestinations safely retrieves destinations from input rules at the given index.
func getInputDestinations(inputRules []PolicyRuleArgs, index int) *[]string {
	if index < len(inputRules) {
		return inputRules[index].Destinations
	}

	return nil
}
