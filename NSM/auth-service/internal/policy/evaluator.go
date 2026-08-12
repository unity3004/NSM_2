// Package policy implements Sprint 4 Task 2's secret path-authorization
// decision: given the rules that apply to a caller (already resolved by
// the service layer from their roles' assigned secret_policies — see
// internal/service.SecretPolicyService), decide whether a specific
// (secret path, action) pair is ALLOW or DENY.
//
// Deliberately narrow and self-contained, the same "no database, no
// logging, no net/http dependency" discipline internal/secrets already
// follows for the same reason: a package that cannot query a database
// cannot accidentally decide authorization from stale or partially-loaded
// data, and a package with no logging dependency cannot be made to log
// anything sensitive by a future one-line edit. Evaluate is a pure
// function of its inputs — same rules, same path, same action always
// produce the same decision, deterministically, with no hidden state and
// nothing to mock to test it.
package policy

import (
	"slices"

	"github.com/acme/auth-service/internal/util"
)

// Action is one of the operations a secret_policy_rule can grant or deny.
// These map directly onto the existing secrets:* permission actions
// (secrets:create/read/update/delete/list) — deliberately the same
// vocabulary, not a second, parallel action taxonomy: a path policy
// restricts *which paths* a permission a user already holds applies to,
// it does not invent new capabilities the permission model doesn't
// already have a name for.
type Action string

const (
	ActionRead   Action = "read"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
	ActionList   Action = "list"
)

// Effect is a rule's disposition when it matches: does it grant the
// action, or explicitly forbid it regardless of any other matching rule?
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Rule is one path_pattern + effect + action-set, exactly one
// secret_policy_rules row's worth of information (with its joined
// secret_policy_rule_actions rows folded in) — everything Evaluate needs
// and nothing it doesn't. PathPattern must already be normalized (see
// util.NormalizePolicyPathPattern) — Evaluate does not normalize it
// again.
type Rule struct {
	PathPattern string
	Effect      Effect
	Actions     []Action
}

func (r Rule) appliesTo(action Action) bool {
	return slices.Contains(r.Actions, action)
}

// Evaluate decides ALLOW/DENY for one (canonicalPath, action) pair against
// rules — the complete set of rules every policy assigned (directly or via
// a role) to the caller contributes, already resolved by the caller of
// this function. canonicalPath must already be normalized (see
// util.NormalizeSecretPath) and validated; Evaluate does not re-validate
// it.
//
// Precedence, exactly as the objective specifies: explicit deny > explicit
// allow > default deny. Implemented as a single pass: any matching rule
// with EffectDeny returns false immediately (deny short-circuits — no
// other rule, allow or deny, can override it once found); otherwise the
// result is true if and only if at least one matching rule had
// EffectAllow. A caller with zero matching rules at all — no policy ever
// mentions this path — gets false: "no applicable policy grants access"
// is indistinguishable, by construction, from "no applicable policy
// exists at all." There is no code path through this function that
// returns true without at least one explicit, matching EffectAllow rule.
func Evaluate(rules []Rule, canonicalPath string, action Action) bool {
	allowed := false
	for _, r := range rules {
		if !r.appliesTo(action) {
			continue
		}
		if !util.MatchPolicyPathPattern(r.PathPattern, canonicalPath) {
			continue
		}
		if r.Effect == EffectDeny {
			return false
		}
		allowed = true
	}
	return allowed
}
