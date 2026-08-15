package policy

import "testing"

// --- deny-by-default ---

func TestEvaluate_NoRules_DeniesByDefault(t *testing.T) {
	if Evaluate(nil, "prod/database", ActionRead) {
		t.Error("Evaluate with zero rules = true, want false (deny by default)")
	}
}

func TestEvaluate_RulesExistButNoneMatchPath_Denies(t *testing.T) {
	rules := []Rule{
		{PathPattern: "dev/*", Effect: EffectAllow, Actions: []Action{ActionRead}},
	}
	if Evaluate(rules, "prod/database", ActionRead) {
		t.Error("Evaluate() = true for a path no rule mentions, want false")
	}
}

func TestEvaluate_RuleMatchesPathButNotAction_Denies(t *testing.T) {
	rules := []Rule{
		{PathPattern: "prod/database", Effect: EffectAllow, Actions: []Action{ActionRead}},
	}
	if Evaluate(rules, "prod/database", ActionDelete) {
		t.Error("Evaluate() = true for an action the matching rule does not grant, want false")
	}
}

// --- explicit allow ---

func TestEvaluate_ExactMatch_Allows(t *testing.T) {
	rules := []Rule{
		{PathPattern: "prod/database", Effect: EffectAllow, Actions: []Action{ActionRead, ActionUpdate}},
	}
	if !Evaluate(rules, "prod/database", ActionRead) {
		t.Error("Evaluate() = false for an exact path/action match with an allow rule, want true")
	}
	if !Evaluate(rules, "prod/database", ActionUpdate) {
		t.Error("Evaluate() = false for ActionUpdate, want true")
	}
}

func TestEvaluate_WildcardPrefix_Allows(t *testing.T) {
	rules := []Rule{
		{PathPattern: "dev/*", Effect: EffectAllow, Actions: []Action{ActionRead, ActionCreate, ActionUpdate}},
	}
	for _, path := range []string{"dev/database", "dev/api", "dev/a/b/c"} {
		if !Evaluate(rules, path, ActionRead) {
			t.Errorf("Evaluate(%q, read) = false, want true (dev/* grants read)", path)
		}
	}
	if Evaluate(rules, "prod/database", ActionRead) {
		t.Error(`Evaluate("prod/database", read) = true, want false — "dev/*" must not grant a sibling tree`)
	}
}

func TestEvaluate_MatchAll_Allows(t *testing.T) {
	rules := []Rule{{PathPattern: "*", Effect: EffectAllow, Actions: []Action{ActionRead}}}
	for _, path := range []string{"a", "a/b", "prod/database/creds"} {
		if !Evaluate(rules, path, ActionRead) {
			t.Errorf("Evaluate(%q, read) with a %q policy = false, want true", path, "*")
		}
	}
}

// --- prefix boundary correctness: the exact scenario the objective calls
// out by name — "prod/db" must never accidentally authorize "prod/database" ---

func TestEvaluate_PrefixBoundary_SimilarPathNameDoesNotBypass(t *testing.T) {
	rules := []Rule{
		{PathPattern: "prod/db/*", Effect: EffectAllow, Actions: []Action{ActionRead}},
	}
	if Evaluate(rules, "prod/database", ActionRead) {
		t.Error(`Evaluate("prod/database", read) with policy "prod/db/*" = true, want false — no "/" boundary between "prod/db" and "database"`)
	}
	if !Evaluate(rules, "prod/db/password", ActionRead) {
		t.Error(`Evaluate("prod/db/password", read) with policy "prod/db/*" = false, want true`)
	}
}

func TestEvaluate_WildcardDoesNotMatchItsOwnPrefix(t *testing.T) {
	// "dev/*" grants access to things inside dev/, not to a secret that
	// happens to be named exactly "dev" — that needs its own exact-match rule.
	rules := []Rule{{PathPattern: "dev/*", Effect: EffectAllow, Actions: []Action{ActionRead}}}
	if Evaluate(rules, "dev", ActionRead) {
		t.Error(`Evaluate("dev", read) with policy "dev/*" = true, want false`)
	}
}

func TestEvaluate_ExactRuleDoesNotGrantChildren(t *testing.T) {
	rules := []Rule{{PathPattern: "prod/db", Effect: EffectAllow, Actions: []Action{ActionRead}}}
	if Evaluate(rules, "prod/db/password", ActionRead) {
		t.Error(`Evaluate("prod/db/password", read) with exact-match policy "prod/db" = true, want false`)
	}
}

// --- explicit deny precedence: explicit deny > explicit allow > default deny ---

func TestEvaluate_ExplicitDeny_OverridesExplicitAllow(t *testing.T) {
	rules := []Rule{
		{PathPattern: "prod/*", Effect: EffectAllow, Actions: []Action{ActionRead}},
		{PathPattern: "prod/database", Effect: EffectDeny, Actions: []Action{ActionRead}},
	}
	if Evaluate(rules, "prod/database", ActionRead) {
		t.Error("Evaluate() = true, want false — an explicit deny rule must override a broader allow")
	}
	// The allow still applies to paths the deny doesn't cover.
	if !Evaluate(rules, "prod/api", ActionRead) {
		t.Error("Evaluate() = false for a sibling path not covered by the deny rule, want true")
	}
}

func TestEvaluate_ExplicitDeny_OverridesRegardlessOfRuleOrder(t *testing.T) {
	denyFirst := []Rule{
		{PathPattern: "prod/database", Effect: EffectDeny, Actions: []Action{ActionRead}},
		{PathPattern: "prod/*", Effect: EffectAllow, Actions: []Action{ActionRead}},
	}
	allowFirst := []Rule{
		{PathPattern: "prod/*", Effect: EffectAllow, Actions: []Action{ActionRead}},
		{PathPattern: "prod/database", Effect: EffectDeny, Actions: []Action{ActionRead}},
	}
	if Evaluate(denyFirst, "prod/database", ActionRead) {
		t.Error("deny-first rule order: Evaluate() = true, want false")
	}
	if Evaluate(allowFirst, "prod/database", ActionRead) {
		t.Error("allow-first rule order: Evaluate() = true, want false — deny must win regardless of slice order")
	}
}

func TestEvaluate_DenyOnUnrelatedAction_DoesNotAffectGrantedAction(t *testing.T) {
	rules := []Rule{
		{PathPattern: "prod/database", Effect: EffectAllow, Actions: []Action{ActionRead}},
		{PathPattern: "prod/database", Effect: EffectDeny, Actions: []Action{ActionDelete}},
	}
	if !Evaluate(rules, "prod/database", ActionRead) {
		t.Error("Evaluate(read) = false, want true — a deny on a different action must not affect this one")
	}
	if Evaluate(rules, "prod/database", ActionDelete) {
		t.Error("Evaluate(delete) = true, want false")
	}
}

// --- determinism: repeated evaluation of the same inputs always agrees ---

func TestEvaluate_Deterministic(t *testing.T) {
	rules := []Rule{
		{PathPattern: "dev/*", Effect: EffectAllow, Actions: []Action{ActionRead, ActionCreate}},
		{PathPattern: "dev/secrets/*", Effect: EffectDeny, Actions: []Action{ActionRead}},
		{PathPattern: "*", Effect: EffectAllow, Actions: []Action{ActionList}},
	}
	first := Evaluate(rules, "dev/secrets/token", ActionRead)
	for i := 0; i < 50; i++ {
		if got := Evaluate(rules, "dev/secrets/token", ActionRead); got != first {
			t.Fatalf("iteration %d: Evaluate() = %v, want %v (same inputs must always produce the same decision)", i, got, first)
		}
	}
	if first {
		t.Error("want false: dev/secrets/* deny should override dev/* allow")
	}
}

// --- multiple policies combine correctly ---

func TestEvaluate_MultipleAllowRules_AnyMatchGrants(t *testing.T) {
	rules := []Rule{
		{PathPattern: "dev/*", Effect: EffectAllow, Actions: []Action{ActionRead}},
		{PathPattern: "staging/*", Effect: EffectAllow, Actions: []Action{ActionRead}},
	}
	if !Evaluate(rules, "staging/api", ActionRead) {
		t.Error("Evaluate() = false, want true — the second rule alone should grant access")
	}
}

func TestRule_AppliesTo(t *testing.T) {
	r := Rule{Actions: []Action{ActionRead, ActionList}}
	if !r.appliesTo(ActionRead) || !r.appliesTo(ActionList) {
		t.Error("appliesTo() = false for an action present in Actions, want true")
	}
	if r.appliesTo(ActionDelete) {
		t.Error("appliesTo() = true for an action absent from Actions, want false")
	}
}
