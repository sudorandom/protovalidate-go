// Copyright 2023-2026 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package protovalidate

import (
	"errors"
	"fmt"
	"slices"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/reflect/protoreflect"
)

//nolint:gochecknoglobals
var (
	enumConstSite = makeRuleSite(enumRuleDescriptor, (*validate.EnumRules)(nil).ProtoReflect().Descriptor().Fields().ByName("const"), "enum.const", "")
	enumInSite    = makeRuleSite(enumRuleDescriptor, (*validate.EnumRules)(nil).ProtoReflect().Descriptor().Fields().ByName("in"), "enum.in", "")
	enumNotInSite = makeRuleSite(enumRuleDescriptor, (*validate.EnumRules)(nil).ProtoReflect().Descriptor().Fields().ByName("not_in"), "enum.not_in", "")
)

// tryBuildNativeEnumRules attempts to build a native Go evaluator for
// enum const/defined_only/in/not_in rules. Returns nil if the rules can't be
// handled natively.
func tryBuildNativeEnumRules(base base, rules *validate.EnumRules, values protoreflect.EnumValueDescriptors) evaluator {
	if rules == nil || !canBuildNativeEnumRules(rules) {
		return nil
	}

	hasRule := false

	eval := &nativeEnumEval{base: base}

	if rules.HasConst() {
		eval.constVal = newFixedRule(rules.GetConst(), enumConstSite,
			"enum.const", fmt.Sprintf("must equal %d", rules.GetConst()))
		rules.ProtoReflect().Clear(enumConstSite.desc)
		hasRule = true
	}

	if rules.GetDefinedOnly() {
		eval.definedOnly = &definedEnum{base: base, ValueDescriptors: values}
		rules.ProtoReflect().Clear(enumDefinedOnlyRuleDescriptor)
		hasRule = true
	}

	if inVals := rules.GetIn(); len(inVals) > 0 {
		eval.inVals = newFixedRule(inVals, enumInSite,
			"enum.in", "must be in list "+formatList(inVals))
		eval.inRuleValue = sliceToListValue(&validate.EnumRules{}, enumInSite.desc, inVals, protoreflect.ValueOfInt32)
		rules.ProtoReflect().Clear(enumInSite.desc)
		hasRule = true
	}

	if notInVals := rules.GetNotIn(); len(notInVals) > 0 {
		eval.notInVals = newFixedRule(notInVals, enumNotInSite,
			"enum.not_in", "must not be in list "+formatList(notInVals))
		eval.notInRuleValue = sliceToListValue(&validate.EnumRules{}, enumNotInSite.desc, notInVals, protoreflect.ValueOfInt32)
		rules.ProtoReflect().Clear(enumNotInSite.desc)
		hasRule = true
	}

	if !hasRule {
		return nil
	}
	return eval
}

// canBuildNativeEnumRules reports whether tryBuildNativeEnumRules can handle
// rules. Unknown fields are custom predefined rules, which CEL must evaluate
// against the complete rules message.
func canBuildNativeEnumRules(rules *validate.EnumRules) bool {
	return len(rules.ProtoReflect().GetUnknown()) == 0
}

var _ evaluator = (*nativeEnumEval)(nil)

// nativeEnumEval is a native Go evaluator for enum const/defined_only/in/not_in rules.
type nativeEnumEval struct {
	base
	constVal       *fixedRule[int32]
	definedOnly    *definedEnum
	inVals         *fixedRule[[]int32]
	inRuleValue    protoreflect.Value
	notInVals      *fixedRule[[]int32]
	notInRuleValue protoreflect.Value
}

type enumProcessor func(n *nativeEnumEval, val protoreflect.Value, enumVal int32) *Violation

//nolint:gochecknoglobals // slice of all the processors that are used, value never modified, effectively immutable
var enumProcessors = []enumProcessor{
	// const
	func(n *nativeEnumEval, val protoreflect.Value, enumVal int32) *Violation {
		if n.constVal != nil && enumVal != n.constVal.value {
			return n.newViolation(n.constVal.site, "", "",
				val, protoreflect.ValueOfInt32(n.constVal.value))
		}
		return nil
	},
	// defined_only
	func(n *nativeEnumEval, val protoreflect.Value, _ int32) *Violation {
		if n.definedOnly == nil {
			return nil
		}
		if valErr, ok := errors.AsType[*ValidationError](n.definedOnly.Evaluate(nil, val, nil)); ok {
			return valErr.Violations[0]
		}
		return nil
	},
	// in
	func(n *nativeEnumEval, val protoreflect.Value, enumVal int32) *Violation {
		if n.inVals != nil && !slices.Contains(n.inVals.value, enumVal) {
			return n.newViolation(n.inVals.site, "", "", val, n.inRuleValue)
		}
		return nil
	},
	// not_in
	func(n *nativeEnumEval, val protoreflect.Value, enumVal int32) *Violation {
		if n.notInVals != nil && slices.Contains(n.notInVals.value, enumVal) {
			return n.newViolation(n.notInVals.site, "", "", val, n.notInRuleValue)
		}
		return nil
	},
}

func (n *nativeEnumEval) Evaluate(_ protoreflect.Message, val protoreflect.Value, cfg *validationConfig) error {
	enumVal := int32(val.Enum())

	var violations []*Violation

	for _, enumProcessor := range enumProcessors {
		violation := enumProcessor(n, val, enumVal)
		if violation != nil {
			violations = append(violations, violation)
			if cfg.failFast {
				break
			}
		}
	}

	if len(violations) > 0 {
		return &ValidationError{
			Violations: violations,
		}
	}
	return nil
}

func (n *nativeEnumEval) Tautology() bool {
	return false
}
