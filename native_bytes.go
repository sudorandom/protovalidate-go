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
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// tryBuildNativeBytesRules attempts to build a native Go evaluator for
// bytes rules. Returns nil if the rules can't be handled natively.
func tryBuildNativeBytesRules(base base, rules *validate.BytesRules) evaluator {
	if rules == nil {
		return nil
	}
	if len(rules.ProtoReflect().GetUnknown()) > 0 {
		return nil
	}

	hasRule := false

	// Detect well-known format constraint (ip, ipv4, ipv6, uuid).
	// Check both presence and value — setting ip=false means no check.
	var wellKnown *bytesWellKnown
	switch {
	case rules.GetIp():
		wellKnown = &bytesWellKnownIP
		rules.ProtoReflect().Clear(bytesDescs.ipDesc)
		hasRule = true
	case rules.GetIpv4():
		wellKnown = &bytesWellKnownIPv4
		rules.ProtoReflect().Clear(bytesDescs.ipv4Desc)
		hasRule = true
	case rules.GetIpv6():
		wellKnown = &bytesWellKnownIPv6
		rules.ProtoReflect().Clear(bytesDescs.ipv6Desc)
		hasRule = true
	case rules.GetUuid():
		wellKnown = &bytesWellKnownUUID
		rules.ProtoReflect().Clear(bytesDescs.uuidDesc)
		hasRule = true
	}

	eval := &nativeBytesEval{
		base:      base,
		wellKnown: wellKnown,
	}

	if rules.HasConst() {
		eval.constVal = newFixedRule(rules.GetConst(), bytesDescs.constSite,
			"bytes.const", fmt.Sprintf("must be %x", rules.GetConst()))
		rules.ProtoReflect().Clear(bytesDescs.constSite.desc)
		hasRule = true
	}

	if rules.HasLen() {
		eval.exactLen = newFixedRule(rules.GetLen(), bytesDescs.lenSite,
			"bytes.len", fmt.Sprintf("must be %d bytes", rules.GetLen()))
		rules.ProtoReflect().Clear(bytesDescs.lenSite.desc)
		hasRule = true
	}

	if rules.HasMinLen() {
		eval.minLen = newFixedRule(rules.GetMinLen(), bytesDescs.minLenSite,
			"bytes.min_len", fmt.Sprintf("must be at least %d bytes", rules.GetMinLen()))
		rules.ProtoReflect().Clear(bytesDescs.minLenSite.desc)
		hasRule = true
	}

	if rules.HasMaxLen() {
		eval.maxLen = newFixedRule(rules.GetMaxLen(), bytesDescs.maxLenSite,
			"bytes.max_len", fmt.Sprintf("must be at most %d bytes", rules.GetMaxLen()))
		rules.ProtoReflect().Clear(bytesDescs.maxLenSite.desc)
		hasRule = true
	}

	if rules.HasPattern() {
		var err error
		eval.pattern, err = regexp.Compile(rules.GetPattern())
		if err != nil {
			return nil // bail to CEL
		}
		eval.patternStr = newFixedRule(rules.GetPattern(), bytesDescs.patternSite,
			"bytes.pattern", fmt.Sprintf("must match regex pattern `%s`", rules.GetPattern()))
		rules.ProtoReflect().Clear(bytesDescs.patternSite.desc)
		hasRule = true
	}

	if rules.HasPrefix() {
		eval.prefix = newFixedRule(rules.GetPrefix(), bytesDescs.prefixSite,
			"bytes.prefix", fmt.Sprintf("does not have prefix %x", rules.GetPrefix()))
		rules.ProtoReflect().Clear(bytesDescs.prefixSite.desc)
		hasRule = true
	}

	if rules.HasSuffix() {
		eval.suffix = newFixedRule(rules.GetSuffix(), bytesDescs.suffixSite,
			"bytes.suffix", fmt.Sprintf("does not have suffix %x", rules.GetSuffix()))
		rules.ProtoReflect().Clear(bytesDescs.suffixSite.desc)
		hasRule = true
	}

	if rules.HasContains() {
		eval.contains = newFixedRule(rules.GetContains(), bytesDescs.containsSite,
			"bytes.contains", fmt.Sprintf("does not contain %x", rules.GetContains()))
		rules.ProtoReflect().Clear(bytesDescs.containsSite.desc)
		hasRule = true
	}

	if inVals := rules.GetIn(); len(inVals) > 0 {
		eval.inVals = newFixedRule(inVals, bytesDescs.inSite,
			"bytes.in", "must be in list "+formatBytesList(inVals))
		eval.inRuleValue = sliceToListValue(&validate.BytesRules{}, bytesDescs.inSite.desc, inVals, protoreflect.ValueOfBytes)
		rules.ProtoReflect().Clear(bytesDescs.inSite.desc)
		hasRule = true
	}

	if notInVals := rules.GetNotIn(); len(notInVals) > 0 {
		eval.notInVals = newFixedRule(notInVals, bytesDescs.notInSite,
			"bytes.not_in", "must not be in list "+formatBytesList(notInVals))
		eval.notInRuleValue = sliceToListValue(&validate.BytesRules{}, bytesDescs.notInSite.desc, notInVals, protoreflect.ValueOfBytes)
		rules.ProtoReflect().Clear(bytesDescs.notInSite.desc)
		hasRule = true
	}

	if !hasRule {
		return nil
	}
	return eval
}

// bytesWellKnown identifies which well-known bytes format constraint is active.
type bytesWellKnown struct {
	site       ruleSite // pre-built rule path site for the error path
	emptySite  ruleSite // pre-built rule path site for the empty value
	validSizes []int
}

var (
	//nolint:gochecknoglobals
	bytesWellKnownIP = bytesWellKnown{
		site:       makeRuleSite(bytesDescs.ruleDesc, bytesDescs.ipDesc, "bytes.ip", "must be a valid IP address"),
		emptySite:  makeRuleSite(bytesDescs.ruleDesc, bytesDescs.ipDesc, "bytes.ip_empty", "value is empty, which is not a valid IP address"),
		validSizes: []int{4, 16},
	}
	//nolint:gochecknoglobals
	bytesWellKnownIPv4 = bytesWellKnown{
		site:       makeRuleSite(bytesDescs.ruleDesc, bytesDescs.ipv4Desc, "bytes.ipv4", "must be a valid IPv4 address"),
		emptySite:  makeRuleSite(bytesDescs.ruleDesc, bytesDescs.ipv4Desc, "bytes.ipv4_empty", "value is empty, which is not a valid IPv4 address"),
		validSizes: []int{4},
	}
	//nolint:gochecknoglobals
	bytesWellKnownIPv6 = bytesWellKnown{
		site:       makeRuleSite(bytesDescs.ruleDesc, bytesDescs.ipv6Desc, "bytes.ipv6", "must be a valid IPv6 address"),
		emptySite:  makeRuleSite(bytesDescs.ruleDesc, bytesDescs.ipv6Desc, "bytes.ipv6_empty", "value is empty, which is not a valid IPv6 address"),
		validSizes: []int{16},
	}
	//nolint:gochecknoglobals
	bytesWellKnownUUID = bytesWellKnown{
		site:       makeRuleSite(bytesDescs.ruleDesc, bytesDescs.uuidDesc, "bytes.uuid", "must be a valid UUID"),
		emptySite:  makeRuleSite(bytesDescs.ruleDesc, bytesDescs.uuidDesc, "bytes.uuid_empty", "value is empty, which is not a valid UUID"),
		validSizes: []int{16},
	}
)

// bytesDescriptors bundles the field descriptors for BytesRules.
type bytesDescriptors struct {
	ruleDesc protoreflect.FieldDescriptor
	ipDesc   protoreflect.FieldDescriptor
	ipv4Desc protoreflect.FieldDescriptor
	ipv6Desc protoreflect.FieldDescriptor
	uuidDesc protoreflect.FieldDescriptor

	// Pre-built rule sites for the error path.
	constSite    ruleSite
	lenSite      ruleSite
	minLenSite   ruleSite
	maxLenSite   ruleSite
	patternSite  ruleSite
	prefixSite   ruleSite
	suffixSite   ruleSite
	containsSite ruleSite
	inSite       ruleSite
	notInSite    ruleSite
}

func makeBytesDescriptors() bytesDescriptors {
	rulesDesc := (*validate.BytesRules)(nil).ProtoReflect().Descriptor()
	descriptors := bytesDescriptors{
		ruleDesc: fieldRulesDesc.Fields().ByName("bytes"),
		ipDesc:   rulesDesc.Fields().ByName("ip"),
		ipv4Desc: rulesDesc.Fields().ByName("ipv4"),
		ipv6Desc: rulesDesc.Fields().ByName("ipv6"),
		uuidDesc: rulesDesc.Fields().ByName("uuid"),
	}
	descriptors.constSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("const"), "bytes.const", "")
	descriptors.lenSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("len"), "bytes.len", "")
	descriptors.minLenSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("min_len"), "bytes.min_len", "")
	descriptors.maxLenSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("max_len"), "bytes.max_len", "")
	descriptors.patternSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("pattern"), "bytes.pattern", "")
	descriptors.prefixSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("prefix"), "bytes.prefix", "")
	descriptors.suffixSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("suffix"), "bytes.suffix", "")
	descriptors.containsSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("contains"), "bytes.contains", "")
	descriptors.inSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("in"), "bytes.in", "")
	descriptors.notInSite = makeRuleSite(descriptors.ruleDesc, rulesDesc.Fields().ByName("not_in"), "bytes.not_in", "")
	return descriptors
}

//nolint:gochecknoglobals
var bytesDescs = makeBytesDescriptors()

var _ evaluator = (*nativeBytesEval)(nil)

// nativeBytesEval is a native Go evaluator for bytes rules.
type nativeBytesEval struct {
	base
	constVal       *fixedRule[[]byte]
	exactLen       *fixedRule[uint64]
	minLen         *fixedRule[uint64]
	maxLen         *fixedRule[uint64]
	pattern        *regexp.Regexp
	patternStr     *fixedRule[string]
	prefix         *fixedRule[[]byte]
	suffix         *fixedRule[[]byte]
	contains       *fixedRule[[]byte]
	inVals         *fixedRule[[][]byte]
	inRuleValue    protoreflect.Value
	notInVals      *fixedRule[[][]byte]
	notInRuleValue protoreflect.Value
	wellKnown      *bytesWellKnown
}

var errNotUTF8 = errors.New("must be valid UTF-8 to apply regexp")

//nolint:gocyclo // this code has nested ifs but it's not hard to follow.
func (n *nativeBytesEval) Evaluate(_ protoreflect.Message, val protoreflect.Value, cfg *validationConfig) error {
	bytesVal := val.Bytes()
	byteLen := uint64(len(bytesVal))
	var violations []*Violation

	if n.constVal != nil && !bytes.Equal(bytesVal, n.constVal.value) {
		violations = append(violations, n.newViolation(n.constVal.site, "", "",
			val, protoreflect.ValueOfBytes(n.constVal.value)))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.exactLen != nil && byteLen != n.exactLen.value {
		violations = append(violations, n.newViolation(n.exactLen.site, "", "",
			val, protoreflect.ValueOfUint64(n.exactLen.value)))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.minLen != nil && byteLen < n.minLen.value {
		violations = append(violations, n.newViolation(n.minLen.site, "", "",
			val, protoreflect.ValueOfUint64(n.minLen.value)))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.maxLen != nil && byteLen > n.maxLen.value {
		violations = append(violations, n.newViolation(n.maxLen.site, "", "",
			val, protoreflect.ValueOfUint64(n.maxLen.value)))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.pattern != nil {
		if !utf8.Valid(bytesVal) {
			// the bytes.pattern rule requires the value to be UTF-8. Surface
			// this as a RuntimeError to match CEL behavior / conformance tests.
			return &RuntimeError{cause: errNotUTF8}
		}
		if !n.pattern.MatchString(string(bytesVal)) {
			violations = append(violations, n.newViolation(n.patternStr.site, "", "",
				val, protoreflect.ValueOfString(n.patternStr.value)))
			if cfg.failFast {
				return &ValidationError{Violations: violations}
			}
		}
	}

	if n.prefix != nil && !bytes.HasPrefix(bytesVal, n.prefix.value) {
		violations = append(violations, n.newViolation(n.prefix.site, "", "",
			val, protoreflect.ValueOfBytes(n.prefix.value)))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.suffix != nil && !bytes.HasSuffix(bytesVal, n.suffix.value) {
		violations = append(violations, n.newViolation(n.suffix.site, "", "",
			val, protoreflect.ValueOfBytes(n.suffix.value)))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.contains != nil && !bytes.Contains(bytesVal, n.contains.value) {
		violations = append(violations, n.newViolation(n.contains.site, "", "",
			val, protoreflect.ValueOfBytes(n.contains.value)))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.inVals != nil && !slices.ContainsFunc(n.inVals.value, func(v []byte) bool { return bytes.Equal(v, bytesVal) }) {
		violations = append(violations, n.newViolation(n.inVals.site, "", "", val, n.inRuleValue))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.notInVals != nil && slices.ContainsFunc(n.notInVals.value, func(v []byte) bool { return bytes.Equal(v, bytesVal) }) {
		violations = append(violations, n.newViolation(n.notInVals.site, "", "", val, n.notInRuleValue))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if n.wellKnown != nil {
		if v := n.evaluateWellKnown(bytesVal, val); v != nil {
			violations = append(violations, v)
			if cfg.failFast {
				return &ValidationError{Violations: violations}
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

func (n *nativeBytesEval) evaluateWellKnown(bytesVal []byte, val protoreflect.Value) *Violation {
	size := len(bytesVal)
	wellKnown := n.wellKnown

	if size == 0 {
		return n.newViolation(wellKnown.emptySite,
			"", "",
			val, protoreflect.ValueOfBool(true))
	}

	if slices.Contains(wellKnown.validSizes, size) {
		return nil
	}

	return n.newViolation(wellKnown.site,
		"", "",
		val, protoreflect.ValueOfBool(true))
}

func (n *nativeBytesEval) Tautology() bool {
	return false
}

// formatBytesList formats a [][]byte to match CEL's list formatting.
func formatBytesList(vals [][]byte) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		// this is what CEL does for a byte slice; displays it as a string
		parts[i] = string(v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
