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
	"cmp"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// timeValue is the set of Go types CEL uses for google.protobuf.Timestamp and
// google.protobuf.Duration values.
type timeValue interface {
	time.Time | time.Duration
}

// timeTypeConfig holds the type-specific operations and metadata for
// timestamp or duration rules.
type timeTypeConfig[T timeValue] struct {
	typeName string             // proto rule prefix: "timestamp" or "duration"
	descs    numericDescriptors // in/not_in sites are zero-valued for timestamps
	compare  func(T, T) int
	format   func(T) string // matches CEL's string format of the value
	// fromParts converts a field value the way CEL does.
	fromParts func(seconds int64, nanos int32) T
	// fromRule converts a rule value. ok is false for values CEL rejects;
	// those rules are left to CEL, which reports them.
	fromRule func(rule protoreflect.Message) (value T, ok bool)
}

//nolint:gochecknoglobals
var (
	timestampConfig = timeTypeConfig[time.Time]{
		typeName: "timestamp",
		descs:    makeNumericDescriptors("timestamp", (*validate.TimestampRules)(nil), "timestamp"),
		compare:  time.Time.Compare,
		format: func(value time.Time) string {
			return value.UTC().Format(time.RFC3339Nano)
		},
		fromParts: func(seconds int64, nanos int32) time.Time {
			return (&timestamppb.Timestamp{Seconds: seconds, Nanos: nanos}).AsTime()
		},
		fromRule: func(rule protoreflect.Message) (time.Time, bool) {
			timestamp, ok := rule.Interface().(*timestamppb.Timestamp)
			if !ok || timestamp.CheckValid() != nil {
				return time.Time{}, false
			}
			return timestamp.AsTime(), true
		},
	}
	durationConfig = timeTypeConfig[time.Duration]{
		typeName: "duration",
		descs:    makeNumericDescriptors("duration", (*validate.DurationRules)(nil), "duration"),
		compare:  cmp.Compare[time.Duration],
		format: func(value time.Duration) string {
			return strconv.FormatFloat(value.Seconds(), 'f', -1, 64) + "s"
		},
		fromParts: func(seconds int64, nanos int32) time.Duration {
			return (&durationpb.Duration{Seconds: seconds, Nanos: nanos}).AsDuration()
		},
		fromRule: func(rule protoreflect.Message) (time.Duration, bool) {
			duration, ok := rule.Interface().(*durationpb.Duration)
			if !ok || duration.CheckValid() != nil {
				return 0, false
			}
			// AsDuration saturates values time.Duration can't hold.
			value := duration.AsDuration()
			return value, value != math.MinInt64 && value != math.MaxInt64
		},
	}
)

// timeBound is a timestamp or duration rule value, along with the rule's
// protoreflect.Value reported on violations.
type timeBound[T timeValue] struct {
	value     T
	ruleValue protoreflect.Value
}

// tryBuildNativeTimeRules attempts to build a native Go evaluator for
// google.protobuf.Timestamp and google.protobuf.Duration rules. Returns nil
// if the field is another message type or the rules can't be handled natively.
func tryBuildNativeTimeRules(
	base base,
	rules *validate.FieldRules,
	messageDesc protoreflect.MessageDescriptor,
) evaluator {
	switch messageDesc.FullName() {
	case "google.protobuf.Timestamp":
		timestampRules := rules.GetTimestamp()
		if timestampRules == nil {
			return nil
		}
		// Rules relative to now stay in CEL. They sort between the fixed
		// bounds in validate.proto, so splitting them off would reorder
		// violations.
		if timestampRules.HasLtNow() || timestampRules.HasGtNow() || timestampRules.HasWithin() {
			return nil
		}
		return tryBuildNativeTimeCompare(base, timestampRules.ProtoReflect(), messageDesc, &timestampConfig)
	case "google.protobuf.Duration":
		if !rules.HasDuration() {
			return nil
		}
		return tryBuildNativeTimeCompare(base, rules.GetDuration().ProtoReflect(), messageDesc, &durationConfig)
	default:
		return nil
	}
}

func tryBuildNativeTimeCompare[T timeValue](
	base base,
	rules protoreflect.Message,
	messageDesc protoreflect.MessageDescriptor,
	config *timeTypeConfig[T],
) evaluator {
	// Bail out for custom predefined extensions.
	if len(rules.GetUnknown()) > 0 {
		return nil
	}
	descs := &config.descs
	eval := nativeTimeCompare[T]{
		base:         base,
		config:       config,
		secondsField: messageDesc.Fields().ByName("seconds"),
		nanosField:   messageDesc.Fields().ByName("nanos"),
	}
	hasRule := false
	for _, site := range []ruleSite{descs.constSite, descs.gtSite, descs.gteSite, descs.ltSite, descs.lteSite} {
		if !rules.Has(site.desc) {
			continue
		}
		ruleValue := rules.Get(site.desc)
		value, ok := config.fromRule(ruleValue.Message())
		if !ok {
			return nil
		}
		bound := timeBound[T]{value: value, ruleValue: ruleValue}
		switch site.desc {
		case descs.constSite.desc:
			eval.constVal = &bound
		case descs.gtSite.desc:
			eval.lo, eval.lower = bound, lowerBoundGt
		case descs.gteSite.desc:
			eval.lo, eval.lower = bound, lowerBoundGte
		case descs.ltSite.desc:
			eval.hi, eval.upper = bound, upperBoundLt
		default:
			eval.hi, eval.upper = bound, upperBoundLte
		}
		hasRule = true
	}
	var ok bool
	if eval.inVals, eval.inValue, ok = readTimeList(rules, descs.inSite.desc, config); !ok {
		return nil
	}
	if eval.notInVals, eval.notInValue, ok = readTimeList(rules, descs.notInSite.desc, config); !ok {
		return nil
	}
	if !hasRule && len(eval.inVals) == 0 && len(eval.notInVals) == 0 {
		return nil
	}
	for _, site := range []ruleSite{
		descs.constSite, descs.gtSite, descs.gteSite, descs.ltSite, descs.lteSite,
		descs.inSite, descs.notInSite,
	} {
		if site.desc != nil {
			rules.Clear(site.desc)
		}
	}
	return eval
}

// readTimeList reads an in/not_in rule, which timestamps don't have (desc is
// nil). The rule value is a copy, because the list is cleared from rules.
func readTimeList[T timeValue](
	rules protoreflect.Message,
	desc protoreflect.FieldDescriptor,
	config *timeTypeConfig[T],
) ([]T, protoreflect.Value, bool) {
	if desc == nil || !rules.Has(desc) {
		return nil, protoreflect.Value{}, true
	}
	list := rules.Get(desc).List()
	values := make([]T, list.Len())
	ruleValue := rules.New().Mutable(desc).List()
	for i := range list.Len() {
		value, ok := config.fromRule(list.Get(i).Message())
		if !ok {
			return nil, protoreflect.Value{}, false
		}
		values[i] = value
		ruleValue.Append(list.Get(i))
	}
	return values, protoreflect.ValueOfList(ruleValue), true
}

// nativeTimeCompare is a native Go evaluator for the fixed timestamp and
// duration rules: const, gt/gte/lt/lte, and (durations only) in/not_in. It
// follows nativeNumericCompare, comparing values the way CEL sees them.
type nativeTimeCompare[T timeValue] struct {
	base
	config       *timeTypeConfig[T]
	secondsField protoreflect.FieldDescriptor
	nanosField   protoreflect.FieldDescriptor
	constVal     *timeBound[T]
	lo           timeBound[T]
	lower        lowerBound
	hi           timeBound[T]
	upper        upperBound
	inVals       []T
	inValue      protoreflect.Value
	notInVals    []T
	notInValue   protoreflect.Value
}

func (n nativeTimeCompare[T]) Evaluate(_ protoreflect.Message, val protoreflect.Value, cfg *validationConfig) error {
	msg := val.Message()
	nanos := int32(msg.Get(n.nanosField).Int()) //nolint:gosec // nanos is an int32 field
	valT := n.config.fromParts(msg.Get(n.secondsField).Int(), nanos)
	var violations []*Violation

	if n.constVal != nil && n.config.compare(valT, n.constVal.value) != 0 {
		violations = append(violations, n.newViolation(n.config.descs.constSite,
			n.config.typeName+".const",
			"must equal "+n.config.format(n.constVal.value),
			val, n.constVal.ruleValue))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if v := n.evaluateRange(valT, val); v != nil {
		violations = append(violations, v)
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if len(n.inVals) > 0 && !n.contains(n.inVals, valT) {
		violations = append(violations, n.newViolation(n.config.descs.inSite,
			n.config.typeName+".in",
			"must be in list "+n.formatList(n.inVals),
			val, n.inValue))
		if cfg.failFast {
			return &ValidationError{Violations: violations}
		}
	}

	if len(n.notInVals) > 0 && n.contains(n.notInVals, valT) {
		violations = append(violations, n.newViolation(n.config.descs.notInSite,
			n.config.typeName+".not_in",
			"must not be in list "+n.formatList(n.notInVals),
			val, n.notInValue))
	}

	if len(violations) > 0 {
		return &ValidationError{Violations: violations}
	}
	return nil
}

// evaluateRange returns a violation for lower/upper bound checks, or nil.
func (n nativeTimeCompare[T]) evaluateRange(valT T, val protoreflect.Value) *Violation {
	switch {
	case n.lower == lowerBoundNone && n.upper == upperBoundNone:
		return nil
	case n.lower == lowerBoundNone:
		if n.aboveHi(valT) {
			return n.newViolation(n.hiSite(), n.config.typeName+"."+n.ltRuleSuffix(),
				"must be "+n.hiMessage(), val, n.hi.ruleValue)
		}
	case n.upper == upperBoundNone:
		if n.belowLo(valT) {
			return n.newViolation(n.loSite(), n.gtRule(),
				"must be "+n.loMessage(), val, n.lo.ruleValue)
		}
	default:
		normalRange := n.config.compare(n.hi.value, n.lo.value) >= 0
		var failure bool
		if normalRange {
			failure = n.aboveHi(valT) || n.belowLo(valT)
		} else {
			failure = n.aboveHi(valT) && n.belowLo(valT)
		}
		if failure {
			rule, conjunction := n.gtRule()+"_"+n.ltRuleSuffix(), " and "
			if !normalRange {
				rule, conjunction = rule+"_exclusive", " or "
			}
			return n.newViolation(n.loSite(), rule,
				"must be "+n.loMessage()+conjunction+n.hiMessage(),
				val, n.lo.ruleValue)
		}
	}
	return nil
}

func (n nativeTimeCompare[T]) belowLo(value T) bool {
	if n.lower == lowerBoundGt {
		return n.config.compare(value, n.lo.value) <= 0
	}
	return n.config.compare(value, n.lo.value) < 0
}

func (n nativeTimeCompare[T]) aboveHi(value T) bool {
	if n.upper == upperBoundLt {
		return n.config.compare(value, n.hi.value) >= 0
	}
	return n.config.compare(value, n.hi.value) > 0
}

func (n nativeTimeCompare[T]) loSite() ruleSite {
	if n.lower == lowerBoundGt {
		return n.config.descs.gtSite
	}
	return n.config.descs.gteSite
}

func (n nativeTimeCompare[T]) hiSite() ruleSite {
	if n.upper == upperBoundLt {
		return n.config.descs.ltSite
	}
	return n.config.descs.lteSite
}

func (n nativeTimeCompare[T]) gtRule() string {
	if n.lower == lowerBoundGt {
		return n.config.typeName + ".gt"
	}
	return n.config.typeName + ".gte"
}

func (n nativeTimeCompare[T]) ltRuleSuffix() string {
	if n.upper == upperBoundLt {
		return "lt"
	}
	return "lte"
}

func (n nativeTimeCompare[T]) loMessage() string {
	if n.lower == lowerBoundGt {
		return "greater than " + n.config.format(n.lo.value)
	}
	return "greater than or equal to " + n.config.format(n.lo.value)
}

func (n nativeTimeCompare[T]) hiMessage() string {
	if n.upper == upperBoundLt {
		return "less than " + n.config.format(n.hi.value)
	}
	return "less than or equal to " + n.config.format(n.hi.value)
}

func (n nativeTimeCompare[T]) contains(values []T, value T) bool {
	return slices.ContainsFunc(values, func(candidate T) bool {
		return n.config.compare(value, candidate) == 0
	})
}

// formatList formats values like CEL formats a list, e.g. "[1s, 2.5s]".
func (n nativeTimeCompare[T]) formatList(values []T) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = n.config.format(value)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func (n nativeTimeCompare[T]) Tautology() bool {
	return false
}

var _ evaluator = nativeTimeCompare[time.Time]{}
