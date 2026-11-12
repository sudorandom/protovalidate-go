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
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestNativeTimeRulesMatchCEL validates timestamp and duration fields with
// native rules and with CEL only, and requires identical violations,
// including rule values.
func TestNativeTimeRulesMatchCEL(t *testing.T) {
	t.Parallel()
	timestamp := func(seconds int64, nanos int32) *timestamppb.Timestamp {
		return &timestamppb.Timestamp{Seconds: seconds, Nanos: nanos}
	}
	duration := func(seconds int64, nanos int32) *durationpb.Duration {
		return &durationpb.Duration{Seconds: seconds, Nanos: nanos}
	}
	timestampRules := func(rules validate.TimestampRules_builder) *validate.FieldRules {
		return validate.FieldRules_builder{Timestamp: rules.Build()}.Build()
	}
	durationRules := func(rules validate.DurationRules_builder) *validate.FieldRules {
		return validate.FieldRules_builder{Duration: rules.Build()}.Build()
	}
	tests := []struct {
		name  string
		rules *validate.FieldRules
		value proto.Message
		valid bool
	}{
		{
			name:  "timestamp_const",
			rules: timestampRules(validate.TimestampRules_builder{Const: timestamp(1, 500)}),
			value: timestamp(1, 0),
		},
		{
			name:  "timestamp_const_valid",
			rules: timestampRules(validate.TimestampRules_builder{Const: timestamp(1, 500)}),
			value: timestamp(1, 500),
			valid: true,
		},
		{
			name:  "timestamp_gt_boundary",
			rules: timestampRules(validate.TimestampRules_builder{Gt: timestamp(10, 0)}),
			value: timestamp(10, 0),
		},
		{
			name:  "timestamp_gte_boundary",
			rules: timestampRules(validate.TimestampRules_builder{Gte: timestamp(10, 0)}),
			value: timestamp(10, 0),
			valid: true,
		},
		{
			name:  "timestamp_lt_boundary",
			rules: timestampRules(validate.TimestampRules_builder{Lt: timestamp(10, 0)}),
			value: timestamp(10, 0),
		},
		{
			name:  "timestamp_lte_nanos",
			rules: timestampRules(validate.TimestampRules_builder{Lte: timestamp(10, 0)}),
			value: timestamp(10, 1),
		},
		{
			name:  "timestamp_gt_lt",
			rules: timestampRules(validate.TimestampRules_builder{Gt: timestamp(0, 0), Lt: timestamp(10, 0)}),
			value: timestamp(10, 0),
		},
		{
			name:  "timestamp_gte_lte_valid",
			rules: timestampRules(validate.TimestampRules_builder{Gte: timestamp(0, 0), Lte: timestamp(10, 0)}),
			value: timestamp(10, 0),
			valid: true,
		},
		{
			name:  "timestamp_gt_lt_exclusive",
			rules: timestampRules(validate.TimestampRules_builder{Gt: timestamp(10, 0), Lt: timestamp(5, 0)}),
			value: timestamp(7, 0),
		},
		{
			name:  "timestamp_gte_lte_exclusive",
			rules: timestampRules(validate.TimestampRules_builder{Gte: timestamp(10, 0), Lte: timestamp(5, 0)}),
			value: timestamp(5, 1),
		},
		{
			name:  "timestamp_gt_lt_exclusive_valid",
			rules: timestampRules(validate.TimestampRules_builder{Gt: timestamp(10, 0), Lt: timestamp(5, 0)}),
			value: timestamp(11, 0),
			valid: true,
		},
		{
			name: "timestamp_const_and_range",
			rules: timestampRules(validate.TimestampRules_builder{
				Const: timestamp(946684800, 0),
				Gte:   timestamp(4102444800, 999999999),
			}),
			value: timestamp(-62135596800, 0),
		},
		{
			name:  "timestamp_value_unnormalized_nanos",
			rules: timestampRules(validate.TimestampRules_builder{Gt: timestamp(5, 0)}),
			value: timestamp(5, -5),
		},
		{
			name:  "timestamp_value_past_max",
			rules: timestampRules(validate.TimestampRules_builder{Lt: timestamp(0, 0)}),
			value: timestamp(253402300800, 0),
		},
		{
			name:  "duration_const",
			rules: durationRules(validate.DurationRules_builder{Const: duration(90, 0)}),
			value: duration(-1, -500000000),
		},
		{
			name:  "duration_gt_lte",
			rules: durationRules(validate.DurationRules_builder{Gt: duration(1, 0), Lte: duration(60, 0)}),
			value: duration(60, 1),
		},
		{
			name:  "duration_gte_lt_exclusive",
			rules: durationRules(validate.DurationRules_builder{Gte: duration(60, 0), Lt: duration(1, 0)}),
			value: duration(30, 0),
		},
		{
			name:  "duration_lt_fraction",
			rules: durationRules(validate.DurationRules_builder{Lt: duration(0, 1)}),
			value: duration(0, 1),
		},
		{
			name:  "duration_in",
			rules: durationRules(validate.DurationRules_builder{In: []*durationpb.Duration{duration(0, 1), duration(-1, -500000000)}}),
			value: duration(1, 0),
		},
		{
			name:  "duration_in_valid",
			rules: durationRules(validate.DurationRules_builder{In: []*durationpb.Duration{duration(0, 1), duration(1, 0)}}),
			value: duration(1, 0),
			valid: true,
		},
		{
			name: "duration_not_in_and_range",
			rules: durationRules(validate.DurationRules_builder{
				Gte:   duration(5, 0),
				NotIn: []*durationpb.Duration{duration(1, 0)},
			}),
			value: duration(1, 0),
		},
		{
			name:  "duration_value_saturated",
			rules: durationRules(validate.DurationRules_builder{Lt: duration(1, 0)}),
			value: duration(315576000001, 0),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			msgType := newDynamicTimeMessageType(t, test.value.ProtoReflect().Descriptor(), test.rules)
			msg := dynamicpb.NewMessage(msgType.Descriptor())
			msg.Set(msgType.Descriptor().Fields().ByName("value"), protoreflect.ValueOfMessage(test.value.ProtoReflect()))

			native, err := New(WithDisableLazy(), WithMessageDescriptors(msgType.Descriptor()))
			require.NoError(t, err)
			evals := findFieldEvaluators(t, native, msgType.Descriptor(), "value")
			evaluatorType := "nativeTimeCompare[time.Time]"
			if _, isDuration := test.value.(*durationpb.Duration); isDuration {
				evaluatorType = "nativeTimeCompare[time.Duration]"
			}
			assertHasEvaluatorType(t, evals, evaluatorType)
			assertNoCELPrograms(t, evals)
			celOnly, err := New(WithDisableLazy(), WithMessageDescriptors(msgType.Descriptor()), WithDisableNativeRules())
			require.NoError(t, err)

			nativeErr, celErr := native.Validate(msg), celOnly.Validate(msg)
			if test.valid {
				require.NoError(t, celErr)
				require.NoError(t, nativeErr)
				return
			}
			var nativeValErr, celValErr *ValidationError
			require.ErrorAs(t, celErr, &celValErr)
			require.ErrorAs(t, nativeErr, &nativeValErr)
			assert.True(t, proto.Equal(celValErr.ToProto(), nativeValErr.ToProto()),
				"native: %v\ncel: %v", nativeValErr, celValErr)
			require.Len(t, nativeValErr.Violations, len(celValErr.Violations))
			for i, celViolation := range celValErr.Violations {
				nativeViolation := nativeValErr.Violations[i]
				assert.True(t, equalTimeRuleValues(celViolation.RuleValue, nativeViolation.RuleValue),
					"violation[%d] RuleValue differs", i)
				assert.Equal(t, celViolation.RuleDescriptor, nativeViolation.RuleDescriptor)
			}
		})
	}
}

func TestTryBuildNativeTimeRules_ReturnsNil(t *testing.T) {
	t.Parallel()
	timestampDesc := (*timestamppb.Timestamp)(nil).ProtoReflect().Descriptor()
	durationDesc := (*durationpb.Duration)(nil).ProtoReflect().Descriptor()
	tests := []struct {
		name        string
		rules       *validate.FieldRules
		messageDesc protoreflect.MessageDescriptor
	}{
		{"no_rules", validate.FieldRules_builder{}.Build(), timestampDesc},
		{"not_time_message", validate.FieldRules_builder{
			Timestamp: validate.TimestampRules_builder{Gt: &timestamppb.Timestamp{}}.Build(),
		}.Build(), (*validate.FieldRules)(nil).ProtoReflect().Descriptor()},
		{"example_only", validate.FieldRules_builder{
			Timestamp: validate.TimestampRules_builder{Example: []*timestamppb.Timestamp{{}}}.Build(),
		}.Build(), timestampDesc},
		{"timestamp_gt_now", validate.FieldRules_builder{
			Timestamp: validate.TimestampRules_builder{Const: &timestamppb.Timestamp{}, GtNow: new(true)}.Build(),
		}.Build(), timestampDesc},
		{"timestamp_lt_now", validate.FieldRules_builder{
			Timestamp: validate.TimestampRules_builder{LtNow: new(true)}.Build(),
		}.Build(), timestampDesc},
		{"timestamp_within", validate.FieldRules_builder{
			Timestamp: validate.TimestampRules_builder{Gt: &timestamppb.Timestamp{}, Within: &durationpb.Duration{Seconds: 1}}.Build(),
		}.Build(), timestampDesc},
		{"timestamp_invalid_nanos", validate.FieldRules_builder{
			Timestamp: validate.TimestampRules_builder{Const: &timestamppb.Timestamp{Nanos: 1000000000}}.Build(),
		}.Build(), timestampDesc},
		{"timestamp_before_min", validate.FieldRules_builder{
			Timestamp: validate.TimestampRules_builder{Gt: &timestamppb.Timestamp{Seconds: -62135596801}}.Build(),
		}.Build(), timestampDesc},
		{"duration_mixed_sign", validate.FieldRules_builder{
			Duration: validate.DurationRules_builder{Const: &durationpb.Duration{Seconds: 1, Nanos: -1}}.Build(),
		}.Build(), durationDesc},
		{"duration_too_large", validate.FieldRules_builder{
			Duration: validate.DurationRules_builder{Lt: &durationpb.Duration{Seconds: 315576000000}}.Build(),
		}.Build(), durationDesc},
		{"duration_in_too_large", validate.FieldRules_builder{
			Duration: validate.DurationRules_builder{In: []*durationpb.Duration{{Seconds: 1}, {Seconds: 315576000000}}}.Build(),
		}.Build(), durationDesc},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Nil(t, tryBuildNativeTimeRules(base{}, test.rules, test.messageDesc))
		})
	}
}

func TestNativeTimeRulesClearHandledRules(t *testing.T) {
	t.Parallel()
	rules := validate.FieldRules_builder{
		Duration: validate.DurationRules_builder{
			Const:   &durationpb.Duration{Seconds: 1},
			Gt:      &durationpb.Duration{},
			In:      []*durationpb.Duration{{Seconds: 1}},
			Example: []*durationpb.Duration{{Seconds: 1}},
		}.Build(),
	}.Build()
	eval := tryBuildNativeTimeRules(base{}, rules, (*durationpb.Duration)(nil).ProtoReflect().Descriptor())
	require.NotNil(t, eval)
	assert.False(t, eval.Tautology())
	// Only the rule CEL still has to evaluate remains.
	assert.True(t, proto.Equal(validate.DurationRules_builder{
		Example: []*durationpb.Duration{{Seconds: 1}},
	}.Build(), rules.GetDuration()))
}

// newDynamicTimeMessageType returns a dynamic message type with a "value"
// field of the given well-known message type and rules.
func newDynamicTimeMessageType(
	t testing.TB,
	valueDesc protoreflect.MessageDescriptor,
	rules *validate.FieldRules,
) protoreflect.MessageType {
	t.Helper()
	registry := new(protoregistry.Files)
	require.NoError(t, registry.RegisterFile(validate.File_buf_validate_validate_proto))
	require.NoError(t, registry.RegisterFile(valueDesc.ParentFile()))
	return newDynamicMessageTypeWithRegistry(t, registry, "test.time", "Msg", &descriptorpb.FieldDescriptorProto{
		Name:     new("value"),
		Number:   proto.Int32(1),
		Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
		TypeName: new("." + string(valueDesc.FullName())),
		Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		Options:  fieldOpts(rules),
	})
}

func equalTimeRuleValues(left, right protoreflect.Value) bool {
	switch {
	case !left.IsValid() || !right.IsValid():
		return left.IsValid() == right.IsValid()
	case isMessageValue(left) && isMessageValue(right):
		return proto.Equal(left.Message().Interface(), right.Message().Interface())
	case isListValue(left) && isListValue(right):
		if left.List().Len() != right.List().Len() {
			return false
		}
		for i := range left.List().Len() {
			if !equalTimeRuleValues(left.List().Get(i), right.List().Get(i)) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isMessageValue(value protoreflect.Value) bool {
	_, ok := value.Interface().(protoreflect.Message)
	return ok
}

func isListValue(value protoreflect.Value) bool {
	_, ok := value.Interface().(protoreflect.List)
	return ok
}
