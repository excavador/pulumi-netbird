package resource

import (
	"slices"
)

// strPtr helper function to stringify a pointer safely.
func strPtr(str *string) string {
	if str == nil {
		return ""
	}

	return *str
}

// equalPtr helper function to compare string pointers safely.
func equalPtr(atrA, strB *string) bool {
	if atrA == nil && strB == nil {
		return true
	}

	if atrA == nil || strB == nil {
		return false
	}

	return *atrA == *strB
}

// equalSlice compares two []string slices, ignoring order.
func equalSlice(sliceA, sliceB []string) bool {
	if len(sliceA) != len(sliceB) {
		return false
	}

	aSorted := slices.Clone(sliceA)
	bSorted := slices.Clone(sliceB)

	slices.Sort(aSorted)
	slices.Sort(bSorted)

	for i := range aSorted {
		if aSorted[i] != bSorted[i] {
			return false
		}
	}

	return true
}

// equalSlicePtr compares two *[]string values by delegating to equalSlice.
// Treats nil and empty slice as equal (semantically the same).
func equalSlicePtr(sliceA, sliceB *[]string) bool {
	if sliceA == nil && sliceB == nil {
		return true
	}

	if sliceA == nil {
		return sliceB != nil && len(*sliceB) == 0
	}

	if sliceB == nil {
		return len(*sliceA) == 0
	}

	return equalSlice(*sliceA, *sliceB)
}

// equalBoolPtr compares two *bool values safely.
// Treats nil as equivalent to false for comparison purposes.
func equalBoolPtr(a, b *bool) bool {
	aVal := a != nil && *a
	bVal := b != nil && *b

	return aVal == bVal
}
