package aisec

import (
	"context"
	"testing"
)

func TestCollectAllStopsBeforeAnotherFetchAndRejectsCycle(t *testing.T) {
	maximum := 2
	calls := 0
	fetch := func(context.Context, int) (CursorPage[int, int], error) {
		calls++
		next := 1
		return CursorPage[int, int]{Items: []int{1, 2}, Next: &next}, nil
	}
	items, err := CollectAll(context.Background(), fetch, 0, CollectOptions{Max: &maximum})
	if err != nil || len(items) != 2 || calls != 1 {
		t.Fatalf("items=%v calls=%d err=%v", items, calls, err)
	}
	if err = Paginate(context.Background(), fetch, 1, func(int) bool { return true }); err == nil {
		t.Fatal("cursor cycle accepted")
	}
}
