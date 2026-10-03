package internal

import (
	"context"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"reflect"
	"testing"
)

func TestCollectPagesBoundaries(t *testing.T) {
	max := 3
	unlimited := 0
	negative := -1
	tests := []struct {
		name      string
		opts      aisec.CollectOptions
		pages     []aisec.ListPage[int]
		want      []int
		wantError bool
	}{
		{"explicit terminal full page", aisec.CollectOptions{Limit: 2}, []aisec.ListPage[int]{{Items: []int{1, 2}, Done: true}}, []int{1, 2}, false},
		{"cap", aisec.CollectOptions{Limit: 2, Max: &max}, []aisec.ListPage[int]{{Items: []int{1, 2}}, {Items: []int{3, 4}}}, []int{1, 2, 3}, false},
		{"unlimited", aisec.CollectOptions{Limit: 2, Max: &unlimited}, []aisec.ListPage[int]{{Items: []int{1, 2}}, {Items: []int{3}}}, []int{1, 2, 3}, false},
		{"cursor regression", aisec.CollectOptions{Limit: 1}, []aisec.ListPage[int]{{Items: []int{1}, Next: new(int)}}, nil, true},
		{"empty non-final", aisec.CollectOptions{Limit: 1}, []aisec.ListPage[int]{{Items: []int{}, Next: &max}}, nil, true},
		{"negative maximum", aisec.CollectOptions{Max: &negative}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			got, err := CollectPages(context.Background(), tt.opts, func(ctx context.Context, offset, limit int) (aisec.ListPage[int], error) {
				if calls >= len(tt.pages) {
					t.Fatal("unnecessary page fetch")
				}
				p := tt.pages[calls]
				calls++
				return p, nil
			})
			if (err != nil) != tt.wantError || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got=%v err=%v", got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := CollectPages(ctx, aisec.CollectOptions{}, func(context.Context, int, int) (aisec.ListPage[int], error) {
		t.Fatal("canceled collection fetched")
		return aisec.ListPage[int]{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCollectPagesOverreportedTotalTerminatesOnEmpty(t *testing.T) {
	total := 100
	calls := 0
	items, err := CollectPages(context.Background(), aisec.CollectOptions{Limit: 2}, func(context.Context, int, int) (aisec.ListPage[int], error) {
		calls++
		if calls == 1 {
			return aisec.ListPage[int]{Items: []int{1}, Total: &total}, nil
		}
		return aisec.ListPage[int]{Items: []int{}, Total: &total}, nil
	})
	if err != nil || len(items) != 1 || calls != 2 {
		t.Fatalf("items=%v calls=%d err=%v", items, calls, err)
	}
	items, err = CollectPages(context.Background(), aisec.CollectOptions{}, func(context.Context, int, int) (aisec.ListPage[int], error) {
		return aisec.ListPage[int]{Items: []int{}, Total: &total}, nil
	})
	if err != nil || len(items) != 0 {
		t.Fatalf("empty filtered inventory=%v %v", items, err)
	}
}
