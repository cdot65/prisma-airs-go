package aisec

// CollectOptions controls a bounded all-page listing. Limit zero defaults to 50;
// Max nil defaults to 10,000 records, and an explicit pointer to zero removes the record cap.
type CollectOptions struct {
	Limit int
	Max   *int
}

// ListPage is a normalized offset page. Next takes precedence over Total when supplied.
type ListPage[T any] struct {
	Items []T
	// Done marks an explicit final page, regardless of its length.
	Done        bool
	Next, Total *int
}

// CursorPage is a native cursor page; nil Next explicitly ends the listing.
type CursorPage[T any, C comparable] struct {
	Items []T
	Next  *C
}
