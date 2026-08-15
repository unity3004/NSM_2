package postgres

import (
	"errors"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/lib/pq"
)

func TestTranslateError(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want error
	}{
		{"nil", nil, nil},
		{"unique violation", &pq.Error{Code: pgUniqueViolation}, entity.ErrAlreadyExists},
		{"foreign key violation", &pq.Error{Code: pgForeignKeyViolation}, entity.ErrNotFound},
		{"unrelated pq error", &pq.Error{Code: "22001"}, nil}, // string_data_right_truncation: passed through, not this func's job
		{"generic error", errors.New("dial tcp: connection refused"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateError(tt.in)
			switch {
			case tt.want != nil:
				if !errors.Is(got, tt.want) {
					t.Errorf("translateError(%v) = %v, want %v", tt.in, got, tt.want)
				}
			case tt.in == nil:
				if got != nil {
					t.Errorf("translateError(nil) = %v, want nil", got)
				}
			default:
				// "passed through unchanged" cases: got must be the same
				// error value translateError received, not nil and not a
				// domain sentinel it was never told to produce.
				if got != tt.in {
					t.Errorf("translateError(%v) = %v, want it passed through unchanged", tt.in, got)
				}
			}
		})
	}
}
