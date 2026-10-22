package service

import (
	"errors"
	"fmt"
	"net/http"
)

// Kind classifies a service error; the HTTP layer maps it to a status code.
type Kind string

// Error kinds.
const (
	KindInvalid      Kind = "invalid_request"
	KindNotFound     Kind = "not_found"
	KindNotPublished Kind = "not_published"
	KindUnmapped     Kind = "owner_unmapped"
	KindInvalidData  Kind = "invalid_workflow_data"
	KindConflict     Kind = "conflict"
	KindUpstream     Kind = "upstream_error"
)

// Error is returned by every Service method on failure.
type Error struct {
	Kind Kind
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Kind, e.Msg, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Msg)
}

func (e *Error) Unwrap() error { return e.Err }

// Status returns the HTTP status for the error kind.
func (e *Error) Status() int {
	switch e.Kind {
	case KindInvalid:
		return http.StatusBadRequest
	case KindNotFound:
		return http.StatusNotFound
	case KindNotPublished, KindConflict:
		return http.StatusConflict
	case KindUnmapped, KindInvalidData:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadGateway
	}
}

func newErr(kind Kind, msg string, err error) *Error { return &Error{Kind: kind, Msg: msg, Err: err} }

// KindOf returns the kind of err, or KindUpstream for foreign errors.
func KindOf(err error) Kind {
	var se *Error
	if errors.As(err, &se) {
		return se.Kind
	}
	return KindUpstream
}
