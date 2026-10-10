package testutil

import "errors"

var (
	errBadCA = errors.New("testutil: no certificates parsed from CA PEM")
)
