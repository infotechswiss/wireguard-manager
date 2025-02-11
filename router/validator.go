package router

import (
	"gopkg.in/go-playground/validator.v9"
)

// Validator is a custom validator that wraps the go-playground validator.
type Validator struct {
	validator *validator.Validate
}

// Validate validates the given struct and returns an error if any validation constraints fail.
func (v *Validator) Validate(i interface{}) error {
	return v.validator.Struct(i)
}

// NewValidator creates and returns a new instance of Validator.
func NewValidator() *Validator {
	return &Validator{
		validator: validator.New(),
	}
}
