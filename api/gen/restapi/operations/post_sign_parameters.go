// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"io"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/validate"

	"github.com/choria-io/aaasvc/api/gen/models"
)

// NewPostSignParams creates a new PostSignParams object
//
// There are no default values defined in the spec.
func NewPostSignParams() PostSignParams {

	return PostSignParams{}
}

// PostSignParams contains all the bound params for the post sign operation
// typically these are obtained from a http.Request
//
// swagger:parameters PostSign
type PostSignParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*The Choria message to sign
	  Required: true
	  In: body
	*/
	Request *models.SignRequest
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewPostSignParams() beforehand.
func (o *PostSignParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.SignRequest
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			if err == io.EOF {
				res = append(res, errors.Required("request", "body", ""))
			} else {
				res = append(res, errors.NewParseError("request", "body", "", err))
			}
		} else {
			// validate body object
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			ctx := validate.WithOperationRequest(context.Background())
			if err := body.ContextValidate(ctx, route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.Request = &body
			}
		}
	} else {
		res = append(res, errors.Required("request", "body", ""))
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
