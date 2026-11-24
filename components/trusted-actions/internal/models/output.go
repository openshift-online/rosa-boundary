package models

import (
	"github.com/openshift-online/rosa-trusted-actions/internal/actions"
	"github.com/openshift-online/rosa-trusted-actions/internal/openapi"
)

type ExecutionOutput struct {
	Message   string
	Resources []map[string]interface{}
}

func OutputFromActionResult(result *actions.ActionResult) *ExecutionOutput {
	if result == nil {
		return nil
	}

	// Actions that return no resources (delete) must still serialize as an
	// empty list rather than null.
	resources := result.Resources
	if resources == nil {
		resources = []map[string]interface{}{}
	}

	return &ExecutionOutput{
		Message:   result.Message,
		Resources: resources,
	}
}

func (o *ExecutionOutput) ToOpenAPI() openapi.ExecutionOutput {
	return openapi.ExecutionOutput{
		Message:   o.Message,
		Resources: o.Resources,
	}
}
