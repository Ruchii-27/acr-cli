// Code generated by mockery v2.27.1. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// ORASClientInterface is an autogenerated mock type for the ORASClientInterface type
type ORASClientInterface struct {
	mock.Mock
}

// Annotate provides a mock function with given fields: ctx, reference, artifactType, annotations
func (_m *ORASClientInterface) Annotate(ctx context.Context, reference string, artifactType string, annotations map[string]string) error {
	ret := _m.Called(ctx, reference, artifactType, annotations)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, map[string]string) error); ok {
		r0 = rf(ctx, reference, artifactType, annotations)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DiscoverLifecycleAnnotation provides a mock function with given fields: ctx, reference, artifactType
func (_m *ORASClientInterface) DiscoverLifecycleAnnotation(ctx context.Context, reference string, artifactType string) (bool, error) {
	ret := _m.Called(ctx, reference, artifactType)

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (bool, error)); ok {
		return rf(ctx, reference, artifactType)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) bool); ok {
		r0 = rf(ctx, reference, artifactType)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, reference, artifactType)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewORASClientInterface interface {
	mock.TestingT
	Cleanup(func())
}

// NewORASClientInterface creates a new instance of ORASClientInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewORASClientInterface(t mockConstructorTestingTNewORASClientInterface) *ORASClientInterface {
	mock := &ORASClientInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}