// Copyright 2025 BeyondTrust. All rights reserved.
// Package utils implements common utility functions tests
package utils

import (
	"testing"
)

// MockLogger is a mock implementation of Logger for testing
type MockLogger struct{}

func (m *MockLogger) Debug(message string) {}
func (m *MockLogger) Info(message string)  {}
func (m *MockLogger) Error(message string) {}
func (m *MockLogger) Warn(message string)  {}

func TestDeleteResourceByID_UUIDValidation(t *testing.T) {
	tests := []struct {
		name           string
		resourceID     string
		validateAsUUID bool
		expectError    bool
		errorContains  string
	}{
		{
			name:           "Valid UUID",
			resourceID:     "550e8400-e29b-41d4-a716-446655440000",
			validateAsUUID: true,
			expectError:    false,
		},
		{
			name:           "Invalid UUID format",
			resourceID:     "invalid-uuid-format",
			validateAsUUID: true,
			expectError:    true,
			errorContains:  "invalid UUID format",
		},
		{
			name:           "Empty UUID",
			resourceID:     "",
			validateAsUUID: true,
			expectError:    true,
			errorContains:  "invalid UUID format",
		},
		{
			name:           "UUID with wrong length",
			resourceID:     "550e8400-e29b-41d4-a716",
			validateAsUUID: true,
			expectError:    true,
			errorContains:  "invalid UUID format",
		},
		{
			name:           "UUID with invalid characters",
			resourceID:     "550e8400-e29b-41d4-a716-44665544000g",
			validateAsUUID: true,
			expectError:    true,
			errorContains:  "invalid UUID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResourceID(tt.resourceID, "test", tt.validateAsUUID)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil for resource ID: %s", tt.resourceID)
				} else if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', but got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestDeleteResourceByID_IntegerValidation(t *testing.T) {
	tests := []struct {
		name          string
		resourceID    string
		expectError   bool
		errorContains string
	}{
		{
			name:        "Valid positive integer",
			resourceID:  "12345",
			expectError: false,
		},
		{
			name:        "Valid zero",
			resourceID:  "0",
			expectError: false,
		},
		{
			name:        "Valid negative integer",
			resourceID:  "-123",
			expectError: false,
		},
		{
			name:          "Invalid - letters",
			resourceID:    "abc123",
			expectError:   true,
			errorContains: "invalid integer format",
		},
		{
			name:          "Invalid - empty string",
			resourceID:    "",
			expectError:   true,
			errorContains: "invalid integer format",
		},
		{
			name:          "Invalid - decimal",
			resourceID:    "12.34",
			expectError:   true,
			errorContains: "invalid integer format",
		},
		{
			name:          "Invalid - special characters",
			resourceID:    "12@34",
			expectError:   true,
			errorContains: "invalid integer format",
		},
		{
			name:          "Invalid - mixed alphanumeric",
			resourceID:    "123abc",
			expectError:   true,
			errorContains: "invalid integer format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResourceID(tt.resourceID, "asset", false)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil for resource ID: %s", tt.resourceID)
				} else if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', but got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v for resource ID: %s", err, tt.resourceID)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
