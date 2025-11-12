// Copyright 2025 BeyondTrust. All rights reserved.
// Package utils implements common utility functions tests
package utils

import (
	"strings"
	"testing"

	"github.com/BeyondTrust/go-client-library-passwordsafe/api/entities"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
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
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
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
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
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

func TestGetOwnerDetailsOwnerIdList(t *testing.T) {
	tests := []struct {
		name             string
		data             map[string]interface{}
		signAppinResponse entities.SignAppinResponse
		expectedLen      int
		expectedOwners   []entities.OwnerDetailsOwnerId
	}{
		{
			name: "Without owners key", // with default owner from signAppinResponse
			data: map[string]interface{}{},
			signAppinResponse: entities.SignAppinResponse{
				UserId:       1,
				UserName:     "main-user",
				EmailAddress: "main@domain.com",
			},
			expectedLen: 1,
			expectedOwners: []entities.OwnerDetailsOwnerId{
				{OwnerId: 1, Owner: "main-user", Email: "main@domain.com"},
			},
		},
		{
			name: "With multiple owners",
			data: map[string]interface{}{
				"owners": []interface{}{
					map[string]interface{}{
						"owner_id": 2,
						"owner":    "secondary-user",
						"email":    "secondary@domain.com",
					},
					map[string]interface{}{
						"owner_id": 3,
						"owner":    "third-user",
						"email":    "third@domain.com",
					},
				},
			},
			signAppinResponse: entities.SignAppinResponse{
				UserId:       1,
				UserName:     "main-user",
				EmailAddress: "main@domain.com",
			},
			expectedLen: 3,
			expectedOwners: []entities.OwnerDetailsOwnerId{
				{OwnerId: 1, Owner: "main-user", Email: "main@domain.com"},
				{OwnerId: 2, Owner: "secondary-user", Email: "secondary@domain.com"},
				{OwnerId: 3, Owner: "third-user", Email: "third@domain.com"},
			},
		},
		{
			name: "Owners key present but nil", // Empty owners list, only main owner
			data: map[string]interface{}{
				"owners": nil,
			},
			signAppinResponse: entities.SignAppinResponse{
				UserId:       10,
				UserName:     "main",
				EmailAddress: "main@domain.com",
			},
			expectedLen: 1,
		},
		{
			name: "Owners with incomplete fields",
			data: map[string]interface{}{
				"owners": []interface{}{
					map[string]interface{}{
						"owner": "incomplete",
					},
				},
			},
			signAppinResponse: entities.SignAppinResponse{
				UserId:       99,
				UserName:     "main-user",
				EmailAddress: "main@domain.com",
			},
			expectedLen: 2,
			expectedOwners: []entities.OwnerDetailsOwnerId{
				{OwnerId: 99, Owner: "main-user", Email: "main@domain.com"},
				{OwnerId: 0, Owner: "incomplete", Email: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetOwnerDetailsOwnerIdList(tt.data, tt.signAppinResponse)
			require.Len(t, result, tt.expectedLen)

			if tt.expectedOwners != nil {
				require.Equal(t, tt.expectedOwners, result)
			}
		})
	}
}


func TestGetOwnerDetailsGroupIdList(t *testing.T) {
	tests := []struct {
		name              string
		data              map[string]interface{}
		groupId           int
		signAppinResponse entities.SignAppinResponse
		expectedLen       int
		expectedOwners    []entities.OwnerDetailsGroupId
	}{
		{
			name:    "Without owners key", // with default owner from signAppinResponse
			data:    map[string]interface{}{},
			groupId: 10,
			signAppinResponse: entities.SignAppinResponse{
				UserId:       1,
				Name:         "Main User",
				EmailAddress: "main@domain.com",
			},
			expectedLen: 1,
			expectedOwners: []entities.OwnerDetailsGroupId{
				{GroupId: 10, UserId: 1, Name: "Main User", Email: "main@domain.com"},
			},
		},
		{
			name: "With multiple owners",
			data: map[string]interface{}{
				"owners": []interface{}{
					map[string]interface{}{
						"group_id": 20,
						"user_id":  2,
						"name":     "Owner Two",
						"email":    "two@domain.com",
					},
					map[string]interface{}{
						"group_id": 30,
						"user_id":  3,
						"name":     "Owner Three",
						"email":    "three@domain.com",
					},
				},
			},
			groupId: 10,
			signAppinResponse: entities.SignAppinResponse{
				UserId:       1,
				Name:         "Main User",
				EmailAddress: "main@domain.com",
			},
			expectedLen: 3,
			expectedOwners: []entities.OwnerDetailsGroupId{
				{GroupId: 10, UserId: 1, Name: "Main User", Email: "main@domain.com"},
				{GroupId: 20, UserId: 2, Name: "Owner Two", Email: "two@domain.com"},
				{GroupId: 30, UserId: 3, Name: "Owner Three", Email: "three@domain.com"},
			},
		},
		{
			name: "Owners key present but nil", // Empty owners list, only main owner
			data: map[string]interface{}{
				"owners": nil,
			},
			groupId: 10,
			signAppinResponse: entities.SignAppinResponse{
				UserId:       1,
				Name:         "Main User",
				EmailAddress: "main@domain.com",
			},
			expectedLen: 1,
			expectedOwners: []entities.OwnerDetailsGroupId{
				{GroupId: 10, UserId: 1, Name: "Main User", Email: "main@domain.com"},
			},
		},
		{
			name: "Owners with incomplete fields",
			data: map[string]interface{}{
				"owners": []interface{}{
					map[string]interface{}{
						"name": "Partial Owner",
					},
				},
			},
			groupId: 5,
			signAppinResponse: entities.SignAppinResponse{
				UserId:       9,
				Name:         "Main",
				EmailAddress: "main@domain.com",
			},
			expectedLen: 2,
			expectedOwners: []entities.OwnerDetailsGroupId{
				{GroupId: 5, UserId: 9, Name: "Main", Email: "main@domain.com"},
				{GroupId: 0, UserId: 0, Name: "Partial Owner", Email: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetOwnerDetailsGroupIdList(tt.data, tt.groupId, tt.signAppinResponse)
			require.Len(t, result, tt.expectedLen)

			if tt.expectedOwners != nil {
				require.Equal(t, tt.expectedOwners, result)
			}
		})
	}
}


func TestGetUrlsDetailsList(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()
	cred1 := uuid.New()
	cred2 := uuid.New()

	tests := []struct {
		name        string
		data        map[string]interface{}
		expectedLen int
		expected    []entities.UrlDetails
	}{
		{
			name:        "Without urls key",
			data:        map[string]interface{}{},
			expectedLen: 0,
			expected:    []entities.UrlDetails{},
		},
		{
			name: "Urls key is nil",
			data: map[string]interface{}{
				"urls": nil,
			},
			expectedLen: 0,
			expected:    []entities.UrlDetails{},
		},
		{
			name: "Valid URLs list",
			data: map[string]interface{}{
				"urls": []interface{}{
					map[string]interface{}{
						"id":            id1.String(),
						"credential_id": cred1.String(),
						"url":           "https://example.com",
					},
					map[string]interface{}{
						"id":            id2.String(),
						"credential_id": cred2.String(),
						"url":           "https://beyondtrust.com",
					},
				},
			},
			expectedLen: 2,
			expected: []entities.UrlDetails{
				{
					Id:           id1,
					CredentialId: cred1,
					Url:          "https://example.com",
				},
				{
					Id:           id2,
					CredentialId: cred2,
					Url:          "https://beyondtrust.com",
				},
			},
		},
		{
			name: "Malformed UUIDs should return zero UUIDs",
			data: map[string]interface{}{
				"urls": []interface{}{
					map[string]interface{}{
						"id":            "not-a-uuid",
						"credential_id": "invalid",
						"url":           "https://bad-url.com",
					},
				},
			},
			expectedLen: 1,
			expected: []entities.UrlDetails{
				{
					Id:           uuid.Nil,
					CredentialId: uuid.Nil,
					Url:          "https://bad-url.com",
				},
			},
		},
		{
			name: "Urls key present but empty list", // Empty urls list
			data: map[string]interface{}{
				"urls": []interface{}{},
			},
			expectedLen: 0,
			expected:    []entities.UrlDetails{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetUrlsDetailsList(tt.data, "user", 1)
			require.Len(t, result, tt.expectedLen)
			require.Equal(t, tt.expected, result)
		})
	}
}