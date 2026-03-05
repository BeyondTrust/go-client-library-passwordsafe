---
applyTo: "**"
---
# Project General Coding Standards

This is a Go client library for BeyondTrust Password Safe. All code must follow the conventions established throughout this codebase.

## File Header

Every `.go` file must begin with a copyright comment and a package doc comment:

```go
// Copyright 2026 BeyondTrust. All rights reserved.
// Package <name> implements <description>.
package <name>
```

## Naming Conventions

- Use **PascalCase** for exported types, functions, methods, and constants.
- Use **camelCase** for unexported functions, methods, and variables.
- Suffix service/client structs with `Obj` (e.g., `AssetObj`, `ManagedAccountstObj`, `AuthenticationObj`).
- Suffix API response structs with `Response` (e.g., `AssetResponse`, `GetTokenResponse`).
- Suffix input parameter structs with `Params` or `ParametersObj` (e.g., `ValidationParams`, `AuthenticationParametersObj`).
- Unexported struct fields use camelCase (e.g., `log`, `authenticationObj`, `clientId`).
- Constants for API method names are defined in `api/constants/methods_names.go` and use PascalCase (e.g., `SecretCreateSecret`, `ManagedAccountGet`).

## Package Structure

- Each domain entity lives in its own package under `api/` (e.g., `api/assets`, `api/managed_account`, `api/secrets`).
- Shared utilities belong in `api/utils/`.
- DTOs and response types belong in `api/entities/entities.go`.
- Constants belong in `api/constants/`.
- The `logging` package defines the `Logger` interface; never use `fmt.Print*` or `log.*` directly in domain packages.

## Constructor Pattern

Every service object must expose a `NewXxxObj` constructor that accepts an `AuthenticationObj` and a `logging.Logger`:

```go
func NewAssetObj(authentication authentication.AuthenticationObj, logger logging.Logger) (*AssetObj, error) {
    return &AssetObj{
        log:               logger,
        authenticationObj: authentication,
    }, nil
}
```

## Error Handling

- Always propagate errors via return values; never silently discard them.
- Use `errors.New("message")` for simple static errors and `fmt.Errorf("context: %w", err)` for wrapped errors.
- Validate inputs at the start of public methods; return a descriptive error immediately on invalid input.
- Use early-return style — check for errors and return before the happy path.
- Call `utils.ValidateData(structInstance)` (backed by `go-playground/validator`) to validate struct input before processing.

```go
// Good
if workGroupId == "" {
    return entities.AssetResponse{}, errors.New("workGroupId is empty, please send a valid workgroup id")
}
```

## Logging

- Inject `logging.Logger` into every service struct; never use package-level loggers.
- Log HTTP calls at **Debug** level with the method and URL: `fmt.Sprintf("%v %v", "POST", url)`.
- Log operational progress at **Info** level (e.g., number of secrets being retrieved).
- Log all errors at **Error** level with enough context to diagnose the problem.
- Never log secrets, passwords, tokens, or credentials.

## HTTP & Retry

- All outbound API calls must use `utils.HttpClientObj` and go through `entities.CallSecretSafeAPIObj` to ensure consistent retry behaviour.
- Use `github.com/cenkalti/backoff/v4` `ExponentialBackOff` for request retries; pass the `ExponentialBackOff` instance from `AuthenticationObj`.
- Construct URLs using `authenticationObj.ApiUrl.JoinPath(...)` to avoid manual string concatenation.

## Input Validation

- Use `go-playground/validator` struct tags on all DTO structs that accept user input (e.g., `validate:"required,max=245"`).
- Centralise reusable validation logic in `api/utils/validator.go`.
- Sensitive length limits (certificates, keys) must be checked explicitly before further processing.

## Testing

- Unit tests live in `_test.go` files within the same package (white-box testing).
- Use `net/http/httptest` to mock HTTP endpoints; never make real network calls in unit tests.
- Test configuration is initialised in a shared `InitializeGlobalConfig()` helper called at the start of each test.
- Use `github.com/stretchr/testify` for assertions.
- Test environment values (URLs, credentials) are read from environment variables defined in `api/constants/constants.go` (e.g., `constants.FakeApiUrl`).
- Fuzz tests live under `fuzzing/<domain>/` and must not share a package with unit tests.

## Cognitive Complexity

- **Maximum cognitive complexity per function: 10.**
- This is enforced by `gocognit -ignore "_test|testdata" -over 10 .` in the CI pipeline ([.github/workflows/golint.yml](.github/workflows/golint.yml)).
- Decompose complex logic into smaller, well-named private helper functions rather than adding branches.
- Avoid deeply nested `if`/`for` blocks; prefer early returns and guard clauses.

## Commit & PR Standards

- Use [Conventional Commits](https://www.conventionalcommits.org/) for all commit messages and PR titles: `fix:`, `feat:`, `chore:`, `docs:`, `refactor:`, `test:`, etc.
- Always pin GitHub Actions and container images to a full commit SHA (not a mutable tag).
