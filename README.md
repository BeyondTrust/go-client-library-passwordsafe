# go-client-library-passwordsafe

This Go client library makes it easier to access Password Safe APIs. Provide simplifications that significantly reduce the amount of code you need to write.

## Release Please App usage

In order to use Release Please App, we need to use [Conventional commits](https://beyondtrust.atlassian.net/wiki/spaces/DEVOPS/pages/380699165/Releasing+Software#4.-Trigger-the-app), but [here](https://github.com/angular/angular/blob/22b96b9/CONTRIBUTING.md#type) is a more comprehensive guide about some conventional commits that we can use.

Some of the more important and common commit types are:

| Type     | Description                                                   | Triggers Release Please |
| :------- | :------------------------------------------------------------ | :---------------------- |
| feat!    | Introduce a major change e.g. v1.0.0 to v2.0.0                | Yes                     |
| feat     | Introduce a minor change e.g. v1.0.0 to v1.1.0                | Yes                     |
| fix      | Introduce a patch change e.g. v1.0.0 to v1.0.1                | Yes                     |
| chore    | Could introduce a BREAKING CHANGE into the CHANGELOG          | Yes                     |
| docs     | Documentation update                                          | No                      |
| refactor | A code change that neither fixes a bug nor adds a feature     | No                      |
| test     | Adding or modifying tests                                     | No                      |
| build    | Changes that affect the build system or external dependencies | No                      |
| ci       | Changes to CI configuration files and scripts                 | No                      |

Remember, Release Please App will trigger once a PR with the conventional commit structure are merged into the main branch, so if you are working on features that are related to a Jira ticket, you can still use **feat** while developing, and because we can squash the commits once we want to merge the PR, only one commit with the conventional syntax will be on the history and on the changelog.

## Example of usage

Look at TestClient.go for example usage of the library

and execute:

```sh
go build
go run TestClient.go
```
