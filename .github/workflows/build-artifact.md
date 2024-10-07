# ps-integration-ansible artifact

The artifact made by the `release.yml` Github Actions workflow is a Go module that is available on **Github** releases from this repository and **Jfrog Artifactory**.

## Building the artifact

To build the ansible artifact, the `release` workflow just run the command `go build` and it is saved as a workflow artifact using the named `library`.

## Publish the artifact

First, the artifact is downloaded into the job execution agent from the workflow's artifacts. Then, is uploaded into **JFrog Artifactory** repository named `eng-generic-dev-local`.