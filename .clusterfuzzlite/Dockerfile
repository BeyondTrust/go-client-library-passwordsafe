FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:3c67aeaa287543e8f9fdbbdc170cb1656b35115a7d7da7d3093a4f81d731eb4e

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/