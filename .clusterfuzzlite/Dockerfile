FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:b97ae30610d30868ed549aed97a7ed2f827699810a5858e329f054f53a6c8f69

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/