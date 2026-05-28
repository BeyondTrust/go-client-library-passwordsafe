FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:eb5c93a296510c9d159cd9091e72d6a2e00aef974f13785237f4fbecacc7ad4a

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/