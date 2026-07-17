FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:3b6a12725517022ed1e21a0dbb043be3d892eedc9e67285ab5c108f4d65034be

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/