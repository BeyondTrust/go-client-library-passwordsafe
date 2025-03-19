FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:b21dc1629f40008e552d1bf692f930938898efd47eda727067deaf28a1d309a7

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/