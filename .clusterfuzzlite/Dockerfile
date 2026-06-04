FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:604d89aebb3e4d684af51b6b2d84ea8e8f19f2590c2558c258d90a18d057bf25

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/