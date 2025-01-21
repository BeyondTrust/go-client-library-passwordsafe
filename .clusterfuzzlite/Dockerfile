FROM gcr.io/oss-fuzz-base/base-builder-go

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/