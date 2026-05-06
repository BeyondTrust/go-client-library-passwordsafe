FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:5fdc08e6006edce0de4f9bc0c3e08b3b5e6ef2841093b996858f5abbfd281f50

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/