FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:8d0f6910f59bc37792470eec4edc046050adc516246a0647d35a1d30e954eb23

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/