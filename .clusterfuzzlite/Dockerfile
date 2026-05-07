FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:8d306a950189d721f1950f7a1f2f941b463ccd09546fc565963988ff5740a29e

RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN go mod tidy

COPY ./.clusterfuzzlite/build.sh $SRC/