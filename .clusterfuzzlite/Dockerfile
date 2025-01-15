FROM gcr.io/oss-fuzz-base/base-builder-go

RUN apt-get update && apt-get install -y make autoconf automake libtool

RUN go install github.com/AdamKorcz/go-118-fuzz-build@latest
RUN go get github.com/AdamKorcz/go-118-fuzz-build/testing

COPY . $SRC/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

RUN ls -alt

COPY ./.clusterfuzzlite/build.sh $SRC/