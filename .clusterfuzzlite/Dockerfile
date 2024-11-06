FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make autoconf automake libtool

RUN go get -u -d github.com/BeyondTrust/go-client-library-passwordsafe

# Dependency for one of the fuzz targets.
RUN go get github.com/ianlancetaylor/demangle

RUN git clone https://github.com/BeyondTrust/go-client-library-passwordsafe /src/go-client-library-passwordsafe

WORKDIR $SRC/go-client-library-passwordsafe

COPY .clusterfuzzlite/build.sh $SRC/