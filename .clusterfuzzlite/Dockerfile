FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make autoconf automake libtool

RUN git clone https://github.com/BeyondTrust/go-client-library-passwordsafe go-client-library-passwordsafe

WORKDIR go-client-library-passwordsafe

COPY .clusterfuzzlite/build.sh $SRC/