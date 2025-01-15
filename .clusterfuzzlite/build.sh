#!/bin/bash -eu

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     $LIB_FUZZING_ENGINE /path/to/library.a

function compile_fuzzer {
  path=$1
  function=$2
  fuzzer=$3

  compile_go_fuzzer $path $function $fuzzer

  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -lpthread -o $OUT/$fuzzer
}

compile_fuzzer ./fuzzing/managed_accounts FuzzGetManagedAccount managed_account_fuzzer
compile_fuzzer ./fuzzing/secrets FuzzGetSecret secrets_fuzzer