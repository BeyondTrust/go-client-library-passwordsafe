function compile_fuzzer {
  path=$1
  function=$2
  fuzzer=$3

  compile_native_go_fuzzer $path $function $fuzzer

  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -lpthread -o $OUT/$fuzzer
}

compile_fuzzer github.com/BeyondTrust/go-client-library-passwordsafe/fuzzing/managed_accounts FuzzGetManagedAccount FuzzGetManagedAccount
compile_fuzzer github.com/BeyondTrust/go-client-library-passwordsafe/fuzzing/secrets FuzzGetSecret FuzzGetSecret