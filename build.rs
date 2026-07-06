fn main() {
    // Tell cargo where to find the compiled C++ shared library
    println!("cargo:rustc-link-search=native=/home/user/Documents/kinnector/kinnector-core/build/lib");
    
    // Link against the kinnector-core library
    println!("cargo:rustc-link-lib=dylib=kinnector-core");

    // Rebuild if the library changes
    println!("cargo:rerun-if-changed=/home/user/Documents/kinnector/kinnector-core/build/lib/libkinnector-core.so");

    // Compile gRPC proto
    tonic_build::compile_protos("proto/warden.proto").unwrap();
}
