fn main() {
    // Tell cargo where to find the compiled C++ shared library
    println!("cargo:rustc-link-search=native=/home/user/Documents/kinnector/kinnector-core/build/lib");
    
    // Link against the static archive of kinnector-core and all of its dependencies statically
    println!("cargo:rustc-link-lib=static=kinnector-core");
    println!("cargo:rustc-link-lib=static=stdc++");
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=z");
    println!("cargo:rustc-link-lib=static=zstd");

    // Rebuild if the library changes
    println!("cargo:rerun-if-changed=/home/user/Documents/kinnector/kinnector-core/build/lib/libkinnector-core.a");

    // Compile gRPC proto
    tonic_build::compile_protos("proto/warden.proto").unwrap();
}
