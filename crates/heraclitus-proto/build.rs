fn main() -> Result<(), Box<dyn std::error::Error>> {
    // protox compiles .proto in pure Rust — no protoc binary required.
    let fds = protox::compile(
        ["proto/heraclitus.proto", "proto/raft.proto"],
        ["proto"],
    )?;
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    println!("cargo:rerun-if-changed=proto/heraclitus.proto");
    println!("cargo:rerun-if-changed=proto/raft.proto");
    Ok(())
}
