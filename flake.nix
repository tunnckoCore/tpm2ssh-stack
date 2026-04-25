{
  description = "tpmctl development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system:
          f (import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          }));
    in
    {
      devShells = forAllSystems (pkgs:
        let
          rustToolchain = pkgs.rust-bin.stable."1.88.0".default.override {
            extensions = [
              "clippy"
              "rust-src"
              "rustfmt"
            ];
          };
          runtimeLibs = with pkgs; [
            openssl
            tpm2-tss
          ];
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rustToolchain
              rust-analyzer
              pkg-config
              openssl
              swtpm
              tpm2-tss
              tpm2-tools
            ];

            env = {
              RUST_BACKTRACE = "1";
              LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath runtimeLibs;
            };

            shellHook = ''
              echo "tpmctl development shell"
              echo "========================"
              echo ""
              echo "rustc: $(rustc --version)"
              echo "cargo: $(cargo --version)"
              echo "swtpm: $(swtpm --version | head -n 1)"
            '';
          };
        });
    };
}
