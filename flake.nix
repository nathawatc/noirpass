{
  description = "noirpass - minimal on-demand GPG-backed freedesktop Secret Service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system:
        f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            cargo-llvm-cov
            llvm # llvm-profdata / llvm-cov binaries driven by cargo-llvm-cov
            gnupg
            openssl # sequoia crypto backend
            capnproto # sequoia-ipc build script needs capnp
            dbus # dbus-run-session, busctl for tests
            libsecret # secret-tool for optional smoke tests
            pkg-config
          ];

          env = {
            RUST_BACKTRACE = "1";
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
            # cargo-llvm-cov looks for rustup's llvm-tools-preview unless the
            # tools are named explicitly.
            LLVM_COV = "${pkgs.llvm}/bin/llvm-cov";
            LLVM_PROFDATA = "${pkgs.llvm}/bin/llvm-profdata";
          };
        };
      });
    };
}
