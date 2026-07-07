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
            gnupg
            capnproto # sequoia-ipc build script needs capnp
            nettle # sequoia crypto backend
            clang # nettle-sys bindgen
            dbus # dbus-run-session, busctl for tests
            libsecret # secret-tool for smoke tests
            pkg-config
          ];

          env = {
            RUST_BACKTRACE = "1";
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          };
        };
      });
    };
}
