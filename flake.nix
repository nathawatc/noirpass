{
  description = "noirpass - minimal on-demand GPG-backed freedesktop Secret Service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      cargoManifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      perSystem = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          nativeBuildInputs = with pkgs; [
            capnproto
            clang
            pkg-config
          ];
          buildInputs = with pkgs; [
            openssl
          ];
          nativeCheckInputs = with pkgs; [
            dbus
            gnupg
            procps
          ];

          noirpass = pkgs.rustPlatform.buildRustPackage {
            pname = "noirpass";
            version = cargoManifest.package.version;
            src = self;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs nativeCheckInputs;
            strictDeps = true;
            doCheck = true;

            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

            postPatch = ''
              substituteInPlace tests/common/mod.rs \
                --replace-fail \
                  '.args(["--session", "--nofork", "--print-address"])' \
                  '.args(["--config-file", "${pkgs.dbus}/share/dbus-1/session.conf", "--nofork", "--print-address"])'
            '';

            postInstall = ''
              install -Dm644 systemd/noirpass.service \
                "$out/share/systemd/user/noirpass.service"
              install -Dm644 systemd/org.freedesktop.secrets.service \
                "$out/share/dbus-1/services/org.freedesktop.secrets.service"
              substituteInPlace \
                "$out/share/systemd/user/noirpass.service" \
                "$out/share/dbus-1/services/org.freedesktop.secrets.service" \
                --replace-fail /usr/bin/noirpass "$out/bin/noirpass"
            '';

            meta = {
              description = "Minimal on-demand GPG-backed freedesktop Secret Service";
              homepage = "https://codeberg.org/koharu/noirpass";
              license = pkgs.lib.licenses.asl20;
              mainProgram = "noirpass";
              platforms = systems;
            };
          };

          formatting = pkgs.runCommand "noirpass-formatting" {
            nativeBuildInputs = with pkgs; [ cargo rustfmt ];
          } ''
            cp -r ${self} source
            chmod -R u+w source
            cd source
            cargo fmt --check
            touch $out
          '';
        in
        {
          inherit
            pkgs
            nativeBuildInputs
            buildInputs
            nativeCheckInputs
            noirpass
            formatting
            ;
        });
    in
    {
      packages = nixpkgs.lib.mapAttrs (_: config: {
        inherit (config) noirpass;
        default = config.noirpass;
      }) perSystem;

      apps = nixpkgs.lib.mapAttrs (_: config: {
        noirpass = {
          type = "app";
          program = "${config.noirpass}/bin/noirpass";
          meta.description = config.noirpass.meta.description;
        };
        default = {
          type = "app";
          program = "${config.noirpass}/bin/noirpass";
          meta.description = config.noirpass.meta.description;
        };
      }) perSystem;

      devShells = nixpkgs.lib.mapAttrs (_: config: {
        default = config.pkgs.mkShell {
          packages = with config.pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            cargo-llvm-cov
            cargo-audit
            llvm
            libsecret
          ]
          ++ config.nativeBuildInputs
          ++ config.buildInputs
          ++ config.nativeCheckInputs;

          RUST_BACKTRACE = "1";
          LIBCLANG_PATH = "${config.pkgs.libclang.lib}/lib";
          LLVM_COV = "${config.pkgs.llvm}/bin/llvm-cov";
          LLVM_PROFDATA = "${config.pkgs.llvm}/bin/llvm-profdata";
        };
      }) perSystem;

      checks = nixpkgs.lib.mapAttrs (_: config: {
        package = config.noirpass;
        formatting = config.formatting;
      }) perSystem;
    };
}
