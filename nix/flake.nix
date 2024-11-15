{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
        };
      in
      {
        packages = rec {
          ssr = pkgs.callPackage ./package.nix { };
          default = ssr;
        };

        devShells = {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              bear
              cachix
              libbpf
              gnumake
              git
              bpftools
              elfutils
              zlib
              linuxHeaders
              clang-tools
              llvmPackages_15.clangUseLLVM
              lldb
              pkg-config
              nixfmt-rfc-style

              # for shell
              fish
              starship
              chezmoi

              # for rust
              rustToolchain
            ];

            hardeningDisable = [
              "zerocallusedregs"
            ];


            shellHook = ''
              echo "Welcome to the development environment!"
              export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E"
            '';
          };
        };
      }
    );
}
