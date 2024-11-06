{
  inputs = {
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    systems.url = "github:nix-systems/default";
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
  };

  outputs =
    {
      self,
      nixpkgs,
      systems,
      ...
    }@inputs:
    let
      forEachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      packages = forEachSystem (system: rec {
        tcpbuffer = nixpkgs.legacyPackages.${system}.callPackage ./package.nix { };
        default = tcpbuffer;
      });

      devShells = forEachSystem (system:  
      let 
        pkgs = nixpkgs.legacyPackages.${system};
      in {
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
            pkg-config

            # for shell
            fish
            starship
            chezmoi

            # for rust
            cargo
            rustc
          ];

          shellHook = ''
            echo "Welcome to the development environment!"
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E"
            fish
          '';
        };
      });
    };
}