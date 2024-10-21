{
  elfutils,
  libbpf,
  libelf,
  llvmPackages_15,
  pkg-config,
  rustPlatform,
  zlib,
}: rustPlatform.buildRustPackage { 
    pname = "tcpbuffer";
    version = "0.0.1";

    src = ../.;

    buildInputs = [
      elfutils
      zlib
      libelf
      libbpf
    ];

    nativeBuildInputs = [
      pkg-config
      llvmPackages_15.clangUseLLVM
    ];

    docheck = false;

    cargoLock = {
      lockFile = ../Cargo.lock;
      outputHashes = {
        "vmlinux-0.0.0" = "sha256-iwndss7hP3uXmeBoS3+vwnUkE/DFRPU1WdABfhRzKlQ=";
      };
    };

    hardeningDisable = [ "all" ];
}