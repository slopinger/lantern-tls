{
  description = "Lantern's independent experimental TLS 1.3 protocol library";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    each = nixpkgs.lib.genAttrs systems;
  in {
    lib.cryptoPackages = pkgs: import ./nix/crypto-packages.nix { inherit pkgs; };
    packages = each (system: let pkgs=nixpkgs.legacyPackages.${system}; in {
      default = (self.lib.cryptoPackages pkgs).callCabal2nix "lantern-tls" self {};
    });
    checks = each (system: let
      pkgs=nixpkgs.legacyPackages.${system};
      package=self.packages.${system}.default;
      python=pkgs.python3.withPackages (p: [ p.cryptography ]);
    in {
      inherit package;
      interoperability = pkgs.runCommand "lantern-tls-interoperability" {
        nativeBuildInputs = [ python pkgs.openssl ];
      } ''
        python ${self}/test/interop.py --binary ${package}/bin/tls-echo
        python ${self}/test/pkix.py --binary ${package}/bin/tls-fetch
        python ${self}/test/client.py --binary ${package}/bin/tls-fetch
        python ${self}/test/negotiation.py --server ${package}/bin/tls-echo --client ${package}/bin/tls-fetch
        touch $out
      '';
    });
    devShells = each (system: let pkgs=nixpkgs.legacyPackages.${system}; in {
      default=(self.lib.cryptoPackages pkgs).shellFor {
        packages = _: [ self.packages.${system}.default ];
        nativeBuildInputs = [ pkgs.cabal-install pkgs.openssl
          (pkgs.python3.withPackages (p: [ p.cryptography ])) ];
      };
    });
  };
}
