# One coherent primitive/PKIX stack, shared by TLS consumers.
{ pkgs }:
pkgs.haskellPackages.override {
  overrides = hself: _hsuper: let
    source = name: version: sha256: hself.callCabal2nix name (pkgs.runCommand "${name}-${version}-source" {
      archive = pkgs.fetchurl {
      url = "https://hackage-content.haskell.org/package/${name}-${version}/${name}-${version}.tar.gz";
      inherit sha256;
      };
    } ''
      mkdir -p $out
      tar -xzf $archive --strip-components=1 -C $out
    '') {};
  in {
    crypton = source "crypton" "2.2.1" "sha256-e6tcwf8os4nKw54mjTbrqca6gsYhjRW3VFj63c3A1dk=";
    crypton-x509 = source "crypton-x509" "1.10.0" "sha256-sAUf6+HXDQ7ed87gt8X6wHTgwpQay60xaSby5iBtsvo=";
    crypton-x509-store = source "crypton-x509-store" "1.10.0" "sha256-pSWg24kAwkua5G3CGnPIKkg/BtW4fCtULorldFEwKcc=";
    crypton-x509-system = source "crypton-x509-system" "1.10.0" "sha256-IejIYjh5vGJBcUXSVLatGLjHrW6bivTGJOgY1/OWzGw=";
    # RFC 5280 constraints persist when a subordinate CA omits the extension.
    crypton-x509-validation = pkgs.haskell.lib.overrideCabal
      (source "crypton-x509-validation" "1.10.0" "sha256-2fqGJrXme5e5Q5e3MgzqCNQTmOFh7WTOpJVuyUcwqA0=")
      (old: { patches = (old.patches or []) ++ [ ./name-constraints-inheritance.patch ]; });
  };
}
