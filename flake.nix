{
  description = "leakscan: find leaked API keys and secrets";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      packages = forAll (pkgs: rec {
        leakscan = pkgs.python3Packages.buildPythonApplication {
          pname = "leakscan";
          version = "0.5.0";
          pyproject = true;
          src = ./.;
          build-system = [ pkgs.python3Packages.setuptools pkgs.python3Packages.wheel ];
          dependencies = with pkgs.python3Packages; [ click rich requests pyyaml ];
          makeWrapperArgs = [ "--prefix" "PATH" ":" "${pkgs.git}/bin" ];
          doCheck = false;
          meta = {
            description = "Find leaked API keys and secrets in code, git history, notebooks, archives and images";
            homepage = "https://github.com/Vasishta03/leakscan";
            license = pkgs.lib.licenses.mit;
            mainProgram = "leakscan";
          };
        };
        default = leakscan;
      });
      apps = forAll (pkgs: {
        default = { type = "app"; program = "${self.packages.${pkgs.system}.default}/bin/leakscan"; };
      });
    };
}
