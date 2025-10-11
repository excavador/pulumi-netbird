{
  description = "Pulumi NetBird provider - declarative NetBird resource management";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };

          # Provider version from provider.go
          providerVersion = "0.2.2";

          # Script to build provider binary
          build-provider = pkgs.writeShellScriptBin "build-provider" ''
            echo "🔨 Building provider binary..."
            REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            cd "$REPO_ROOT"
            export CGO_ENABLED=0
            mkdir -p bin
            go build -o bin/pulumi-resource-netbird ./provider/cmd/pulumi-resource-netbird
            echo "✅ Provider binary built: bin/pulumi-resource-netbird"
          '';

          # Script to install provider plugin
          install-provider = pkgs.writeShellScriptBin "install-provider" ''
            echo "📦 Installing Pulumi NetBird provider plugin..."
            REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            cd "$REPO_ROOT"
            
            # Build if not exists
            if [ ! -f "bin/pulumi-resource-netbird" ]; then
              ${build-provider}/bin/build-provider
            fi
            
            pulumi plugin install resource netbird ${providerVersion} \
              -f "$REPO_ROOT/bin/pulumi-resource-netbird"
            echo "✅ Provider plugin installed"
          '';

          # Script to generate Go SDK
          gen-sdk-go = pkgs.writeShellScriptBin "gen-sdk-go" ''
            echo "🔨 Generating Go SDK from provider..."
            REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            cd "$REPO_ROOT"
            export CGO_ENABLED=0
            
            # Build provider if not exists
            if [ ! -f "bin/pulumi-resource-netbird" ]; then
              echo "Building provider first..."
              ${build-provider}/bin/build-provider
            fi
            
            # Generate SDK using built binary
            pulumi package gen-sdk \
              "$REPO_ROOT/bin/pulumi-resource-netbird" \
              --language go
            echo "✅ Go SDK generated in sdk"
          '';

          # Script to generate Python SDK
          gen-sdk-python = pkgs.writeShellScriptBin "gen-sdk-python" ''
            echo "🔨 Generating Python SDK from provider..."
            REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            cd "$REPO_ROOT"
            export CGO_ENABLED=0
            
            # Build provider if not exists
            if [ ! -f "bin/pulumi-resource-netbird" ]; then
              echo "Building provider first..."
              ${build-provider}/bin/build-provider
            fi
            
            # Generate SDK using built binary
            pulumi package gen-sdk \
              "$REPO_ROOT/bin/pulumi-resource-netbird" \
              --language python \
              --out "$REPO_ROOT/sdk/python"
            
            echo "✅ Python SDK generated in sdk/python"
          '';

          # Script to generate TypeScript SDK
          gen-sdk-nodejs = pkgs.writeShellScriptBin "gen-sdk-nodejs" ''
            echo "🔨 Generating TypeScript/Node.js SDK from provider..."
            REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
            cd "$REPO_ROOT"
            export CGO_ENABLED=0
            
            # Build provider if not exists
            if [ ! -f "bin/pulumi-resource-netbird" ]; then
              echo "Building provider first..."
              ${build-provider}/bin/build-provider
            fi
            
            # Generate SDK using built binary
            pulumi package gen-sdk \
              "$REPO_ROOT/bin/pulumi-resource-netbird" \
              --language nodejs \
              --out "$REPO_ROOT/sdk/nodejs"
            
            echo "✅ TypeScript SDK generated in sdk/nodejs"
          '';

          # Script to generate all SDKs
          gen-sdk-all = pkgs.writeShellScriptBin "gen-sdk-all" ''
            echo "🔨 Generating all SDKs from provider..."
            ${gen-sdk-go}/bin/gen-sdk-go
            ${gen-sdk-python}/bin/gen-sdk-python
            ${gen-sdk-nodejs}/bin/gen-sdk-nodejs
            echo "✅ All SDKs generated"
          '';

          # Combined setup script
          setup-provider = pkgs.writeShellScriptBin "setup-provider" ''
            echo "🚀 Setting up Pulumi NetBird provider..."
            ${build-provider}/bin/build-provider
            ${install-provider}/bin/install-provider
            ${gen-sdk-go}/bin/gen-sdk-go
            echo "✅ Provider setup complete"
          '';

          packages = [
            # common
            pkgs.bash
            pkgs.git
            pkgs.jq
            pkgs.openssh
            # go
            pkgs.go_1_25
            pkgs.gopls
            pkgs.golangci-lint
            # pulumi
            pkgs.pulumi
            pkgs.pulumictl
            pkgs.pulumiPackages.pulumi-go
          ];
        in
        {
          devShells.default = pkgs.mkShell {
            nativeBuildInputs = packages ++ [
              build-provider
              install-provider
              gen-sdk-go
              gen-sdk-python
              gen-sdk-nodejs
              gen-sdk-all
              setup-provider
            ];

            shellHook = ''
              # Go development environment
              export GOPRIVATE=""
              export CGO_ENABLED=0

              echo ""
              echo "🚀 Pulumi NetBird Provider Development:"
              echo ""
              echo "  Quick Start:"
              echo "    setup-provider       # Build, install, and generate Go SDK"
              echo ""
              echo "  Provider Management:"
              echo "    build-provider       # Build provider binary"
              echo "    install-provider     # Install provider plugin"
              echo ""
              echo "  SDK Generation:"
              echo "    gen-sdk-go           # Generate Go SDK"
              echo "    gen-sdk-python       # Generate Python SDK"
              echo "    gen-sdk-nodejs       # Generate TypeScript SDK"
              echo "    gen-sdk-all          # Generate all SDKs"
              echo ""
              echo "  Development:"
              echo "    go build ./...       # Build all packages"
              echo "    go test ./...        # Test provider"
              echo "    golangci-lint run    # Lint provider"
              echo ""
              echo "  Nix Commands:"
              echo "    nix run .#setup-provider"
              echo "    nix run .#gen-sdk-go"
            '';
          };

          formatter = pkgs.nixfmt-tree;

          packages = {
            inherit build-provider;
            inherit install-provider;
            inherit gen-sdk-go;
            inherit gen-sdk-python;
            inherit gen-sdk-nodejs;
            inherit gen-sdk-all;
            inherit setup-provider;
            
            # Default package
            default = setup-provider;
          };

          apps = {
            build-provider = flake-utils.lib.mkApp { drv = build-provider; };
            install-provider = flake-utils.lib.mkApp { drv = install-provider; };
            gen-sdk-go = flake-utils.lib.mkApp { drv = gen-sdk-go; };
            gen-sdk-python = flake-utils.lib.mkApp { drv = gen-sdk-python; };
            gen-sdk-nodejs = flake-utils.lib.mkApp { drv = gen-sdk-nodejs; };
            gen-sdk-all = flake-utils.lib.mkApp { drv = gen-sdk-all; };
            setup-provider = flake-utils.lib.mkApp { drv = setup-provider; };
            
            # Default app
            default = flake-utils.lib.mkApp { drv = setup-provider; };
          };

          # Checks for nix flake check
          checks = {
            # Go linting check
            golangci-lint =
              pkgs.runCommand "golangci-lint-check"
                {
                  buildInputs = [
                    pkgs.go_1_25
                    pkgs.golangci-lint
                  ];
                }
                ''
                  cd ${./.}
                  export HOME=$(mktemp -d)
                  export CGO_ENABLED=0

                  echo "Running golangci-lint..."
                  golangci-lint run ./...

                  touch $out
                  echo "✅ golangci-lint passed"
                '';

            # Go tests check
            go-tests =
              pkgs.runCommand "go-tests-check"
                {
                  buildInputs = [ pkgs.go_1_25 ];
                }
                ''
                  cd ${./.}
                  export HOME=$(mktemp -d)
                  export CGO_ENABLED=0

                  echo "Running Go tests..."
                  go test ./...

                  touch $out
                  echo "✅ Go tests passed"
                '';

            # Build check
            build =
              pkgs.runCommand "build-check"
                {
                  buildInputs = [ pkgs.go_1_25 ];
                }
                ''
                  cd ${./.}
                  export HOME=$(mktemp -d)
                  export CGO_ENABLED=0

                  echo "Building provider..."
                  go build -o /dev/null ./provider/cmd/pulumi-resource-netbird

                  touch $out
                  echo "✅ Build passed"
                '';
          };
        }
      );
}
