// Command server is the araquanid service CLI. The root command runs the service
// (gRPC server, its grpc-gateway REST translation, and an operational HTTP
// server for metrics and health); subcommands provide auxiliary tooling.
package main

func main() {
	Execute()
}
