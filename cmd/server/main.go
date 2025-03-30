package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
	"github.com/nafridma/security-scanner/pkg/api"
	"github.com/nafridma/security-scanner/pkg/scanner"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	port         = flag.Int("port", 50051, "The server port")
	policyFolder = flag.String("policy-folder", "policies", "Folder containing custom policies")
)

func main() {
	flag.Parse()

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Get GitHub token from environment
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		log.Fatal("GITHUB_TOKEN environment variable is required")
	}

	// Create absolute path for policy folder
	absPath, err := filepath.Abs(*policyFolder)
	if err != nil {
		log.Fatalf("Failed to get absolute path for policy folder: %v", err)
	}

	log.Println("Using OPA (Open Policy Agent) for all policy evaluation")
	log.Println("RegEx policies have been converted to Rego policies for consistent evaluation")

	// Create scanner service
	scannerService, err := scanner.NewService(githubToken, absPath)
	if err != nil {
		log.Fatalf("Failed to create scanner service: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	api.RegisterSecurityScannerServer(grpcServer, scannerService)

	// Enable reflection for tools like grpcurl
	reflection.Register(grpcServer)

	// Start listening on the specified port
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Server started on port %d", *port)
	log.Printf("Policy folder: %s", absPath)

	// Start serving
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
