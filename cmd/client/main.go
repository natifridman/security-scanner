package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/nafridma/security-scanner/pkg/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	addr     = flag.String("addr", "localhost:50051", "The address to connect to")
	cmd      = flag.String("cmd", "", "Command to run: list, scan-repo, scan-org")
	org      = flag.String("org", "", "GitHub organization name")
	owner    = flag.String("owner", "", "GitHub repo or org owner")
	repo     = flag.String("repo", "", "GitHub repo name")
	maxRepos = flag.Int("max-repos", 10, "Maximum number of repositories to scan for org")
	list     = flag.Bool("list", false, "List repositories (equivalent to --cmd list)")
	scan     = flag.Bool("scan", false, "Scan repository (equivalent to --cmd scan-repo)")
	scanAll  = flag.Bool("scan-all", false, "Scan all repositories (equivalent to --cmd scan-org)")
	token    = flag.String("token", "", "GitHub API token (can also be provided via GITHUB_TOKEN env var)")
)

func main() {
	flag.Parse()

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Get GitHub token from environment or command line
	githubToken := *token
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
		if githubToken == "" {
			log.Fatal("GitHub token is required. Provide via GITHUB_TOKEN environment variable or --token flag")
		}
	}

	// Set up a connection to the server
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()

	// Create client
	client := api.NewSecurityScannerClient(conn)

	// Create context with token in metadata
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+githubToken)

	// If org is provided and owner is not, use org as owner
	if *owner == "" && *org != "" {
		owner = org
	}

	// If --list flag is used, set cmd to "list"
	if *list {
		*cmd = "list"
	}

	// If --scan flag is used, set cmd to "scan-repo"
	if *scan {
		*cmd = "scan-repo"
	}

	// If --scan-all flag is used, set cmd to "scan-org"
	if *scanAll {
		*cmd = "scan-org"
	}

	// Execute command
	switch strings.ToLower(*cmd) {
	case "list":
		listRepositories(ctx, client)
	case "scan-repo":
		if *owner == "" || *repo == "" {
			log.Fatal("Owner and repo are required for scan-repo command")
		}
		scanRepository(ctx, client, *owner, *repo)
	case "scan-org":
		if *owner == "" {
			log.Fatal("Owner is required for scan-org command")
		}
		scanOrganization(ctx, client, *owner, *maxRepos)
	default:
		log.Fatal("Invalid command. Use: list, scan-repo, scan-org")
	}
}

func listRepositories(ctx context.Context, client api.SecurityScannerClient) {
	resp, err := client.ListRepositories(ctx, &api.ListRepositoriesRequest{
		Organization: *owner,
		Page:         1,
		PerPage:      50,
	})
	if err != nil {
		if strings.Contains(err.Error(), "404 Not Found") {
			log.Fatalf("Error: Organization or user '%s' not found. Please check the name and try again.", *owner)
		} else {
			log.Fatalf("Error listing repositories: %v", err)
		}
	}

	fmt.Printf("Repositories (%d):\n", resp.TotalCount)
	for _, repo := range resp.Repositories {
		fmt.Printf("- %s: %s\n", repo.Name, repo.Description)
	}
}

func scanRepository(ctx context.Context, client api.SecurityScannerClient, owner, repo string) {
	fmt.Printf("Scanning repository %s/%s...\n", owner, repo)

	resp, err := client.ScanRepository(ctx, &api.ScanRepositoryRequest{
		Organization: owner,
		Repository:   repo,
	})
	if err != nil {
		st := status.Convert(err)
		if strings.Contains(st.Message(), "404 Not Found") {
			log.Fatalf("Error: Repository '%s/%s' not found. Please check the name and try again.", owner, repo)
		} else {
			log.Fatalf("Error scanning repository: %v", err)
		}
	}

	printScanResult(resp)
}

func scanOrganization(ctx context.Context, client api.SecurityScannerClient, org string, maxRepos int) {
	fmt.Printf("Scanning organization %s (up to %d repositories)...\n", org, maxRepos)

	resp, err := client.ScanOrganization(ctx, &api.ScanOrganizationRequest{
		Organization: org,
	})
	if err != nil {
		st := status.Convert(err)
		if strings.Contains(st.Message(), "404 Not Found") {
			log.Fatalf("Error: Organization '%s' not found. Please check the name and try again.", org)
		} else {
			log.Fatalf("Error scanning organization: %v", err)
		}
	}

	fmt.Printf("Organization: %s\n", resp.Organization)
	fmt.Printf("Total repositories: %d\n", resp.TotalRepositories)
	fmt.Printf("Compliant repositories: %d\n", resp.CompliantRepositories)
	fmt.Printf("Non-compliant repositories: %d\n", resp.NonCompliantRepositories)
	fmt.Printf("Scan time: %s\n\n", resp.ScanTime)

	fmt.Printf("Repository results:\n")
	for i, result := range resp.RepositoryResults {
		fmt.Printf("\n=== Repository %d: %s ===\n", i+1, result.Repository.Name)
		printScanResult(result)
	}
}

func printScanResult(result *api.ScanResult) {
	fmt.Printf("Total violations: %d\n", len(result.Violations))

	// Count violations by severity
	violationsBySeverity := make(map[string]int)
	for _, v := range result.Violations {
		violationsBySeverity[v.Severity]++
	}

	fmt.Printf("Violation counts by severity:\n")
	for severity, count := range violationsBySeverity {
		fmt.Printf("- %s: %d\n", severity, count)
	}

	if len(result.Violations) > 0 {
		fmt.Printf("\nViolations:\n")
		for i, v := range result.Violations {
			fmt.Printf("%d. [%s] %s\n", i+1, v.Severity, v.PolicyName)
			fmt.Printf("   Resource: %s/%s\n", v.ResourceType, v.ResourceId)
			if v.Description != "" {
				fmt.Printf("   Description: %s\n", v.Description)
			}
			fmt.Println()
		}
	}
}
