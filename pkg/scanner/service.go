package scanner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	githubapi "github.com/google/go-github/v54/github"
	"github.com/nafridma/security-scanner/pkg/api"
	"github.com/nafridma/security-scanner/pkg/github"
	"github.com/nafridma/security-scanner/pkg/policy"
	"google.golang.org/grpc/metadata"
)

// Service implements the SecurityScanner gRPC service
type Service struct {
	api.UnimplementedSecurityScannerServer
	githubClient *github.Client
	policyEngine *policy.Engine
	defaultToken string
}

// NewService creates a new scanner service
func NewService(githubToken, policyFolder string) (*Service, error) {
	// Create GitHub client
	githubClient := github.NewClient(githubToken)

	// Create policy engine
	policyEngine, err := policy.NewEngine(policyFolder)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy engine: %w", err)
	}

	return &Service{
		githubClient: githubClient,
		policyEngine: policyEngine,
		defaultToken: githubToken,
	}, nil
}

// extractToken extracts the token from the context metadata
func (s *Service) extractToken(ctx context.Context) string {
	// Extract token from metadata if available
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		auth := md.Get("authorization")
		if len(auth) > 0 {
			parts := strings.Split(auth[0], " ")
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				log.Printf("Using token from request metadata")
				return parts[1]
			}
		}
	}

	// Fallback to default token
	log.Printf("Using default token")
	return s.defaultToken
}

// ListRepositories lists repositories in a GitHub organization
func (s *Service) ListRepositories(ctx context.Context, req *api.ListRepositoriesRequest) (*api.ListRepositoriesResponse, error) {
	log.Printf("Listing repositories for organization: %s", req.Organization)

	// Extract token from context
	token := s.extractToken(ctx)

	// Create client with the token
	client := github.NewClient(token)

	// Use default page size if not specified
	perPage := int(req.PerPage)
	if perPage == 0 {
		perPage = 50
	}

	// Use default page if not specified
	page := int(req.Page)
	if page == 0 {
		page = 1
	}

	// Get repositories from GitHub
	repos, _, err := client.ListRepositories(req.Organization, page, perPage)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	// Convert repositories to proto format
	protoRepos := make([]*api.Repository, 0, len(repos))
	for _, repo := range repos {
		protoRepos = append(protoRepos, s.convertRepository(repo))
	}

	return &api.ListRepositoriesResponse{
		Repositories: protoRepos,
		TotalCount:   int32(len(protoRepos)),
	}, nil
}

// GetRepository gets detailed information about a repository
func (s *Service) GetRepository(ctx context.Context, req *api.GetRepositoryRequest) (*api.RepositoryDetail, error) {
	log.Printf("Getting repository details for %s/%s", req.Organization, req.Repository)

	// Extract token from context
	token := s.extractToken(ctx)

	// Create client with the token
	client := github.NewClient(token)

	// Get repository details from GitHub
	repoDetail, err := client.GetRepositoryDetail(req.Organization, req.Repository)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository details: %w", err)
	}

	// Convert repository detail to proto format
	protoDetail := s.convertRepositoryDetail(repoDetail)

	return protoDetail, nil
}

// ScanRepository scans a repository for security policy violations
func (s *Service) ScanRepository(ctx context.Context, req *api.ScanRepositoryRequest) (*api.ScanResult, error) {
	log.Printf("Scanning repository %s/%s for policy violations", req.Organization, req.Repository)

	// Extract token from context
	token := s.extractToken(ctx)

	// Create client with the token
	client := github.NewClient(token)

	// Get repository details
	repoDetail, err := client.GetRepositoryDetail(req.Organization, req.Repository)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository details: %w", err)
	}

	// Apply policies to repository
	violations, err := s.policyEngine.EvaluateRepository(repoDetail, req.Policies)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Convert violations to proto format
	protoViolations := make([]*api.Violation, 0, len(violations))
	for _, v := range violations {
		protoViolations = append(protoViolations, s.convertViolation(*v))
	}

	// Create scan result
	return &api.ScanResult{
		Repository: s.convertRepository(repoDetail.Repository),
		Violations: protoViolations,
		Compliant:  len(violations) == 0,
		ScanTime:   time.Now().Format(time.RFC3339),
	}, nil
}

// ScanOrganization scans all repositories in an organization
func (s *Service) ScanOrganization(ctx context.Context, req *api.ScanOrganizationRequest) (*api.ScanOrganizationResult, error) {
	log.Printf("Scanning organization %s for policy violations", req.Organization)

	// Extract token from context
	token := s.extractToken(ctx)

	// Create client with the token
	client := github.NewClient(token)

	// List repositories
	repos, _, err := client.ListRepositories(req.Organization, 1, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	// Scan each repository
	repoResults := make([]*api.ScanResult, 0, len(repos))
	compliantCount := 0
	nonCompliantCount := 0

	for _, repo := range repos {
		// Get repository details
		repoDetail, err := client.GetRepositoryDetail(req.Organization, repo.GetName())
		if err != nil {
			log.Printf("Warning: failed to get details for repository %s: %v", repo.GetName(), err)
			continue
		}

		// Apply policies to repository
		violations, err := s.policyEngine.EvaluateRepository(repoDetail, req.Policies)
		if err != nil {
			log.Printf("Warning: policy evaluation failed for repository %s: %v", repo.GetName(), err)
			continue
		}

		// Convert violations to proto format
		protoViolations := make([]*api.Violation, 0, len(violations))
		for _, v := range violations {
			protoViolations = append(protoViolations, s.convertViolation(*v))
		}

		// Create scan result
		scanResult := &api.ScanResult{
			Repository: s.convertRepository(repoDetail.Repository),
			Violations: protoViolations,
			Compliant:  len(violations) == 0,
			ScanTime:   time.Now().Format(time.RFC3339),
		}

		// Add to results
		repoResults = append(repoResults, scanResult)

		// Update counts
		if scanResult.Compliant {
			compliantCount++
		} else {
			nonCompliantCount++
		}
	}

	// Create organization scan result
	return &api.ScanOrganizationResult{
		Organization:             req.Organization,
		RepositoryResults:        repoResults,
		TotalRepositories:        int32(len(repoResults)),
		CompliantRepositories:    int32(compliantCount),
		NonCompliantRepositories: int32(nonCompliantCount),
		ScanTime:                 time.Now().Format(time.RFC3339),
	}, nil
}

// Helper functions to convert types

func (s *Service) convertRepository(repo *githubapi.Repository) *api.Repository {
	return &api.Repository{
		Id:            repo.GetNodeID(),
		Name:          repo.GetName(),
		Description:   repo.GetDescription(),
		HtmlUrl:       repo.GetHTMLURL(),
		IsPrivate:     repo.GetPrivate(),
		DefaultBranch: repo.GetDefaultBranch(),
		CreatedAt:     repo.GetCreatedAt().Format(time.RFC3339),
		UpdatedAt:     repo.GetUpdatedAt().Format(time.RFC3339),
	}
}

func (s *Service) convertRepositoryDetail(detail *github.RepoDetails) *api.RepositoryDetail {
	// Convert repository
	protoRepo := s.convertRepository(detail.Repository)

	// Convert collaborators
	protoCollaborators := make([]*api.Collaborator, 0, len(detail.Collaborators))
	for _, collab := range detail.Collaborators {
		protoCollaborators = append(protoCollaborators, &api.Collaborator{
			Id:         collab.User.GetNodeID(),
			Login:      collab.User.GetLogin(),
			Type:       collab.User.GetType(),
			Permission: collab.Permission,
		})
	}

	// Convert teams
	protoTeams := make([]*api.Team, 0, len(detail.Teams))
	for _, team := range detail.Teams {
		protoTeams = append(protoTeams, &api.Team{
			Id:         team.GetNodeID(),
			Name:       team.GetName(),
			Permission: team.GetPermission(),
		})
	}

	// Convert branches
	protoBranches := make([]*api.Branch, 0, len(detail.Branches))
	for _, branch := range detail.Branches {
		protoBranches = append(protoBranches, &api.Branch{
			Name:      branch.GetName(),
			Protected: branch.GetProtected(),
		})
	}

	// Convert branch protections
	protoProtections := make([]*api.Protection, 0, len(detail.Protections))
	for _, p := range detail.Protections {
		protection := p.Protection
		if protection == nil {
			continue
		}

		protoProtection := &api.Protection{
			Branch:             p.BranchName,
			RequirePullRequest: protection.RequiredPullRequestReviews != nil,
			AllowForcePushes:   protection.AllowForcePushes != nil && protection.AllowForcePushes.Enabled,
			AllowDeletions:     protection.AllowDeletions != nil && protection.AllowDeletions.Enabled,
		}

		if protection.RequiredPullRequestReviews != nil {
			protoProtection.RequiredApprovingReviewCount = int32(protection.RequiredPullRequestReviews.RequiredApprovingReviewCount)
			protoProtection.DismissStaleReviews = protection.RequiredPullRequestReviews.DismissStaleReviews
			protoProtection.RequireCodeOwnerReviews = protection.RequiredPullRequestReviews.RequireCodeOwnerReviews
		}

		protoProtections = append(protoProtections, protoProtection)
	}

	return &api.RepositoryDetail{
		Repository:    protoRepo,
		Collaborators: protoCollaborators,
		Teams:         protoTeams,
		Branches:      protoBranches,
		Protections:   protoProtections,
	}
}

func (s *Service) convertViolation(violation policy.Violation) *api.Violation {
	return &api.Violation{
		PolicyName:   violation.PolicyName,
		Description:  violation.Description,
		Severity:     violation.Severity,
		ResourceType: violation.ResourceType,
		ResourceId:   violation.ResourceID,
		Details:      violation.Details,
	}
}
