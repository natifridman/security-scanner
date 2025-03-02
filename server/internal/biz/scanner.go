package biz

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/go-github/v69/github"
	"github.com/open-policy-agent/opa/v1/rego"
)

// ScannerRepo is a Scanner model.
type Scanner struct {
	Repository   string
	ScannedRepos []RepositoryInfo
}

// permission data
type RepositoryPermissions struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Source   string `json:"source"`
}

// repository data
type RepositoryInfo struct {
	Name          string                  `json:"name"`
	FullName      string                  `json:"full_name"`
	Owner         string                  `json:"owner"`
	Visibility    string                  `json:"visibility"`
	Private       bool                    `json:"private"`
	Description   string                  `json:"description"`
	RepoURL       string                  `json:"repo_url"`
	DefaultBranch string                  `json:"default_branch"`
	LastUpdated   string                  `json:"last_updated"`
	Permissions   []RepositoryPermissions `json:"permissions"`
	Result        string                  `json:"result"`
}

// ScannerRepo is a Scanner repo.
type ScannerRepo interface {
	Save(context.Context, *Scanner) (*Scanner, error)
	Update(context.Context, *Scanner) (*Scanner, error)
	FindByID(context.Context, int64) (*Scanner, error)
	ListByHello(context.Context, string) ([]*Scanner, error)
	ListAll(context.Context) ([]*Scanner, error)
}

// ScannerUsecase is a Scanner usecase.
type ScannerUsecase struct {
	repo ScannerRepo
	log  *log.Helper
}

var policies = []string{
	// Allow only public repos
	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.private == false
	}
	`,
}

// NewScannerUsecase new a Scanner usecase.
func NewScannerUsecase(repo ScannerRepo, logger log.Logger) *ScannerUsecase {
	return &ScannerUsecase{repo: repo, log: log.NewHelper(logger)}
}

// CreateScanner creates a Scanner, and returns the new Scanner.
func (uc *ScannerUsecase) CreateScanner(ctx context.Context, s *Scanner) (*Scanner, error) {
	uc.log.WithContext(ctx).Infof("CreateScanner: %v", s.Repository)
	uc.log.WithContext(ctx).Infof("Connecting Github...")
	org := s.Repository
	repositories := uc.ScanOrg(org)
	s.ScannedRepos = repositories
	// uc.log.WithContext(ctx).Infof("found repossss: %v", repositories[0])
	return uc.repo.Save(ctx, s)
}

// fetches repositories and scan
func (uc *ScannerUsecase) ScanOrg(org string) []RepositoryInfo {
	client := getGitHubClient()

	ctx := context.Background()
	opt := &github.RepositoryListByOrgOptions{Type: "all"}
	var allRepos []*github.Repository
	var scannedRepos []RepositoryInfo

	uc.log.WithContext(ctx).Info("Fetching repositories for organization: %s", org)

	// Fetch all repositories in the organization
	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
		if err != nil {
			uc.log.WithContext(ctx).Info("Error fetching repositories for %s: %v", org, err)
		}

		allRepos = append(allRepos, repos...)
		uc.log.WithContext(ctx).Info("Fetched %d repositories so far...", len(allRepos))

		if resp.NextPage == 0 {
			uc.log.WithContext(ctx).Info("No more pages to fetch.")
			break
		}
		opt.Page = resp.NextPage
	}

	uc.log.WithContext(ctx).Info("Total repositories found: %d", len(allRepos))

	// Process each repository
	for _, repo := range allRepos {
		repoInfo := uc.getRepository(ctx, org, repo, client)
		uc.log.WithContext(ctx).Info("Processing repository: %s", repoInfo.FullName)

		// Evaluate the repository against the policy
		success, err := uc.evaluatePolicy(policies[0], repoInfo)
		if err != nil {
			uc.log.WithContext(ctx).Info("Policy evaluation error for %s: %v", repoInfo.FullName, err)
			if strings.Contains(err.Error(), "rego_parse_error") {
				repoInfo.Result = "Rego Parsing Error"
			} else {
				repoInfo.Result = err.Error() // General error
			}
		} else if success {
			repoInfo.Result = "Success"
		} else {
			repoInfo.Result = "Failure"
		}
		scannedRepos = append(scannedRepos, repoInfo)
	}

	uc.log.WithContext(ctx).Info("Scan complete. Returning results.")
	return scannedRepos
}

// get repository info
func (uc *ScannerUsecase) getRepository(ctx context.Context, org string, repo *github.Repository, client *github.Client) RepositoryInfo {
	repoDetails, _, err := client.Repositories.Get(ctx, org, repo.GetName())
	if err != nil {
		uc.log.WithContext(ctx).Info("Skipping %s due to error: %v", repo.GetName(), err)
		return RepositoryInfo{}
	}

	// collaborator/team permissions
	// permissions := FetchRepositoryPermissions(ctx, repoDetails, org, client)

	// Return repo data
	return NormalizeRepoData(repoDetails)
}

// evaluatePolicy runs the repository data against the provided Rego policy
func (uc *ScannerUsecase) evaluatePolicy(policy string, input interface{}) (bool, error) {
	ctx := context.Background()

	r := rego.New(
		rego.Query("data.repository"),
		rego.Module("repository.rego", policy),
		rego.Input(input),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to prepare rego query: %w", err)
	}

	rs, err := query.Eval(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		policyResults, ok := rs[0].Expressions[0].Value.(map[string]interface{})
		if !ok {
			return false, fmt.Errorf("invalid policy evaluation result format")
		}

		// Check for deny
		if deny, exists := policyResults["deny"].(bool); exists && deny {
			return false, nil
		}
		// Check for allow
		if allow, exists := policyResults["allow"].(bool); exists && allow {
			return true, nil
		}
	}
	// Default: deny if no explicit allow
	return false, nil
}

func NormalizeRepoData(repo *github.Repository) RepositoryInfo {
	return RepositoryInfo{
		Name:          repo.GetName(),
		FullName:      repo.GetFullName(),
		Owner:         repo.GetOwner().GetLogin(),
		Visibility:    repo.GetVisibility(),
		Private:       repo.GetPrivate(),
		Description:   repo.GetDescription(),
		RepoURL:       repo.GetHTMLURL(),
		DefaultBranch: repo.GetDefaultBranch(),
		LastUpdated:   repo.GetUpdatedAt().String(),
	}
}
