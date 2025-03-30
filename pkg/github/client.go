package github

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-github/v54/github"
	"golang.org/x/oauth2"
)

// Client is a wrapper around the GitHub API client
type Client struct {
	client *github.Client
	ctx    context.Context
}

// NewClient creates a new GitHub client
func NewClient(token string) *Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)

	return &Client{
		client: github.NewClient(tc),
		ctx:    ctx,
	}
}

// ListRepositories lists all repositories in an organization or for a user
func (c *Client) ListRepositories(owner string, page, perPage int) ([]*github.Repository, int, error) {
	// First try as organization
	orgOpts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			Page:    page,
			PerPage: perPage,
		},
	}

	repos, resp, err := c.client.Repositories.ListByOrg(c.ctx, owner, orgOpts)
	if err == nil {
		return repos, resp.LastPage, nil
	}

	// If org fails, try as user
	if errResp, ok := err.(*github.ErrorResponse); ok && errResp.Response.StatusCode == http.StatusNotFound {
		userOpts := &github.RepositoryListOptions{
			ListOptions: github.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		}

		repos, resp, err := c.client.Repositories.List(c.ctx, owner, userOpts)
		if err != nil {
			return nil, 0, fmt.Errorf("error listing repositories: %w", err)
		}
		return repos, resp.LastPage, nil
	}

	return nil, 0, fmt.Errorf("error listing repositories: %w", err)
}

// GetRepository gets detailed information about a repository
func (c *Client) GetRepository(owner, repo string) (*github.Repository, error) {
	repository, _, err := c.client.Repositories.Get(c.ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("error getting repository: %w", err)
	}

	return repository, nil
}

// ListCollaborators lists all collaborators for a repository
func (c *Client) ListCollaborators(owner, repo string) ([]*github.User, error) {
	opts := &github.ListCollaboratorsOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
		Affiliation: "all",
	}

	var allCollaborators []*github.User
	for {
		collaborators, resp, err := c.client.Repositories.ListCollaborators(c.ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("error listing collaborators: %w", err)
		}

		allCollaborators = append(allCollaborators, collaborators...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allCollaborators, nil
}

// GetCollaboratorPermission gets permission level for a collaborator
func (c *Client) GetCollaboratorPermission(owner, repo, username string) (string, error) {
	permission, _, err := c.client.Repositories.GetPermissionLevel(c.ctx, owner, repo, username)
	if err != nil {
		return "", fmt.Errorf("error getting permission: %w", err)
	}

	return *permission.Permission, nil
}

// ListTeams lists all teams for a repository
func (c *Client) ListTeams(owner, repo string) ([]*github.Team, error) {
	opts := &github.ListOptions{
		PerPage: 100,
	}

	var allTeams []*github.Team
	for {
		teams, resp, err := c.client.Repositories.ListTeams(c.ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("error listing teams: %w", err)
		}

		allTeams = append(allTeams, teams...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allTeams, nil
}

// ListBranches lists all branches for a repository
func (c *Client) ListBranches(owner, repo string) ([]*github.Branch, error) {
	opts := &github.BranchListOptions{
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	var allBranches []*github.Branch
	for {
		branches, resp, err := c.client.Repositories.ListBranches(c.ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("error listing branches: %w", err)
		}

		allBranches = append(allBranches, branches...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allBranches, nil
}

// GetBranchProtection gets protection settings for a branch
func (c *Client) GetBranchProtection(owner, repo, branch string) (*github.Protection, error) {
	protection, _, err := c.client.Repositories.GetBranchProtection(c.ctx, owner, repo, branch)
	if err != nil {
		// If protection is not enabled, return nil without error
		if errResp, ok := err.(*github.ErrorResponse); ok && errResp.Response.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("error getting branch protection: %w", err)
	}

	return protection, nil
}

// GetRepositoryDetail gets detailed information about a repository including collaborators, teams, etc.
func (c *Client) GetRepositoryDetail(owner, repo string) (*RepoDetails, error) {
	// Get basic repository info
	repository, err := c.GetRepository(owner, repo)
	if err != nil {
		return nil, err
	}

	// Get collaborators
	collaborators, err := c.ListCollaborators(owner, repo)
	if err != nil {
		return nil, err
	}

	// Get collaborator permissions
	collabWithPerms := make([]*CollaboratorWithPermission, 0, len(collaborators))
	for _, collab := range collaborators {
		perm, err := c.GetCollaboratorPermission(owner, repo, *collab.Login)
		if err != nil {
			return nil, err
		}

		collabWithPerms = append(collabWithPerms, &CollaboratorWithPermission{
			User:       collab,
			Permission: perm,
		})
	}

	// Get teams
	teams, err := c.ListTeams(owner, repo)
	if err != nil {
		return nil, err
	}

	// Get branches
	branches, err := c.ListBranches(owner, repo)
	if err != nil {
		return nil, err
	}

	// Get branch protections for protected branches
	protections := make([]*BranchProtectionDetails, 0)
	for _, branch := range branches {
		if branch.GetProtected() {
			protection, err := c.GetBranchProtection(owner, repo, branch.GetName())
			if err != nil {
				return nil, err
			}

			if protection != nil {
				protections = append(protections, &BranchProtectionDetails{
					BranchName: branch.GetName(),
					Protection: protection,
				})
			}
		}
	}

	return &RepoDetails{
		Repository:    repository,
		Collaborators: collabWithPerms,
		Teams:         teams,
		Branches:      branches,
		Protections:   protections,
		FetchedAt:     time.Now().UTC(),
	}, nil
}

// CollaboratorWithPermission represents a collaborator with their permission level
type CollaboratorWithPermission struct {
	User       *github.User
	Permission string
}

// BranchProtectionDetails represents branch protection settings
type BranchProtectionDetails struct {
	BranchName string
	Protection *github.Protection
}

// RepoDetails contains detailed information about a repository
type RepoDetails struct {
	Repository    *github.Repository
	Collaborators []*CollaboratorWithPermission
	Teams         []*github.Team
	Branches      []*github.Branch
	Protections   []*BranchProtectionDetails
	FetchedAt     time.Time
}
