package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/nafridma/security-scanner/pkg/github"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// Engine represents the policy engine
type Engine struct {
	policies     map[string]Policy
	policyFolder string
}

// Policy represents a security policy
type Policy interface {
	// Name returns the name of the policy
	Name() string

	// Description returns the description of the policy
	Description() string

	// Severity returns the severity of the policy
	Severity() string

	// Evaluate evaluates the policy against the repository details
	Evaluate(repoDetails *github.RepoDetails) ([]*Violation, error)
}

// Violation represents a policy violation
type Violation struct {
	PolicyName   string
	Description  string
	Severity     string
	ResourceType string
	ResourceID   string
	Details      map[string]string
}

// NewEngine creates a new policy engine
func NewEngine(policyFolder string) (*Engine, error) {
	engine := &Engine{
		policies:     make(map[string]Policy),
		policyFolder: policyFolder,
	}

	// Load policies from the policy folder
	err := engine.loadPolicies()
	if err != nil {
		return nil, fmt.Errorf("error loading policies: %w", err)
	}

	return engine, nil
}

// loadPolicies loads all policies from the policy folder
func (e *Engine) loadPolicies() error {
	// Load built-in policies
	e.registerBuiltinPolicies()

	// Check if policy folder exists
	if _, err := os.Stat(e.policyFolder); os.IsNotExist(err) {
		// Policy folder doesn't exist, use only built-in policies
		return nil
	}

	// Read all .rego files in the policy folder
	files, err := ioutil.ReadDir(e.policyFolder)
	if err != nil {
		return fmt.Errorf("error reading policy folder: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(file.Name()))
		if ext == ".rego" {
			// Load Rego policy
			policy, err := e.loadRegoPolicy(filepath.Join(e.policyFolder, file.Name()))
			if err != nil {
				return fmt.Errorf("error loading rego policy %s: %w", file.Name(), err)
			}

			e.policies[policy.Name()] = policy
		}
	}

	return nil
}

// registerBuiltinPolicies registers built-in policies
func (e *Engine) registerBuiltinPolicies() {
	// No admin access for regular users
	e.policies["no-admin-for-users"] = &RegoPolicy{
		name:        "no-admin-for-users",
		description: "Regular users should not have admin access to repositories",
		severity:    "HIGH",
		source: `
package github.security

# Define a rule to check if a collaborator has admin permission
deny[decision] {
    # Get collaborator information from input
    collaborator := input.collaborators[_]
    
    # Check if user has admin permission and is not a bot
    collaborator.permission == "admin"
    collaborator.user.type == "User"
    
    # Create a decision object
    decision := {
        "resource_type": "collaborator",
        "resource_id": collaborator.user.login,
        "details": {
            "login": collaborator.user.login,
            "permission": collaborator.permission
        }
    }
}

# Return true if violations exist
violations = x {
    x := count(deny) > 0
}`,
	}

	// Force branch protection on main branch
	e.policies["protect-main-branch"] = &RegoPolicy{
		name:        "protect-main-branch",
		description: "Main branches must have protection rules enabled",
		severity:    "MEDIUM",
		source: `
package github.security

# Define which branches should be protected
protected_branches = {"main", "master"}

# Check if protection is missing for important branches
deny[decision] {
    # Get branch information from input
    branch := input.branches[_]
    
    # Check if it's a protected branch by name
    protected_branches[branch.name]
    
    # Check if protection is not enabled
    not branch.protected
    
    # Create a decision object
    decision := {
        "resource_type": "branch",
        "resource_id": branch.name,
        "details": {
            "branch_name": branch.name,
            "protected": branch.protected
        }
    }
}

# Return true if violations exist
violations = x {
    x := count(deny) > 0
}`,
	}

	// Blacklisted collaborators (converted from regex to Rego)
	e.policies["blacklisted-collaborators"] = &RegoPolicy{
		name:        "blacklisted-collaborators",
		description: "Prevents specific users from having access to repositories",
		severity:    "HIGH",
		source: `
package github.security

# Define blacklisted users
blacklisted_users = {
    "blacklisted-user",
    "forbidden-account"
}

# Check for blacklisted collaborators
deny[decision] {
    # Get collaborator information from input
    collaborator := input.collaborators[_]
    
    # Get the login name
    login := collaborator.user.login
    
    # Convert to lowercase for case-insensitive matching
    lower_login := lower(login)
    lower_blacklisted := [lower(name) | name := blacklisted_users[_]]
    
    # Check if login is in the blacklist (case insensitive)
    lower_login == lower_blacklisted[_]
    
    # Create a decision object
    decision := {
        "resource_type": "collaborator",
        "resource_id": login,
        "details": {
            "login": login,
            "matched_rule": "Blacklisted user",
            "permission": collaborator.permission,
            "collaborator_type": collaborator.user.type
        }
    }
}

# Return true if violations exist
violations = x {
    x := count(deny) > 0
}`,
	}
}

// GetAvailablePolicies returns the names of all available policies
func (e *Engine) GetAvailablePolicies() []string {
	policyNames := make([]string, 0, len(e.policies))
	for name := range e.policies {
		policyNames = append(policyNames, name)
	}
	return policyNames
}

// GetPolicy returns a policy by name
func (e *Engine) GetPolicy(name string) (Policy, bool) {
	policy, ok := e.policies[name]
	return policy, ok
}

// EvaluateRepository evaluates all or specified policies against a repository
func (e *Engine) EvaluateRepository(repoDetails *github.RepoDetails, policyNames []string) ([]*Violation, error) {
	var violations []*Violation

	// If no specific policies are provided, evaluate all policies
	if len(policyNames) == 0 {
		for _, policy := range e.policies {
			policyViolations, err := policy.Evaluate(repoDetails)
			if err != nil {
				return nil, fmt.Errorf("error evaluating policy %s: %w", policy.Name(), err)
			}

			violations = append(violations, policyViolations...)
		}
	} else {
		// Evaluate only specified policies
		for _, name := range policyNames {
			policy, ok := e.policies[name]
			if !ok {
				return nil, fmt.Errorf("policy not found: %s", name)
			}

			policyViolations, err := policy.Evaluate(repoDetails)
			if err != nil {
				return nil, fmt.Errorf("error evaluating policy %s: %w", policy.Name(), err)
			}

			violations = append(violations, policyViolations...)
		}
	}

	return violations, nil
}

// loadRegoPolicy loads a Rego policy from a file
func (e *Engine) loadRegoPolicy(filePath string) (*RegoPolicy, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	var metadata struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	}

	// Try to extract metadata from comments
	metadataStr := extractMetadata(string(data))
	if metadataStr != "" {
		err = json.Unmarshal([]byte(metadataStr), &metadata)
		if err != nil {
			return nil, fmt.Errorf("error parsing policy metadata: %w", err)
		}
	}

	// Use filename as policy name if metadata doesn't provide one
	if metadata.Name == "" {
		metadata.Name = strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	}

	if metadata.Severity == "" {
		metadata.Severity = "MEDIUM" // Default severity
	}

	return &RegoPolicy{
		name:        metadata.Name,
		description: metadata.Description,
		severity:    metadata.Severity,
		source:      string(data),
	}, nil
}

// extractMetadata extracts metadata from policy comments
func extractMetadata(source string) string {
	// Use strings.Index and substring operations instead of regex
	metadataPrefix := "# METADATA: "
	start := strings.Index(source, metadataPrefix)
	if start == -1 {
		return ""
	}

	start += len(metadataPrefix)
	end := strings.Index(source[start:], "\n")
	if end == -1 {
		end = len(source) - start
	}

	return source[start : start+end]
}

// RegoPolicy implements a policy using Rego language
type RegoPolicy struct {
	name        string
	description string
	severity    string
	source      string
}

func (p *RegoPolicy) Name() string {
	return p.name
}

func (p *RegoPolicy) Description() string {
	return p.description
}

func (p *RegoPolicy) Severity() string {
	return p.severity
}

func (p *RegoPolicy) Evaluate(repoDetails *github.RepoDetails) ([]*Violation, error) {
	// Convert repo details to a format suitable for Rego
	input, err := prepareRepositoryInput(repoDetails)
	if err != nil {
		return nil, fmt.Errorf("error preparing input: %w", err)
	}

	// Compile the Rego code
	ctx := context.Background()
	compiler, err := ast.CompileModules(map[string]string{
		p.name: p.source,
	})
	if err != nil {
		return nil, fmt.Errorf("error compiling rego module: %w", err)
	}

	// Prepare the Rego query
	r := rego.New(
		rego.Query("data.github.security.deny"),
		rego.Compiler(compiler),
		rego.Input(input),
	)

	// Evaluate the policy
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("error evaluating rego policy: %w", err)
	}

	// Extract violations from the result
	var violations []*Violation
	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		results, ok := rs[0].Expressions[0].Value.([]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected result format")
		}

		for _, result := range results {
			resultMap, ok := result.(map[string]interface{})
			if !ok {
				continue
			}

			resourceType, _ := resultMap["resource_type"].(string)
			resourceID, _ := resultMap["resource_id"].(string)

			details := make(map[string]string)
			if detailsMap, ok := resultMap["details"].(map[string]interface{}); ok {
				for k, v := range detailsMap {
					details[k] = fmt.Sprintf("%v", v)
				}
			}

			violations = append(violations, &Violation{
				PolicyName:   p.name,
				Description:  p.description,
				Severity:     p.severity,
				ResourceType: resourceType,
				ResourceID:   resourceID,
				Details:      details,
			})
		}
	}

	return violations, nil
}

// prepareRepositoryInput prepares repository details for Rego evaluation
func prepareRepositoryInput(repoDetails *github.RepoDetails) (map[string]interface{}, error) {
	// Convert collaborators
	collaborators := make([]map[string]interface{}, 0, len(repoDetails.Collaborators))
	for _, collab := range repoDetails.Collaborators {
		collaborators = append(collaborators, map[string]interface{}{
			"user": map[string]interface{}{
				"login": collab.User.GetLogin(),
				"id":    collab.User.GetID(),
				"type":  collab.User.GetType(),
			},
			"permission": collab.Permission,
		})
	}

	// Convert teams
	teams := make([]map[string]interface{}, 0, len(repoDetails.Teams))
	for _, team := range repoDetails.Teams {
		teams = append(teams, map[string]interface{}{
			"name":       team.GetName(),
			"id":         team.GetID(),
			"permission": team.GetPermission(),
		})
	}

	// Convert branches
	branches := make([]map[string]interface{}, 0, len(repoDetails.Branches))
	for _, branch := range repoDetails.Branches {
		branches = append(branches, map[string]interface{}{
			"name":      branch.GetName(),
			"protected": branch.GetProtected(),
		})
	}

	// Convert protections
	protections := make([]map[string]interface{}, 0, len(repoDetails.Protections))
	for _, protection := range repoDetails.Protections {
		protectionMap := map[string]interface{}{
			"branch_name": protection.BranchName,
		}

		if protection.Protection != nil {
			if protection.Protection.RequiredPullRequestReviews != nil {
				protectionMap["require_pull_request"] = true
				protectionMap["required_approving_review_count"] = protection.Protection.RequiredPullRequestReviews.RequiredApprovingReviewCount
				protectionMap["dismiss_stale_reviews"] = protection.Protection.RequiredPullRequestReviews.DismissStaleReviews
				protectionMap["require_code_owner_reviews"] = protection.Protection.RequiredPullRequestReviews.RequireCodeOwnerReviews
			} else {
				protectionMap["require_pull_request"] = false
			}

			if protection.Protection.AllowForcePushes != nil {
				protectionMap["allow_force_pushes"] = protection.Protection.AllowForcePushes.Enabled
			}

			if protection.Protection.AllowDeletions != nil {
				protectionMap["allow_deletions"] = protection.Protection.AllowDeletions.Enabled
			}
		}

		protections = append(protections, protectionMap)
	}

	// Prepare the repository info
	repoInfo := map[string]interface{}{
		"id":             repoDetails.Repository.GetID(),
		"name":           repoDetails.Repository.GetName(),
		"full_name":      repoDetails.Repository.GetFullName(),
		"private":        repoDetails.Repository.GetPrivate(),
		"default_branch": repoDetails.Repository.GetDefaultBranch(),
	}

	// Build the complete input
	input := map[string]interface{}{
		"repository":    repoInfo,
		"collaborators": collaborators,
		"teams":         teams,
		"branches":      branches,
		"protections":   protections,
	}

	return input, nil
}
