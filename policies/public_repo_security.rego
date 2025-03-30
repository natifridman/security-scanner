# METADATA: {"name": "public-repo-security", "description": "Enforces stricter security requirements for public repositories", "severity": "HIGH"}
package github.security

# Check if repository is public
is_public_repo {
    input.repository.private == false
}

# For public repositories, main branches must be protected
deny[decision] {
    # Only apply this policy to public repos
    is_public_repo
    
    # Get the default branch
    default_branch := input.repository.default_branch
    
    # Find the branch in branches list
    branch := input.branches[_]
    branch.name == default_branch
    
    # Check if branch is not protected
    not branch.protected
    
    # Create a decision object
    decision := {
        "resource_type": "branch",
        "resource_id": default_branch,
        "details": {
            "branch_name": default_branch,
            "issue": "Default branch in public repository must be protected",
            "repository": input.repository.full_name,
            "is_protected": false
        }
    }
}

# For public repositories, don't allow admins to bypass branch protection rules
deny[decision] {
    # Only apply this policy to public repos
    is_public_repo
    
    # Find branch protection for the default branch
    branch_name := input.repository.default_branch
    protection := input.protections[_]
    protection.branch_name == branch_name
    
    # Check if force pushes are allowed (dangerous for public repos)
    protection.allow_force_pushes == true
    
    # Create a decision object
    decision := {
        "resource_type": "protection",
        "resource_id": branch_name,
        "details": {
            "branch_name": branch_name,
            "issue": "Force pushes should not be allowed for default branch in public repository",
            "repository": input.repository.full_name
        }
    }
}

# For public repositories, require pull request reviews
deny[decision] {
    # Only apply this policy to public repos
    is_public_repo
    
    # Find branch protection for the default branch
    branch_name := input.repository.default_branch
    protection := input.protections[_]
    protection.branch_name == branch_name
    
    # Check if PR reviews are required
    not protection.require_pull_request
    
    # Create a decision object
    decision := {
        "resource_type": "protection",
        "resource_id": branch_name,
        "details": {
            "branch_name": branch_name,
            "issue": "Pull request reviews should be required for default branch in public repository",
            "repository": input.repository.full_name
        }
    }
}

# Return true if violations exist
violations = x {
    x := count(deny) > 0
} 