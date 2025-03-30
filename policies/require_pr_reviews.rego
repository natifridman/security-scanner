# METADATA: {"name": "require-pr-reviews", "description": "Ensures branches require pull request reviews", "severity": "MEDIUM"}
package github.security

# Define which branches should require PR reviews
critical_branches = {"main", "master", "production", "staging"}

# Check if PR reviews are not required for important branches
deny[decision] {
    # Get protection information from input
    protection := input.protections[_]
    
    # Check if it's a critical branch by name
    critical_branches[protection.branch_name]
    
    # Check if PR reviews are not required
    not protection.require_pull_request
    
    # Create a decision object
    decision := {
        "resource_type": "protection",
        "resource_id": protection.branch_name,
        "details": {
            "branch_name": protection.branch_name,
            "require_pull_request": false
        }
    }
}

# Check if minimum reviewers is not sufficient
deny[decision] {
    # Get protection information from input
    protection := input.protections[_]
    
    # Check if it's a critical branch by name
    critical_branches[protection.branch_name]
    
    # Check if PR reviews are required but fewer than 2 reviewers
    protection.require_pull_request
    protection.required_approving_review_count < 2
    
    # Create a decision object
    decision := {
        "resource_type": "protection",
        "resource_id": protection.branch_name,
        "details": {
            "branch_name": protection.branch_name,
            "required_approving_review_count": protection.required_approving_review_count,
            "recommended_minimum": 2
        }
    }
}

# Return true if violations exist
violations = x {
    x := count(deny) > 0
} 