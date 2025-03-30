# METADATA: {"name": "unsafe-branch-names", "description": "Detects unsafe branch names that could indicate temporary or development work", "severity": "MEDIUM"}
package github.security

# Pattern detection for unsafe branch names
unsafe_branch_patterns = {
  "temp": "temporary branch",
  "wip": "work in progress",
  "test": "test branch",
  "foo": "placeholder name",
  "bar": "placeholder name",
  "poc": "proof of concept",
  "hack": "hackathon or experimental code"
}

# Check for unsafe branch names
deny[decision] {
  # Get branch information from input
  branch := input.branches[_]
  branch_name := lower(branch.name)
  
  # Check if branch name contains unsafe pattern
  pattern := object.keys(unsafe_branch_patterns)[_]
  contains(branch_name, pattern)
  
  # Create a decision object
  decision := {
    "resource_type": "branch",
    "resource_id": branch.name,
    "details": {
      "branch_name": branch.name,
      "pattern": pattern,
      "issue": unsafe_branch_patterns[pattern],
      "protected": branch.protected
    }
  }
}

# Return true if violations exist
violations = x {
  x := count(deny) > 0
} 