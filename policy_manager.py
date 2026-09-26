import json
from pathlib import Path


class PolicyManager:
    """
    Handles loading, viewing, and managing ABAC policies.
    """

    def __init__(self, policy_file="policies/policies.json"):
        self.policy_file = Path(policy_file)
        self.policies = []
        self.version = None
        self.description = None

        self.load_policies()

    def load_policies(self):
        """Load policies from the JSON policy file."""

        if not self.policy_file.exists():
            raise FileNotFoundError(
                f"Policy file not found: {self.policy_file}"
            )

        with open(self.policy_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        self.version = data.get("version")
        self.description = data.get("description")

        self.policies = data.get("policies", [])

        self.policies.sort(
            key=lambda policy: policy.get("priority", 0),
            reverse=True
        )

        return self.policies

    def reload_policies(self):
        """Reload policies from disk."""

        return self.load_policies()

    def get_all_policies(self):
        """Return all loaded policies."""

        return self.policies

    def get_policy(self, policy_id):
        """Return a policy by its policy ID."""

        for policy in self.policies:
            if policy.get("policy_id") == policy_id:
                return policy

        return None

    def get_policies_by_effect(self, effect):
        """Return policies filtered by ALLOW or DENY."""

        effect = effect.upper()

        return [
            policy
            for policy in self.policies
            if policy.get("effect", "").upper() == effect
        ]

    def get_active_policy_count(self):
        """Return the number of configured policies."""

        return len(self.policies)

    def get_policy_summary(self):
        """Return a summary of the loaded policies."""

        allow_count = len(self.get_policies_by_effect("ALLOW"))
        deny_count = len(self.get_policies_by_effect("DENY"))

        return {
            "version": self.version,
            "total_policies": len(self.policies),
            "allow_policies": allow_count,
            "deny_policies": deny_count
        }


if __name__ == "__main__":
    manager = PolicyManager()

    summary = manager.get_policy_summary()

    print("=" * 60)
    print("             ABAC POLICY MANAGER")
    print("=" * 60)
    print(f"Policy Version : {summary['version']}")
    print(f"Total Policies : {summary['total_policies']}")
    print(f"ALLOW Policies : {summary['allow_policies']}")
    print(f"DENY Policies  : {summary['deny_policies']}")
    print("=" * 60)