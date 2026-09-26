
import json
from pathlib import Path

from audit_logger import log_access


class ABACEngine:
    """
    Attribute-Based Access Control Policy Engine.

    Evaluates access requests against JSON-based policies
    and provides explainable authorization decisions.
    """

    def __init__(self, policy_file="policies/policies.json"):
        self.policy_file = Path(policy_file)
        self.policies = self._load_policies()

    def _load_policies(self):
        """Load and prioritize policies from JSON."""

        if not self.policy_file.exists():
            raise FileNotFoundError(
                f"Policy file not found: {self.policy_file}"
            )

        with open(self.policy_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        policies = data.get("policies", [])

        # Higher priority policies are evaluated first.
        policies.sort(
            key=lambda policy: policy.get("priority", 0),
            reverse=True
        )

        return policies

    def reload_policies(self):
        """Reload policies from disk."""

        self.policies = self._load_policies()

    @staticmethod
    def _attribute_matches(request_value, allowed_values):
        """
        Check whether a request attribute satisfies
        a policy condition.
        """

        if request_value is None:
            return False

        if isinstance(request_value, list):
            return any(
                value in allowed_values
                for value in request_value
            )

        return request_value in allowed_values

    def _evaluate_conditions(self, request, conditions):
        """
        Evaluate every condition in a policy.

        ABAC uses AND logic:
        all conditions must be satisfied.
        """

        attribute_results = {}
        all_matched = True

        for attribute, expected_values in conditions.items():

            actual_value = request.get(attribute)

            matched = self._attribute_matches(
                actual_value,
                expected_values
            )

            attribute_results[attribute] = {
                "matched": matched,
                "expected": expected_values,
                "received": actual_value
            }

            if not matched:
                all_matched = False

        return all_matched, attribute_results

    def evaluate(self, request):
        """
        Evaluate an access request against all policies.

        Returns:
            Explainable authorization result.
        """

        if not isinstance(request, dict):
            raise ValueError(
                "Access request must be a dictionary."
            )

        policy_evaluations = []

        for policy in self.policies:

            conditions = policy.get(
                "conditions",
                {}
            )

            matched, attribute_results = (
                self._evaluate_conditions(
                    request,
                    conditions
                )
            )

            evaluation = {
                "policy_id": policy.get("policy_id"),
                "policy_name": policy.get("name"),
                "description": policy.get("description"),
                "effect": policy.get("effect"),
                "priority": policy.get(
                    "priority",
                    0
                ),
                "matched": matched,
                "attributes": attribute_results
            }

            policy_evaluations.append(evaluation)

            if matched:

                result = {
                    "decision": policy.get(
                        "effect",
                        "DENY"
                    ),
                    "policy_id": policy.get(
                        "policy_id"
                    ),
                    "policy_name": policy.get(
                        "name"
                    ),
                    "priority": policy.get(
                        "priority",
                        0
                    ),
                    "reason": policy.get(
                        "description"
                    ),
                    "matched_attributes": [
                        attribute
                        for attribute, details
                        in attribute_results.items()
                        if details["matched"]
                    ],
                    "failed_attributes": [],
                    "policy_evaluations":
                        policy_evaluations,
                    "request_id": request.get(
                        "request_id"
                    ),
                    "user_id": request.get(
                        "user_id"
                    )
                }

                return result

        # -------------------------------------------------
        # DEFAULT DENY
        # -------------------------------------------------

        failed_attributes = []

        for evaluation in policy_evaluations:

            for attribute, details in (
                evaluation["attributes"].items()
            ):

                if not details["matched"]:

                    failed_attributes.append({
                        "policy_id":
                            evaluation["policy_id"],
                        "attribute":
                            attribute,
                        "expected":
                            details["expected"],
                        "received":
                            details["received"]
                    })

        return {
            "decision": "DENY",
            "policy_id": None,
            "policy_name": None,
            "priority": 0,
            "reason":
                "No matching policy found. "
                "Access denied by default.",
            "matched_attributes": [],
            "failed_attributes":
                failed_attributes,
            "policy_evaluations":
                policy_evaluations,
            "request_id":
                request.get("request_id"),
            "user_id":
                request.get("user_id")
        }


def load_requests(
    request_file="data/access_requests.json"
):
    """Load synthetic access requests."""

    path = Path(request_file)

    if not path.exists():
        raise FileNotFoundError(
            f"Request file not found: {path}"
        )

    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    return data.get("requests", [])


if __name__ == "__main__":

    engine = ABACEngine()

    requests = load_requests()

    print("=" * 70)
    print(
        "       ATTRIBUTE-BASED ACCESS CONTROL ENGINE"
    )
    print("=" * 70)

    for request in requests:

        result = engine.evaluate(request)

        log_access(
            request,
            result
        )

        print(
            f"\nRequest ID : "
            f"{result['request_id']}"
        )

        print(
            f"User ID    : "
            f"{result['user_id']}"
        )

        print(
            f"Resource   : "
            f"{request['resource']}"
        )

        print(
            f"Action     : "
            f"{request['action']}"
        )

        print(
            f"Decision   : "
            f"{result['decision']}"
        )

        if result["policy_id"]:

            print(
                f"Policy     : "
                f"{result['policy_id']}"
            )

            print(
                f"Reason     : "
                f"{result['reason']}"
            )

        else:

            print(
                f"Reason     : "
                f"{result['reason']}"
            )

            print(
                "\nFailed Policy Attributes:"
            )

            for failure in (
                result["failed_attributes"][:10]
            ):

                print(
                    f"  Policy "
                    f"{failure['policy_id']} | "
                    f"{failure['attribute']} | "
                    f"Expected: "
                    f"{failure['expected']} | "
                    f"Received: "
                    f"{failure['received']}"
                )

        print("-" * 70)

