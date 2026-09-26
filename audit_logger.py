from database import initialize_database, insert_access_log


def log_access(request, result):
    """
    Log an ABAC authorization decision.

    Every access attempt is recorded regardless
    of whether access is allowed or denied.
    """

    initialize_database()

    insert_access_log(
        request=request,
        decision=result.get("decision"),
        policy_id=result.get("policy_id"),
        policy_name=result.get("policy_name"),
        reason=result.get("reason")
    )


if __name__ == "__main__":
    print("Audit logger module ready.")