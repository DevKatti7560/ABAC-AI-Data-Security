
import streamlit as st
import pandas as pd

from abac_engine import ABACEngine
from database import initialize_database, insert_access_log, get_access_logs


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="ABAC AI Data Security",
    page_icon="🔐",
    layout="wide"
)


# ---------------------------------------------------------
# INITIALIZATION
# ---------------------------------------------------------

initialize_database()

engine = ABACEngine()


# ---------------------------------------------------------
# CUSTOM CSS
# ---------------------------------------------------------

st.markdown(
    """
    <style>

    .main-title {
        font-size: 38px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 17px;
        color: #888888;
        margin-bottom: 25px;
    }

    .decision-allow {
        padding: 20px;
        border-radius: 10px;
        border: 2px solid #2ecc71;
        background-color: rgba(46, 204, 113, 0.10);
        text-align: center;
        font-size: 24px;
        font-weight: bold;
    }

    .decision-deny {
        padding: 20px;
        border-radius: 10px;
        border: 2px solid #e74c3c;
        background-color: rgba(231, 76, 60, 0.10);
        text-align: center;
        font-size: 24px;
        font-weight: bold;
    }

    .info-box {
        padding: 15px;
        border-radius: 8px;
        background-color: rgba(128, 128, 128, 0.10);
        margin-top: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.markdown(
    '<div class="main-title">🔐 ABAC AI Data Security</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="subtitle">
    Attribute-Based Access Control for Secure AI Dataset Management
    </div>
    """,
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# LOAD AUDIT DATA
# ---------------------------------------------------------

logs = get_access_logs()

if logs:

    columns = [
        "ID",
        "Request ID",
        "User ID",
        "Role",
        "Department",
        "Resource",
        "Classification",
        "Action",
        "Purpose",
        "Decision",
        "Policy ID",
        "Policy Name",
        "Reason",
        "Timestamp"
    ]

    df = pd.DataFrame(logs, columns=columns)

else:

    df = pd.DataFrame()



# ---------------------------------------------------------
# SECURITY DASHBOARD
# ---------------------------------------------------------

st.subheader("📊 Security Dashboard")

total_requests = len(df)

if total_requests > 0:

    allowed_requests = len(
        df[df["Decision"] == "ALLOW"]
    )

    denied_requests = len(
        df[df["Decision"] == "DENY"]
    )

    denial_rate = (
        denied_requests / total_requests
    ) * 100

else:

    allowed_requests = 0
    denied_requests = 0
    denial_rate = 0


total_policies = len(engine.policies)


# ---------------------------------------------------------
# METRIC CARDS
# ---------------------------------------------------------

col1, col2, col3, col4, col5 = st.columns(5)

with col1:

    st.metric(
        "Total Requests",
        total_requests
    )

with col2:

    st.metric(
        "Allowed",
        allowed_requests
    )

with col3:

    st.metric(
        "Denied",
        denied_requests
    )

with col4:

    st.metric(
        "Denial Rate",
        f"{denial_rate:.1f}%"
    )

with col5:

    st.metric(
        "Active Policies",
        total_policies
    )


st.divider()


# ---------------------------------------------------------
# SECURITY ANALYTICS
# ---------------------------------------------------------

if not df.empty:

    chart_col1, chart_col2 = st.columns(2)

    # -----------------------------------------------------
    # ALLOW VS DENY
    # -----------------------------------------------------

    with chart_col1:

        st.write("### Access Decisions")

        decision_counts = (
            df["Decision"]
            .value_counts()
            .rename_axis("Decision")
            .reset_index(name="Count")
        )

        st.bar_chart(
            decision_counts.set_index("Decision")
        )


    # -----------------------------------------------------
    # ACCESS BY ROLE
    # -----------------------------------------------------

    with chart_col2:

        st.write("### Access Attempts by Role")

        role_counts = (
            df["Role"]
            .value_counts()
            .rename_axis("Role")
            .reset_index(name="Count")
        )

        st.bar_chart(
            role_counts.set_index("Role")
        )


    st.divider()


    chart_col3, chart_col4 = st.columns(2)


    # -----------------------------------------------------
    # ACCESS BY ACTION
    # -----------------------------------------------------

    with chart_col3:

        st.write("### Access by Action")

        action_counts = (
            df["Action"]
            .value_counts()
            .rename_axis("Action")
            .reset_index(name="Count")
        )

        st.bar_chart(
            action_counts.set_index("Action")
        )


    # -----------------------------------------------------
    # MOST ACCESSED RESOURCES
    # -----------------------------------------------------

    with chart_col4:

        st.write("### Most Accessed Resources")

        resource_counts = (
            df["Resource"]
            .value_counts()
            .head(10)
            .rename_axis("Resource")
            .reset_index(name="Count")
        )

        st.bar_chart(
            resource_counts.set_index("Resource")
        )


    st.divider()


    # -----------------------------------------------------
    # POLICY USAGE
    # -----------------------------------------------------

    st.write("### 📋 Policy Usage")

    policy_usage = (
        df[df["Policy ID"].notna()]
        ["Policy ID"]
        .value_counts()
        .rename_axis("Policy ID")
        .reset_index(name="Usage Count")
    )

    if not policy_usage.empty:

        st.dataframe(
            policy_usage,
            width="stretch",
            hide_index=True
        )

    else:

        st.info(
            "No policies have been triggered yet."
        )


else:

    st.info(
        "No access requests are available "
        "for analytics."
    )


# ---------------------------------------------------------
# ACCESS CONTROL SECTION
# ---------------------------------------------------------

st.subheader("🔐 Access Control")


# ---------------------------------------------------------
# ACCESS CONTROL SECTION
# ---------------------------------------------------------

st.subheader("🔐 Access Control")

col1, col2 = st.columns(2)

with col1:

    user_id = st.text_input(
        "User ID",
        value="USR001"
    )

    role = st.selectbox(
        "Role",
        [
            "student",
            "researcher",
            "data_scientist",
            "admin",
            "security_officer"
        ]
    )

    department = st.selectbox(
        "Department",
        [
            "AI",
            "Data Science",
            "IT",
            "Security"
        ]
    )

    clearance = st.selectbox(
        "Security Clearance",
        [
            "PUBLIC",
            "INTERNAL",
            "CONFIDENTIAL",
            "RESTRICTED"
        ]
    )


with col2:

    resource = st.text_input(
        "AI Dataset / Resource",
        value="gait_analysis_dataset"
    )

    classification = st.selectbox(
        "Data Classification",
        [
            "PUBLIC",
            "INTERNAL",
            "CONFIDENTIAL",
            "RESTRICTED"
        ]
    )

    action = st.selectbox(
        "Requested Action",
        [
            "READ",
            "WRITE",
            "DELETE"
        ]
    )

    purpose = st.selectbox(
        "Purpose",
        [
            "academic",
            "research",
            "model_development",
            "administration",
            "security_audit"
        ]
    )


location = st.selectbox(
    "Access Location",
    [
        "campus",
        "lab",
        "security_lab",
        "remote"
    ]
)


st.write("")

check_access = st.button(
    "🔍 CHECK ACCESS",
    type="primary",
    width="stretch"
)


# ---------------------------------------------------------
# ACCESS DECISION
# ---------------------------------------------------------

if check_access:

    request = {
        "request_id": f"UI-{pd.Timestamp.now().strftime('%Y%m%d%H%M%S')}",
        "user_id": user_id,
        "role": role,
        "department": department,
        "clearance": clearance,
        "resource": resource,
        "classification": classification,
        "action": action,
        "purpose": purpose,
        "location": location
    }

    result = engine.evaluate(request)

    insert_access_log(
        request=request,
        decision=result.get("decision"),
        policy_id=result.get("policy_id"),
        policy_name=result.get("policy_name"),
        reason=result.get("reason")
    )

    st.divider()

    st.subheader("🛡️ Authorization Decision")

    # -----------------------------------------------------
    # ALLOW
    # -----------------------------------------------------

    if result["decision"] == "ALLOW":

        st.success("✓ ACCESS ALLOWED")

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Decision",
                result["decision"]
            )

        with col2:
            st.metric(
                "Policy",
                result["policy_id"]
            )

        st.info(
            f"**Policy:** {result['policy_name']}\n\n"
            f"**Reason:** {result['reason']}"
        )

        st.write("### ✓ Matched Attributes")

        for attribute in result["matched_attributes"]:
            st.write(
                f"✓ **{attribute}**: "
                f"`{request.get(attribute)}`"
            )

    # -----------------------------------------------------
    # DENY
    # -----------------------------------------------------

    else:

        st.error("✗ ACCESS DENIED")

        st.warning(
            "No policy completely matched this access request."
        )

        st.write("### 🔎 Policy Evaluation")

        for evaluation in result["policy_evaluations"]:

            with st.expander(
                f"{evaluation['policy_id']} — "
                f"{evaluation['policy_name']}"
            ):

                if evaluation["matched"]:

                    st.success(
                        "All policy conditions matched."
                    )

                else:

                    st.write(
                        "**Attribute Evaluation**"
                    )

                    for attribute, details in (
                        evaluation["attributes"].items()
                    ):

                        if details["matched"]:

                            st.write(
                                f"✓ **{attribute}**  \n"
                                f"Expected: "
                                f"`{details['expected']}`  \n"
                                f"Received: "
                                f"`{details['received']}`"
                            )

                        else:

                            st.write(
                                f"❌ **{attribute}**  \n"
                                f"Expected: "
                                f"`{details['expected']}`  \n"
                                f"Received: "
                                f"`{details['received']}`"
                            )

        st.info(
            "**Final Decision:** DENY  \n"
            "The request was rejected because no policy "
            "satisfied all required attributes."
        )


# ---------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------

st.divider()

st.subheader("📜 Security Audit Log")

if not df.empty:

    display_columns = [
        "Request ID",
        "User ID",
        "Role",
        "Resource",
        "Action",
        "Decision",
        "Policy ID",
        "Timestamp"
    ]

    st.dataframe(
        df[display_columns],
        width="stretch",
        hide_index=True
    )

else:

    st.info("No access requests have been logged yet.")

