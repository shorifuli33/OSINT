"""
Nahidx001 - ZeroLeak Threat Intelligence Dashboard
A professional cybersecurity threat intelligence platform.
"""

import streamlit as st
import pandas as pd
import json
import hashlib
from datetime import datetime

# ── Page config (must be first Streamlit call) ─────────────────────────────
st.set_page_config(
    page_title="Nahidx001 | ZeroLeak Threat Intelligence",
    page_icon="🔴",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Local imports ───────────────────────────────────────────────────────────
from helpers.api_client import query_api
from helpers.password_strength import evaluate_password
from helpers.database import (
    save_search, get_history, get_search_by_id,
    get_aggregate_stats, delete_history_item, clear_all_history,
)
from helpers.export import export_csv, export_json, generate_pdf_bytes


# ── Global CSS ──────────────────────────────────────────────────────────────
def inject_css():
    st.markdown("""
    <style>
    /* ── Base ── */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0a0a0f !important;
        color: #e0e0e0;
    }
    [data-testid="stSidebar"] {
        background-color: #0d0d15 !important;
        border-right: 1px solid #1e1e2e;
    }
    /* ── Hide default streamlit chrome ── */
    #MainMenu, footer, header { visibility: hidden; }

    /* ── Branding banner ── */
    .brand-banner {
        text-align: center;
        padding: 12px 0 4px;
        border-bottom: 1px solid #ff2d55;
        margin-bottom: 16px;
    }
    .brand-title {
        font-size: 22px;
        font-weight: 800;
        color: #ff2d55;
        letter-spacing: 2px;
        font-family: monospace;
    }
    .brand-tagline {
        font-size: 10px;
        color: #666;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    /* ── KPI cards ── */
    .kpi-card {
        background: linear-gradient(135deg, #12121a 0%, #1a1a2e 100%);
        border: 1px solid #1e1e2e;
        border-radius: 12px;
        padding: 20px 16px;
        text-align: center;
        transition: border-color 0.3s, transform 0.2s;
    }
    .kpi-card:hover {
        border-color: #ff2d55;
        transform: translateY(-2px);
    }
    .kpi-value {
        font-size: 36px;
        font-weight: 800;
        color: #ff2d55;
        font-family: monospace;
    }
    .kpi-label {
        font-size: 11px;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 4px;
    }
    .kpi-icon { font-size: 24px; margin-bottom: 4px; }

    /* ── Nav buttons ── */
    .stButton > button {
        width: 100%;
        background: transparent;
        border: 1px solid #1e1e2e;
        color: #ccc;
        border-radius: 8px;
        padding: 10px 16px;
        text-align: left;
        transition: all 0.2s;
        font-size: 14px;
    }
    .stButton > button:hover {
        border-color: #ff2d55;
        color: #ff2d55;
        background: rgba(255,45,85,0.06);
    }

    /* ── Alert banners ── */
    .risk-banner {
        background: rgba(255,45,85,0.12);
        border: 1px solid #ff2d55;
        border-radius: 8px;
        padding: 12px 16px;
        margin: 12px 0;
        color: #ff2d55;
        font-size: 14px;
    }
    .success-banner {
        background: rgba(52,199,89,0.1);
        border: 1px solid #34c759;
        border-radius: 8px;
        padding: 12px 16px;
        margin: 12px 0;
        color: #34c759;
        font-size: 14px;
    }
    .info-banner {
        background: rgba(0,122,255,0.08);
        border: 1px solid #007aff;
        border-radius: 8px;
        padding: 12px 16px;
        margin: 12px 0;
        color: #007aff;
        font-size: 14px;
    }

    /* ── Tabs ── */
    .stTabs [data-baseweb="tab"] {
        color: #888;
        border-bottom: 2px solid transparent;
    }
    .stTabs [aria-selected="true"] {
        color: #ff2d55 !important;
        border-bottom-color: #ff2d55 !important;
    }

    /* ── DataFrames ── */
    .stDataFrame { border: 1px solid #1e1e2e; border-radius: 8px; }

    /* ── Inputs ── */
    .stTextInput input, .stSelectbox select {
        background-color: #12121a !important;
        color: #e0e0e0 !important;
        border-color: #2a2a3e !important;
    }
    .stTextInput input:focus { border-color: #ff2d55 !important; }

    /* ── Section headers ── */
    .section-header {
        font-size: 18px;
        font-weight: 700;
        color: #ff2d55;
        border-left: 3px solid #ff2d55;
        padding-left: 12px;
        margin: 20px 0 12px;
        font-family: monospace;
        letter-spacing: 1px;
    }

    /* ── Strength badges ── */
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
        color: #000;
    }

    /* ── Login box ── */
    .login-box {
        max-width: 420px;
        margin: 80px auto;
        background: #12121a;
        border: 1px solid #1e1e2e;
        border-radius: 16px;
        padding: 40px 36px;
        box-shadow: 0 20px 60px rgba(255,45,85,0.08);
    }
    </style>
    """, unsafe_allow_html=True)


# ── Helpers ─────────────────────────────────────────────────────────────────
def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def kpi_card(icon: str, value, label: str):
    return f"""
    <div class="kpi-card">
        <div class="kpi-icon">{icon}</div>
        <div class="kpi-value">{value}</div>
        <div class="kpi-label">{label}</div>
    </div>"""


def strength_color(label: str) -> str:
    colors = {
        "Very Weak": "#ff2d55",
        "Weak": "#ff6b35",
        "Fair": "#ffb800",
        "Strong": "#34c759",
        "Very Strong": "#00d4aa",
    }
    return colors.get(label, "#888")


def classify_records(records: list, org_domains: list) -> list:
    """Add 'type' and 'strength' fields to each record."""
    enriched = []
    for r in records:
        rec = dict(r)
        username = rec.get("username", "").lower()
        url = rec.get("url", "").lower()
        password = rec.get("password", "")

        # Employee detection
        is_emp = any(
            d.lower() in username or d.lower() in url
            for d in org_domains if d.strip()
        )
        rec["type"] = "Employee" if is_emp else "User"

        # Password strength
        strength = evaluate_password(password)
        rec["strength"] = strength["label"]
        rec["strength_color"] = strength["color"]
        rec["strength_score"] = strength["score"]

        enriched.append(rec)
    return enriched


def get_settings() -> dict:
    """Load settings from session state with defaults."""
    if "settings" not in st.session_state:
        st.session_state["settings"] = {
            "org_domains": ["riseuplabs.com", "riseuplabs"],
            "api_key": st.secrets.get("api_key", ""),
            "dashboard_password": st.secrets.get("dashboard_password", "Nahidx001@secure"),
        }
    return st.session_state["settings"]


# ── Login Page ───────────────────────────────────────────────────────────────
def page_login():
    inject_css()
    st.markdown("""
    <div style="text-align:center; margin-top:60px;">
        <div style="font-size:48px; color:#ff2d55; font-family:monospace; font-weight:900; letter-spacing:4px;">
            NAHIDX001
        </div>
        <div style="font-size:13px; color:#555; letter-spacing:3px; text-transform:uppercase; margin-top:4px;">
            ZeroLeak Threat Intelligence Dashboard
        </div>
        <div style="width:80px; height:3px; background:#ff2d55; margin:16px auto;"></div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown('<div style="height:20px"></div>', unsafe_allow_html=True)
        with st.container():
            st.markdown("""
            <div style="background:#12121a; border:1px solid #1e1e2e; border-radius:16px; padding:36px 32px;">
                <div style="text-align:center; margin-bottom:24px; color:#888; font-size:12px; letter-spacing:2px; text-transform:uppercase;">
                    🔒 Secure Access
                </div>
            </div>
            """, unsafe_allow_html=True)

            username = st.text_input("Username", placeholder="Enter username", key="login_user")
            password = st.text_input("Password", type="password", placeholder="Enter password", key="login_pass")
            st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)

            if st.button("🔐  LOGIN", use_container_width=True):
                settings = get_settings()
                correct_pw = settings.get("dashboard_password", "Nahidx001@secure")
                if username == "admin" and password == correct_pw:
                    st.session_state["authenticated"] = True
                    st.session_state["login_error"] = False
                    st.rerun()
                else:
                    st.session_state["login_error"] = True

            if st.session_state.get("login_error"):
                st.markdown("""
                <div class="risk-banner">
                    ⚠️ Invalid credentials. Access denied.
                </div>
                """, unsafe_allow_html=True)

    st.markdown("""
    <div style="text-align:center; margin-top:40px; color:#333; font-size:11px;">
        NAHIDX001 v1.0 &nbsp;|&nbsp; CONFIDENTIAL &nbsp;|&nbsp; AUTHORIZED USE ONLY
    </div>
    """, unsafe_allow_html=True)


# ── Sidebar ──────────────────────────────────────────────────────────────────
def render_sidebar() -> str:
    with st.sidebar:
        st.markdown("""
        <div class="brand-banner">
            <div class="brand-title">NAHIDX001</div>
            <div class="brand-tagline">ZeroLeak Threat Intelligence</div>
        </div>
        """, unsafe_allow_html=True)

        pages = [
            ("🏠", "Home"),
            ("🔍", "Search"),
            ("📜", "History"),
            ("📊", "Analytics"),
            ("⚙️", "Settings"),
        ]

        current = st.session_state.get("page", "Home")

        for icon, name in pages:
            label = f"{icon}  {name}"
            if current == name:
                label = f"{icon}  **{name}**"
            if st.button(label, key=f"nav_{name}", use_container_width=True):
                st.session_state["page"] = name
                st.rerun()

        st.markdown("---")

        stats = get_aggregate_stats()
        st.markdown(f"""
        <div style="font-size:11px; color:#555; text-align:center; padding:4px 0;">
            Searches: <span style="color:#ff2d55">{stats['total_searches']}</span> &nbsp;|&nbsp;
            Breaches: <span style="color:#ff2d55">{stats['total_breaches']}</span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")
        if st.button("🚪  Logout", use_container_width=True, key="logout_btn"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

        st.markdown("""
        <div style="font-size:10px; color:#333; text-align:center; margin-top:12px;">
            v1.0 | CONFIDENTIAL
        </div>
        """, unsafe_allow_html=True)

    return st.session_state.get("page", "Home")


# ── Home Page ────────────────────────────────────────────────────────────────
def page_home():
    st.markdown('<div class="section-header">THREAT INTELLIGENCE OVERVIEW</div>', unsafe_allow_html=True)

    stats = get_aggregate_stats()
    history = get_history(limit=500)

    # Aggregate counts from history
    all_records = []
    unique_urls = set()
    unique_emails = set()
    for h in history:
        try:
            recs = json.loads(h.get("results_json") or "[]")
            all_records.extend(recs)
            for r in recs:
                url = r.get("url", "").strip()
                user = r.get("username", "").strip()
                if url:
                    unique_urls.add(url)
                if "@" in user:
                    unique_emails.add(user)
        except Exception:
            pass

    weak_count = sum(
        1 for r in all_records
        if evaluate_password(r.get("password", ""))["score"] <= 1
    )

    # KPI row 1
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(kpi_card("💥", stats["total_breaches"], "Total Breaches"), unsafe_allow_html=True)
    with c2:
        st.markdown(kpi_card("👔", stats["total_employees"], "Employee Breaches"), unsafe_allow_html=True)
    with c3:
        st.markdown(kpi_card("👤", stats["total_users"], "User Breaches"), unsafe_allow_html=True)

    st.markdown('<div style="height:16px"></div>', unsafe_allow_html=True)

    # KPI row 2
    c4, c5, c6 = st.columns(3)
    with c4:
        st.markdown(kpi_card("🌐", len(unique_urls), "Unique URLs"), unsafe_allow_html=True)
    with c5:
        st.markdown(kpi_card("📧", len(unique_emails), "Unique Emails"), unsafe_allow_html=True)
    with c6:
        st.markdown(kpi_card("🔓", weak_count, "Weak Passwords"), unsafe_allow_html=True)

    # Risk banner
    if weak_count > 0:
        st.markdown(f"""
        <div class="risk-banner" style="margin-top:20px;">
            ⚠️ <strong>RISK ALERT:</strong> {weak_count} weak or very weak password(s) detected across all searches.
            Immediate credential rotation recommended.
        </div>
        """, unsafe_allow_html=True)

    if stats["total_employees"] > 0:
        st.markdown(f"""
        <div class="risk-banner">
            🔴 <strong>CRITICAL:</strong> {stats["total_employees"]} employee credential(s) found in breach data.
            Enforce MFA and password reset for affected accounts.
        </div>
        """, unsafe_allow_html=True)

    # Quick search
    st.markdown('<div class="section-header">QUICK SEARCH</div>', unsafe_allow_html=True)
    col_a, col_b, col_c = st.columns([1, 3, 1])
    with col_a:
        qtype = st.selectbox("Type", ["URL", "Email"], key="home_qtype", label_visibility="collapsed")
    with col_b:
        qval = st.text_input("Query", placeholder="e.g. example.com or user@domain.com",
                             key="home_query", label_visibility="collapsed")
    with col_c:
        if st.button("🔍  SEARCH", use_container_width=True, key="home_search_btn"):
            if qval.strip():
                st.session_state["pending_search_type"] = qtype.lower()
                st.session_state["pending_search_query"] = qval.strip()
                st.session_state["page"] = "Search"
                st.rerun()
            else:
                st.warning("Enter a query first.")

    # Recent history snippet
    if history:
        st.markdown('<div class="section-header">RECENT SEARCHES</div>', unsafe_allow_html=True)
        for h in history[:5]:
            ts = h["timestamp"][:19].replace("T", " ")
            badge_color = "#ff2d55" if h["employee_count"] > 0 else "#34c759"
            st.markdown(f"""
            <div style="background:#12121a; border:1px solid #1e1e2e; border-radius:8px;
                        padding:12px 16px; margin:6px 0; display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span style="color:#888; font-size:11px;">{ts}</span>
                    <span style="margin-left:10px; font-size:13px; color:#e0e0e0;">
                        {h['search_type'].upper()}: <strong>{h['query']}</strong>
                    </span>
                </div>
                <div>
                    <span style="background:{badge_color}22; color:{badge_color}; border:1px solid {badge_color};
                                 padding:2px 10px; border-radius:20px; font-size:11px; font-weight:700;">
                        {h['total_results']} results
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)


# ── Search Page ──────────────────────────────────────────────────────────────
def page_search():
    st.markdown('<div class="section-header">BREACH SEARCH</div>', unsafe_allow_html=True)

    settings = get_settings()
    api_key = settings.get("api_key", "")
    org_domains = settings.get("org_domains", ["riseuplabs.com", "riseuplabs"])

    if not api_key:
        st.markdown("""
        <div class="risk-banner">
            ⚠️ No API key configured. Go to <strong>Settings</strong> to add your ZeroLeak API key.
        </div>
        """, unsafe_allow_html=True)
        return

    # ── Search form ──
    col1, col2, col3 = st.columns([1, 3, 1])
    with col1:
        default_type = st.session_state.get("pending_search_type", "url")
        idx = 0 if default_type == "url" else 1
        search_type = st.selectbox("Search Type", ["URL / Domain", "Email Address"],
                                   index=idx, key="search_type_sel")
    with col2:
        default_q = st.session_state.get("pending_search_query", "")
        placeholder = "e.g. example.com" if "URL" in search_type else "e.g. user@example.com"
        query = st.text_input("Search Query", value=default_q, placeholder=placeholder, key="search_query_input")
    with col3:
        st.markdown('<div style="height:28px"></div>', unsafe_allow_html=True)
        run_search = st.button("🔍  SEARCH", use_container_width=True, key="search_run_btn")

    # Clear pending
    st.session_state.pop("pending_search_type", None)
    st.session_state.pop("pending_search_query", None)

    if run_search and query.strip():
        api_type = "email" if "Email" in search_type else "url"
        with st.spinner(f"🔎 Querying ZeroLeak API for **{query.strip()}** — this may take 10–15 seconds..."):
            result = query_api(api_key, api_type, query.strip())

        if not result["success"]:
            st.markdown(f"""
            <div class="risk-banner">⚠️ API Error: {result['error']}</div>
            """, unsafe_allow_html=True)
            return

        raw_records = result["data"]
        if not raw_records:
            st.markdown("""
            <div class="success-banner">✅ No breaches found for this query.</div>
            """, unsafe_allow_html=True)
            save_search(api_type, query.strip(), 0, 0, 0, [], result["raw"])
            return

        # Classify & enrich
        records = classify_records(raw_records, org_domains)
        emp_records = [r for r in records if r["type"] == "Employee"]
        user_records = [r for r in records if r["type"] == "User"]

        # Save to history
        save_search(api_type, query.strip(), len(records),
                    len(emp_records), len(user_records), records, result["raw"])

        # Store results in session for display
        st.session_state["last_results"] = records
        st.session_state["last_query"] = query.strip()
        st.session_state["last_search_type"] = api_type
        st.session_state["last_raw"] = result["raw"]

    # Display results
    records = st.session_state.get("last_results", [])
    query_display = st.session_state.get("last_query", "")

    if not records:
        st.markdown("""
        <div class="info-banner">
            💡 Enter a domain or email above and click SEARCH to discover breach data.
        </div>
        """, unsafe_allow_html=True)
        return

    emp_records = [r for r in records if r["type"] == "Employee"]
    user_records = [r for r in records if r["type"] == "User"]
    weak_in_results = [r for r in records if r.get("strength_score", 4) <= 1]

    # Summary KPIs
    ck1, ck2, ck3, ck4 = st.columns(4)
    with ck1:
        st.markdown(kpi_card("💥", len(records), "Total Results"), unsafe_allow_html=True)
    with ck2:
        st.markdown(kpi_card("👔", len(emp_records), "Employee Accounts"), unsafe_allow_html=True)
    with ck3:
        st.markdown(kpi_card("👤", len(user_records), "User Accounts"), unsafe_allow_html=True)
    with ck4:
        st.markdown(kpi_card("🔓", len(weak_in_results), "Weak Passwords"), unsafe_allow_html=True)

    # Risk alerts
    if emp_records:
        st.markdown(f"""
        <div class="risk-banner" style="margin-top:16px;">
            🔴 <strong>CRITICAL:</strong> {len(emp_records)} employee credential(s) exposed for <strong>{query_display}</strong>.
            Immediate action required.
        </div>
        """, unsafe_allow_html=True)

    if weak_in_results:
        st.markdown(f"""
        <div class="risk-banner">
            ⚠️ <strong>WARNING:</strong> {len(weak_in_results)} weak password(s) detected in results.
        </div>
        """, unsafe_allow_html=True)

    # ── Export buttons ──
    st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)
    ecol1, ecol2, ecol3, _ = st.columns([1, 1, 1, 3])
    with ecol1:
        csv_data = export_csv(records)
        st.download_button("📥 CSV", data=csv_data,
                           file_name=f"nahidx001_{query_display}.csv",
                           mime="text/csv", use_container_width=True)
    with ecol2:
        json_data = export_json(records)
        st.download_button("📥 JSON", data=json_data,
                           file_name=f"nahidx001_{query_display}.json",
                           mime="application/json", use_container_width=True)
    with ecol3:
        api_type_for_pdf = st.session_state.get("last_search_type", "url")
        pdf_bytes = generate_pdf_bytes(records, query_display, api_type_for_pdf)
        st.download_button("📥 PDF (HTML)", data=pdf_bytes,
                           file_name=f"nahidx001_{query_display}_report.html",
                           mime="text/html",
                           help="Open in browser → Ctrl+P → Save as PDF",
                           use_container_width=True)

    # ── Raw response debug expander ──
    with st.expander("🔧 Raw API Response (debug)", expanded=False):
        raw = st.session_state.get("last_raw", {})
        st.json(raw if raw else {"note": "No raw response stored."})
        st.caption("Use this to verify the API response format if results look wrong.")

    # ── Results table ──
    st.markdown('<div class="section-header">RESULTS</div>', unsafe_allow_html=True)

    tab_all, tab_emp, tab_usr = st.tabs([
        f"All ({len(records)})",
        f"Employees ({len(emp_records)})",
        f"Users ({len(user_records)})",
    ])

    def render_table(data: list):
        if not data:
            st.info("No records in this category.")
            return

        # Filter bar
        filter_text = st.text_input("🔎 Filter rows (username / password / url)...",
                                    key=f"filter_{id(data)}", label_visibility="collapsed")

        df_data = []
        for r in data:
            if filter_text:
                haystack = f"{r.get('username','')} {r.get('password','')} {r.get('url','')}".lower()
                if filter_text.lower() not in haystack:
                    continue
            df_data.append({
                "Username": r.get("username", ""),
                "Password": r.get("password", ""),
                "URL": r.get("url", ""),
                "Type": r.get("type", ""),
                "Strength": r.get("strength", ""),
            })

        if not df_data:
            st.info("No records match the filter.")
            return

        df = pd.DataFrame(df_data)

        # Colour-code strength column using pandas Styler
        def color_strength(val):
            c = strength_color(val)
            return f"color: {c}; font-weight: 700"

        styled = df.style.applymap(color_strength, subset=["Strength"])
        st.dataframe(styled, use_container_width=True, height=420,
                     column_config={
                         "Username": st.column_config.TextColumn("Username", width="medium"),
                         "Password": st.column_config.TextColumn("Password", width="medium"),
                         "URL": st.column_config.TextColumn("URL", width="large"),
                         "Type": st.column_config.TextColumn("Type", width="small"),
                         "Strength": st.column_config.TextColumn("Strength", width="small"),
                     })

        st.caption(f"Showing {len(df_data)} of {len(data)} records")

    with tab_all:
        render_table(records)
    with tab_emp:
        render_table(emp_records)
    with tab_usr:
        render_table(user_records)


# ── History Page ─────────────────────────────────────────────────────────────
def page_history():
    st.markdown('<div class="section-header">SEARCH HISTORY</div>', unsafe_allow_html=True)

    history = get_history()
    if not history:
        st.markdown('<div class="info-banner">📜 No search history yet.</div>', unsafe_allow_html=True)
        return

    # Clear all button
    col_h, col_clr = st.columns([4, 1])
    with col_clr:
        if st.button("🗑️ Clear All", use_container_width=True, key="clear_hist_btn"):
            clear_all_history()
            st.session_state.pop("last_results", None)
            st.rerun()

    for h in history:
        ts = h["timestamp"][:19].replace("T", "  ")
        emp_col = "#ff2d55" if h["employee_count"] > 0 else "#34c759"
        icon = "📧" if h["search_type"] == "email" else "🌐"

        with st.expander(
            f"{icon} {h['search_type'].upper()} | {h['query']} | {ts} | {h['total_results']} results",
            expanded=False,
        ):
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Total", h["total_results"])
            mc2.metric("Employees", h["employee_count"])
            mc3.metric("Users", h["user_count"])
            mc4.metric("Type", h["search_type"].upper())

            col_load, col_del = st.columns([2, 1])
            with col_load:
                if st.button("🔄 Load Results", key=f"load_{h['id']}", use_container_width=True):
                    try:
                        recs = json.loads(h.get("results_json") or "[]")
                        st.session_state["last_results"] = recs
                        st.session_state["last_query"] = h["query"]
                        st.session_state["last_search_type"] = h["search_type"]
                        st.session_state["page"] = "Search"
                        st.rerun()
                    except Exception as e:
                        st.error(f"Could not load results: {e}")
            with col_del:
                if st.button("🗑️ Delete", key=f"del_{h['id']}", use_container_width=True):
                    delete_history_item(h["id"])
                    st.rerun()


# ── Analytics Page ───────────────────────────────────────────────────────────
def page_analytics():
    try:
        import plotly.express as px
        import plotly.graph_objects as go
        HAS_PLOTLY = True
    except ImportError:
        HAS_PLOTLY = False

    st.markdown('<div class="section-header">ANALYTICS & INSIGHTS</div>', unsafe_allow_html=True)

    history = get_history(limit=500)
    if not history:
        st.markdown('<div class="info-banner">📊 No data yet. Run some searches first.</div>',
                    unsafe_allow_html=True)
        return

    # Aggregate
    all_records = []
    for h in history:
        try:
            recs = json.loads(h.get("results_json") or "[]")
            all_records.extend(recs)
        except Exception:
            pass

    if not all_records:
        st.info("No detailed record data available yet.")
        return

    total = len(all_records)
    emp_count = sum(1 for r in all_records if r.get("type") == "Employee")
    usr_count = total - emp_count

    # KPIs
    ak1, ak2, ak3, ak4 = st.columns(4)
    ak1.metric("Total Records", total)
    ak2.metric("Employee Breaches", emp_count)
    ak3.metric("User Breaches", usr_count)
    weak = sum(1 for r in all_records if evaluate_password(r.get("password", ""))["score"] <= 1)
    ak4.metric("Weak Passwords", weak)

    st.markdown('<div style="height:16px"></div>', unsafe_allow_html=True)

    if HAS_PLOTLY:
        col_l, col_r = st.columns(2)

        # Pie: Employee vs User
        with col_l:
            st.markdown('<div class="section-header" style="font-size:14px;">Employee vs User Breaches</div>',
                        unsafe_allow_html=True)
            fig_pie = px.pie(
                names=["Employees", "Users"],
                values=[emp_count, usr_count],
                color_discrete_sequence=["#ff2d55", "#007aff"],
                hole=0.4,
            )
            fig_pie.update_layout(
                paper_bgcolor="#0a0a0f",
                plot_bgcolor="#0a0a0f",
                font_color="#e0e0e0",
                legend=dict(bgcolor="#12121a"),
                margin=dict(t=10, b=10),
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        # Bar: Password strength distribution
        with col_r:
            st.markdown('<div class="section-header" style="font-size:14px;">Password Strength Distribution</div>',
                        unsafe_allow_html=True)
            strength_counts = {"Very Weak": 0, "Weak": 0, "Fair": 0, "Strong": 0, "Very Strong": 0}
            for r in all_records:
                lbl = evaluate_password(r.get("password", ""))["label"]
                if lbl in strength_counts:
                    strength_counts[lbl] += 1
            colors = ["#ff2d55", "#ff6b35", "#ffb800", "#34c759", "#00d4aa"]
            fig_bar = px.bar(
                x=list(strength_counts.keys()),
                y=list(strength_counts.values()),
                color=list(strength_counts.keys()),
                color_discrete_sequence=colors,
            )
            fig_bar.update_layout(
                paper_bgcolor="#0a0a0f",
                plot_bgcolor="#12121a",
                font_color="#e0e0e0",
                showlegend=False,
                margin=dict(t=10, b=10),
                xaxis=dict(gridcolor="#1e1e2e"),
                yaxis=dict(gridcolor="#1e1e2e"),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # Top 10 breached URLs
        from collections import Counter
        url_counts = Counter(r.get("url", "Unknown").strip() or "Unknown" for r in all_records)
        top_urls = url_counts.most_common(10)
        if top_urls:
            st.markdown('<div class="section-header" style="font-size:14px;">Top 10 Breached Sources</div>',
                        unsafe_allow_html=True)
            urls, counts = zip(*top_urls)
            fig_url = px.bar(
                x=list(counts),
                y=list(urls),
                orientation="h",
                color=list(counts),
                color_continuous_scale=["#1e1e2e", "#ff2d55"],
            )
            fig_url.update_layout(
                paper_bgcolor="#0a0a0f",
                plot_bgcolor="#12121a",
                font_color="#e0e0e0",
                showlegend=False,
                coloraxis_showscale=False,
                margin=dict(t=10, b=10),
                xaxis=dict(gridcolor="#1e1e2e"),
                yaxis=dict(gridcolor="#1e1e2e"),
                height=350,
            )
            fig_url.update_yaxes(autorange="reversed")
            st.plotly_chart(fig_url, use_container_width=True)

        # Search timeline
        if len(history) > 1:
            st.markdown('<div class="section-header" style="font-size:14px;">Search Activity Timeline</div>',
                        unsafe_allow_html=True)
            df_timeline = pd.DataFrame([{
                "Date": h["timestamp"][:10],
                "Results": h["total_results"],
                "Query": h["query"],
            } for h in history])
            df_timeline = df_timeline.groupby("Date")["Results"].sum().reset_index()
            fig_time = px.line(df_timeline, x="Date", y="Results",
                               markers=True, line_shape="spline",
                               color_discrete_sequence=["#ff2d55"])
            fig_time.update_layout(
                paper_bgcolor="#0a0a0f",
                plot_bgcolor="#12121a",
                font_color="#e0e0e0",
                xaxis=dict(gridcolor="#1e1e2e"),
                yaxis=dict(gridcolor="#1e1e2e"),
                margin=dict(t=10, b=10),
            )
            st.plotly_chart(fig_time, use_container_width=True)
    else:
        st.warning("Install `plotly` for interactive charts: `pip install plotly`")
        # Fallback: text stats
        st.markdown(f"**Employee breaches:** {emp_count}  |  **User breaches:** {usr_count}")
        st.markdown(f"**Weak passwords:** {weak} / {total}")


# ── Settings Page ────────────────────────────────────────────────────────────
def page_settings():
    st.markdown('<div class="section-header">SETTINGS</div>', unsafe_allow_html=True)

    settings = get_settings()

    # ── API Key ──
    st.markdown("#### API Configuration")
    new_api_key = st.text_input("ZeroLeak API Key", value=settings.get("api_key", ""),
                                type="password", key="settings_api_key",
                                help="Get your key from the SixEye ZeroLeak platform.")
    if st.button("💾 Save API Key", key="save_api"):
        settings["api_key"] = new_api_key.strip()
        st.session_state["settings"] = settings
        st.success("API key saved for this session. Update secrets.toml for persistence.")

    st.markdown("---")

    # ── Organization Domains ──
    st.markdown("#### Employee Detection Domains")
    st.caption("Credentials matching these domains are classified as **Employee** breaches.")

    domains = settings.get("org_domains", ["riseuplabs.com", "riseuplabs"])

    # Display current domains
    remove_idx = None
    for i, d in enumerate(domains):
        dc1, dc2 = st.columns([5, 1])
        with dc1:
            st.code(d, language=None)
        with dc2:
            if st.button("✕", key=f"rm_domain_{i}"):
                remove_idx = i

    if remove_idx is not None:
        domains.pop(remove_idx)
        settings["org_domains"] = domains
        st.session_state["settings"] = settings
        st.rerun()

    # Add domain
    nd_col, nd_btn = st.columns([4, 1])
    with nd_col:
        new_domain = st.text_input("Add domain", placeholder="e.g. mycompany.com",
                                   key="new_domain_input", label_visibility="collapsed")
    with nd_btn:
        if st.button("＋ Add", key="add_domain_btn", use_container_width=True):
            nd = new_domain.strip().lower()
            if nd and nd not in domains:
                domains.append(nd)
                settings["org_domains"] = domains
                st.session_state["settings"] = settings
                st.rerun()
            elif nd in domains:
                st.warning("Domain already exists.")

    st.markdown("---")

    # ── Change Password ──
    st.markdown("#### Change Dashboard Password")
    cur_pw = st.text_input("Current Password", type="password", key="cur_pw")
    new_pw = st.text_input("New Password", type="password", key="new_pw")
    new_pw2 = st.text_input("Confirm New Password", type="password", key="new_pw2")

    if st.button("🔑 Update Password", key="update_pw_btn"):
        correct = settings.get("dashboard_password", st.secrets.get("dashboard_password", ""))
        if cur_pw != correct:
            st.error("Current password is incorrect.")
        elif new_pw != new_pw2:
            st.error("New passwords do not match.")
        elif len(new_pw) < 8:
            st.error("Password must be at least 8 characters.")
        else:
            settings["dashboard_password"] = new_pw
            st.session_state["settings"] = settings
            st.success("Password updated for this session. Update secrets.toml for persistence.")

    st.markdown("---")

    # ── About ──
    st.markdown("#### About")
    st.markdown("""
    <div style="background:#12121a; border:1px solid #1e1e2e; border-radius:8px; padding:20px;">
        <div style="color:#ff2d55; font-size:20px; font-family:monospace; font-weight:800;">NAHIDX001</div>
        <div style="color:#666; font-size:11px; margin-bottom:12px;">ZeroLeak Threat Intelligence Dashboard</div>
        <table style="font-size:12px; color:#888; border-collapse:collapse; width:100%;">
            <tr><td style="padding:4px 0; color:#555;">Version</td><td style="color:#e0e0e0;">1.0.0</td></tr>
            <tr><td style="padding:4px 0; color:#555;">API Endpoint</td>
                <td style="color:#e0e0e0; font-family:monospace; font-size:11px;">
                    https://sixeye.fwh.is/zeroleakapi.php
                </td>
            </tr>
            <tr><td style="padding:4px 0; color:#555;">Data Storage</td><td style="color:#e0e0e0;">Local SQLite</td></tr>
            <tr><td style="padding:4px 0; color:#555;">License</td><td style="color:#e0e0e0;">Internal Use Only</td></tr>
        </table>
    </div>
    """, unsafe_allow_html=True)


# ── Main App Router ──────────────────────────────────────────────────────────
def main():
    inject_css()

    # Session defaults
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "page" not in st.session_state:
        st.session_state["page"] = "Home"

    # Auth gate
    if not st.session_state["authenticated"]:
        page_login()
        return

    # Render sidebar and get active page
    active_page = render_sidebar()

    # Route to page
    if active_page == "Home":
        page_home()
    elif active_page == "Search":
        page_search()
    elif active_page == "History":
        page_history()
    elif active_page == "Analytics":
        page_analytics()
    elif active_page == "Settings":
        page_settings()
    else:
        page_home()


if __name__ == "__main__":
    main()
