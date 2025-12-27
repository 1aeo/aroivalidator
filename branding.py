"""
1AEO Branding Module
Centralized theme constants and UI components for the AROI Validator.
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import streamlit as st

# ============================================================================
# THEME CONSTANTS
# ============================================================================

THEME = {
    "primary": "#00ff7f",
    "bg_primary": "#121212",
    "bg_secondary": "#1e1e1e",
    "text": "#ffffff",
    "text_muted": "#888888",
    "text_secondary": "#cccccc",
    "border_alpha": "0.2",
}

# Site navigation links
SITE_LINKS = [
    ("Home", "https://www.1aeo.com", False),
    ("Metrics", "https://metrics.1aeo.com", False),
    ("Validator", "https://aroivalidator.1aeo.com", True),  # Active
    ("FluxMap", "https://routefluxmap.1aeo.com", False),
]


def _get_streamlit():
    """Lazy import of streamlit to avoid loading it in batch mode."""
    import streamlit as st
    return st


def render_1aeo_navigation() -> None:
    """Render 1AEO cross-site navigation bar."""
    st = _get_streamlit()
    
    # Build links HTML
    links_html = "\n".join(
        f'<a href="{url}" class="{"active" if active else ""}">{name}</a>'
        for name, url, active in SITE_LINKS
    )
    
    st.markdown(f"""
    <style>
        .aeo-nav {{
            background-color: {THEME["bg_secondary"]};
            padding: 12px 20px;
            margin: -1rem -1rem 1.5rem -1rem;
            border-bottom: 1px solid rgba(0,255,127,{THEME["border_alpha"]});
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .aeo-nav a {{ color: {THEME["text_secondary"]}; text-decoration: none; font-size: 14px; transition: color 0.2s; }}
        .aeo-nav a:hover {{ color: {THEME["primary"]}; }}
        .aeo-nav .brand {{ color: {THEME["primary"]}; font-weight: bold; font-size: 16px; }}
        .aeo-nav .active {{ color: {THEME["primary"]}; font-weight: 500; }}
        .aeo-nav .links {{ display: flex; gap: 20px; flex-wrap: wrap; }}
    </style>
    <div class="aeo-nav">
        <a href="https://www.1aeo.com" class="brand">1AEO</a>
        <div class="links">
            {links_html}
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_1aeo_styles() -> None:
    """Render additional 1AEO brand styling."""
    st = _get_streamlit()
    
    st.markdown(f"""
    <style>
        [data-testid="stSidebar"] {{ border-right: 1px solid rgba(0,255,127,{THEME["border_alpha"]}); }}
        [data-testid="stMetric"] {{
            background-color: {THEME["bg_secondary"]};
            padding: 15px;
            border-radius: 8px;
            border: 1px solid rgba(0,255,127,0.1);
        }}
        .stButton > button:hover {{
            border-color: {THEME["primary"]};
            box-shadow: 0 0 10px rgba(0,255,127,0.3);
        }}
        [data-testid="stDataFrame"] {{
            border: 1px solid rgba(0,255,127,0.1);
            border-radius: 8px;
        }}
    </style>
    """, unsafe_allow_html=True)


def render_1aeo_footer() -> None:
    """Render 1AEO footer with cross-site links."""
    st = _get_streamlit()
    
    # Build footer links (exclude Home, include only tools)
    tool_links = " |\n".join(
        f'<a href="{url}" style="color: {THEME["primary"]}; margin: 0 10px;">{name}</a>'
        for name, url, _ in SITE_LINKS if name != "Home"
    )
    
    st.markdown(f"""
    <div style="margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid rgba(0,255,127,{THEME["border_alpha"]}); text-align: center; color: {THEME["text_muted"]};">
        <div style="margin-bottom: 10px;">
            {tool_links}
        </div>
        <p style="font-size: 12px; margin: 0;">
            <a href="https://www.1aeo.com" style="color: {THEME["primary"]};">1AEO</a> · 
            <a href="https://github.com/1aeo" style="color: {THEME["text_muted"]};">GitHub</a>
        </p>
    </div>
    """, unsafe_allow_html=True)

