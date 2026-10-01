"""Entry point for the sales dashboard.

``python app.py`` launches Streamlit on this file. The page layer here only
handles rendering and pass/fail presentation; every credential decision is
delegated to the ``credentials`` service.
"""

from __future__ import annotations

import os
import sys


def _launch_streamlit() -> None:
    """Re-exec this file under `streamlit run` when launched with python."""
    # Running under the streamlit runtime (normal `streamlit run`, or the
    # headless AppTest harness used by verify_auth.py) means the script body
    # below must execute instead of relaunching a server.
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx

        if get_script_run_ctx() is not None:
            return
    except Exception:
        pass
    if os.environ.get("_SALES_DASHBOARD_STREAMLIT") == "1":
        return
    os.environ["_SALES_DASHBOARD_STREAMLIT"] = "1"
    import subprocess

    port = os.environ.get("APP_PORT", "8501")
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        os.path.join(str(os.path.dirname(os.path.abspath(__file__))), "app.py"),
        "--server.port",
        str(port),
        "--server.headless",
        "true",
    ]
    try:
        sys.exit(subprocess.call(cmd))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    _launch_streamlit()


# The code below is executed by the streamlit runtime on every rerun.
import pandas as pd  # noqa: E402
import plotly.express as px  # noqa: E402
import streamlit as st  # noqa: E402
import streamlit_authenticator as stauth  # noqa: E402

import credentials as cred  # noqa: E402

st.set_page_config(
    page_title="Sales Dashboard",
    page_icon=":bar_chart:",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --- AUTHENTICATION (service layer decides, page only displays) -------------

try:
    credentials = cred.load()
except cred.MigrationError as exc:
    # Neither the new nested format nor the legacy flat list: show the
    # concrete reason. Never fall back to empty/old credentials.
    st.error(str(exc))
    st.stop()

names, usernames = credentials.names_and_usernames()
authenticator = stauth.Authenticate(
    credentials.mapping,
    "sales_dashboard",
    "abcdef",
    cookie_expiry_days=30,
    auto_hash=False,
)


def render_login() -> None:
    """The /login page: legacy banner on top, then the authenticator form."""
    if credentials.is_legacy:
        st.warning(cred.LEGACY_BANNER)

    # streamlit-authenticator 0.4.x renders the form itself and records the
    # outcome in session_state; the old tuple is returned only for
    # location='unrendered'.
    authenticator.login(location="main", key="Login")
    authentication_status = st.session_state.get("authentication_status")

    if authentication_status is False:
        st.error(cred.BAD_CREDENTIALS_MESSAGE)
    elif authentication_status is None:
        st.warning(cred.NO_INPUT_MESSAGE)


def render_dashboard(name: str) -> None:
    """Content shown only after a successful login."""

    @st.cache_data
    def get_data_from_excel():
        data_frame = pd.read_excel(
            io=str(cred.PROJECT_ROOT / "supermarkt_sales.xlsx"),
            engine="openpyxl",
            sheet_name="Sales",
            skiprows=3,
            usecols="B:R",
            nrows=1000,
        )
        data_frame["hour"] = pd.to_datetime(
            data_frame["Time"], format="%H:%M:%S"
        ).dt.hour
        return data_frame

    data_frame = get_data_from_excel()

    # ---- SIDEBAR ----
    authenticator.logout("Logout", "sidebar")
    st.sidebar.title(f"Welcome {name}")
    st.sidebar.header("Please Filter Here:")
    city = st.sidebar.multiselect(
        "Select the City:",
        options=data_frame["City"].unique(),
        default=data_frame["City"].unique(),
    )
    customer_type = st.sidebar.multiselect(
        "Select the Customer Type:",
        options=data_frame["Customer_type"].unique(),
        default=data_frame["Customer_type"].unique(),
    )
    gender = st.sidebar.multiselect(
        "Select the Gender:",
        options=data_frame["Gender"].unique(),
        default=data_frame["Gender"].unique(),
    )

    df_selection = data_frame.query(
        "City == @city & Customer_type == @customer_type & Gender == @gender"
    )

    # ---- MAINPAGE ----
    st.title(":bar_chart: Sales Dashboard")
    st.markdown("##")

    total_sales = int(df_selection["Total"].sum())
    average_rating = round(df_selection["Rating"].mean(), 1)
    star_rating = ":star:" * int(round(average_rating, 0))
    average_sale_by_transaction = round(df_selection["Total"].mean(), 2)

    left_column, middle_column, right_column = st.columns(3)
    with left_column:
        st.subheader("Total Sales:")
        st.subheader(f"US $ {total_sales:,}")
    with middle_column:
        st.subheader("Average Rating:")
        st.subheader(f"{average_rating} {star_rating}")
    with right_column:
        st.subheader("Average Sales Per Transaction:")
        st.subheader(f"US $ {average_sale_by_transaction}")

    st.markdown("""---""")

    sales_by_product_line = (
        df_selection.groupby(by=["Product line"])
        .sum(numeric_only=True)[["Total"]]
        .sort_values(by="Total")
    )
    fig_product_sales = px.bar(
        sales_by_product_line,
        x="Total",
        y=sales_by_product_line.index,
        orientation="h",
        title="<b>Sales by Product Line</b>",
        color_discrete_sequence=["#0083B8"] * len(sales_by_product_line),
        template="plotly_white",
    )
    fig_product_sales.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False),
    )

    sales_by_hour = (
        df_selection.groupby(by=["hour"])
        .sum(numeric_only=True)[["Total"]]
    )
    fig_hourly = px.bar(
        sales_by_hour,
        x=sales_by_hour.index,
        y="Total",
        title="<b>Sales by hour</b>",
        color_discrete_sequence=["#0083B8"] * len(sales_by_hour),
        template="plotly_white",
    )
    fig_hourly.update_layout(
        xaxis=dict(tickmode="linear"),
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis=dict(showgrid=False),
    )

    left_column, right_column = st.columns(2)
    left_column.plotly_chart(fig_hourly, use_container_width=True)
    right_column.plotly_chart(fig_product_sales, use_container_width=True)

    hide_st_style = """
                <style>
                #MainMenu {visibility: hidden;}
                footer {visibility: hidden;}
                header {visibility: hidden;}
                </style>
                """
    st.markdown(hide_st_style, unsafe_allow_html=True)


# --- ROUTE ------------------------------------------------------------------

# Only /login and a hidden dashboard exist; the page layer never decides
# credentials itself, it just shows what the service/authenticator returned.
dashboard_page = st.Page(
    render_dashboard, title="Dashboard", url_path="dashboard"
)
login_page = st.Page(render_login, title="Login", url_path="login", default=True)
st.navigation([dashboard_page, login_page], position="hidden")

if st.session_state.get("authentication_status"):
    st.switch_page(dashboard_page)
else:
    render_login()
