
import streamlit as st
import requests

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="V360 Shopify Integration",
    page_icon="🛍️",
    layout="wide"
)

st.title("V360 Integration Assistant")
st.caption("Shopify connection and credential management")

st.divider()

st.subheader("Connect your Shopify store")

customer_id = st.text_input(
    "V360 Client ID",
    placeholder="Enter customer ID"
)

shop = st.text_input(
    "Shopify Store URL",
    placeholder="your-store.myshopify.com"
)

if st.button("Connect Shopify", type="primary"):
    if not customer_id or not shop:
        st.warning("Please enter both fields.")
    else:
        try:
            response = requests.post(
                f"{API_URL}/api/shopify/connect",
                json={
                    "customer_id": customer_id,
                    "shop": shop
                },
                timeout=30
            )

            response.raise_for_status()
            result = response.json()

            if result.get("authorization_url"):
                st.session_state["shop"] = shop
                st.session_state["customer_id"] = customer_id
                st.session_state["authorization_url"] = (
                    result["authorization_url"]
                )

        except requests.RequestException as e:
            st.error(f"Connection request failed: {e}")

if st.session_state.get("authorization_url"):
    st.success("Authorization URL generated!")

    st.link_button(
        "Authorize Shopify",
        st.session_state["authorization_url"]
    )

st.divider()

st.subheader("Connection verification")

if st.button("Check Shopify connection"):
    selected_shop = st.session_state.get("shop")

    if not selected_shop:
        st.warning("Connect a Shopify store first.")
    else:
        try:
            response = requests.get(
                f"{API_URL}/api/shopify/scopes",
                params={"shop": selected_shop},
                timeout=30
            )

            if response.ok:
                result = response.json()
                st.success("Shopify connected successfully!")

                st.write("Store:", result.get("shop"))

                st.write("Granted permissions:")
                st.json(result.get("permissions", []))

            else:
                st.error(
                    f"Connection check failed: {response.text}"
                )

        except requests.RequestException as e:
            st.error(f"API request failed: {e}")
