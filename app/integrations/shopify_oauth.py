
import os
import hmac
import hashlib
import secrets
import re

from urllib.parse import urlencode, parse_qsl
from datetime import datetime, timezone

import httpx
from dotenv import load_dotenv

import asyncio
from datetime import datetime, timedelta, timezone

from app.security.token_store import get_token, save_token
from datetime import datetime, timedelta, timezone

load_dotenv()

CLIENT_ID = os.getenv("SHOPIFY_CLIENT_ID")
CLIENT_SECRET = os.getenv("SHOPIFY_CLIENT_SECRET")
REDIRECT_URI = os.getenv("SHOPIFY_REDIRECT_URI")

SCOPES = os.getenv(
    "SHOPIFY_SCOPES",
    "read_analytics"
)

# Temporary state storage for local development.
# Replace with shared, short-lived storage before deployment.
oauth_states = {}

# Temporary token handoff for local development.
# Tokens must not be logged or exposed to the browser.
# Production handoff will go directly to the V360 backend.


def normalize_shop(shop: str) -> str:
    """Validate and normalize a Shopify store domain."""

    shop = shop.strip().lower()

    shop = re.sub(r"^https?://", "", shop)
    shop = shop.split("/")[0]

    if not re.fullmatch(
        r"[a-z0-9][a-z0-9-]*\.myshopify\.com",
        shop
    ):
        raise ValueError(
            "Please enter a valid Shopify store domain."
        )

    return shop


def generate_authorization_url(shop: str, customer_id: str):
    """Generate Shopify OAuth authorization URL."""

    shop = normalize_shop(shop)

    if not CLIENT_ID or not CLIENT_SECRET or not REDIRECT_URI:
        raise ValueError("Shopify environment variables are missing.")

    state = secrets.token_urlsafe(32)

    oauth_states[state] = {
        "shop": shop,
        "customer_id": customer_id,
        "created_at": datetime.now(timezone.utc)
    }

    params = {
        "client_id": CLIENT_ID,
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    authorization_url = (
        f"https://{shop}/admin/oauth/authorize?"
        + urlencode(params)
    )

    return authorization_url


def validate_callback_hmac(query_params: dict) -> bool:
    """Validate Shopify callback signature."""

    received_hmac = query_params.get("hmac")

    if not received_hmac:
        return False

    message_params = {
        key: value
        for key, value in query_params.items()
        if key not in ("hmac", "signature")
    }

    message = "&".join(
        f"{key}={value}"
        for key, value in sorted(message_params.items())
    )

    calculated_hmac = hmac.new(
        CLIENT_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(
        calculated_hmac,
        received_hmac
    )


async def exchange_code_for_token(shop: str, code: str):
    """Exchange authorization code for expiring offline tokens."""

    shop = normalize_shop(shop)

    token_url = f"https://{shop}/admin/oauth/access_token"

    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "expiring": "1"
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            token_url,
            data=payload
        )

        response.raise_for_status()

        return response.json()

async def get_granted_scopes(shop: str, access_token: str):
    shop = normalize_shop(shop)

    url = f"https://{shop}/admin/api/2026-10/graphql.json"

    query = """
    query {
        currentAppInstallation {
            accessScopes {
                handle
            }
        }
    }
    """

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            url,
            json={"query": query},
            headers=headers
        )
        response.raise_for_status()
        return response.json()

    
async def get_shopify_sales(shop: str, access_token: str):
    shop = normalize_shop(shop)

    url = f"https://{shop}/admin/api/2026-10/graphql.json"

    query = """
    query {
        shopifyqlQuery(
            query: "FROM sales SHOW total_sales TIMESERIES day SINCE -30d UNTIL today ORDER BY day ASC"
        ) {
            tableData {
                columns {
                    name
                }
                rows
            }
            parseErrors
        }
    }
    """

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            url,
            json={"query": query},
            headers=headers
        )

        response.raise_for_status()
        return response.json()


async def refresh_shopify_token(shop: str, refresh_token: str):
    """
    Refresh an expiring Shopify offline access token.

    Returns the new access token, rotated refresh token,
    and expiration metadata.
    """

    shop = normalize_shop(shop)

    if not CLIENT_ID or not CLIENT_SECRET:
        raise ValueError("Shopify client credentials are missing.")

    if not refresh_token:
        raise ValueError("Shopify refresh token is missing.")

    token_url = f"https://{shop}/admin/oauth/access_token"

    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                token_url,
                data=payload,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json"
                }
            )

            response.raise_for_status()

            token_data = response.json()

            if not isinstance(token_data, dict):
                raise ValueError("Shopify returned an invalid token response.")

            required_fields = [
                "access_token",
                "refresh_token",
                "expires_in"
            ]

            missing_fields = [
                field for field in required_fields
                if not token_data.get(field)
            ]

            if missing_fields:
                raise ValueError(
                    f"Shopify token response is missing: {', '.join(missing_fields)}"
                )

            return token_data

    except httpx.HTTPStatusError as e:
        raise RuntimeError(
            f"Shopify token refresh failed with HTTP {e.response.status_code}: "
            f"{e.response.text}"
        ) from e

    except httpx.RequestError as e:
        raise RuntimeError(
            f"Could not connect to Shopify token endpoint: {str(e)}"
        ) from e


_refresh_lock = asyncio.Lock()



async def get_valid_access_token(shop: str):
    shop = normalize_shop(shop)

    # Retrieve credentials from SQLite.
    stored = get_token(shop)

    if not stored:
        raise ValueError("Shopify store is not connected.")

    def parse_expiry(value):
        if not value:
            return None

        expiry = datetime.fromisoformat(value)

        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        return expiry

    # Refresh 5 minutes before access token expiry.
    expires_at = parse_expiry(stored.get("expires_at"))
    now = datetime.now(timezone.utc)

    if expires_at and expires_at > now + timedelta(minutes=5):
        return stored["access_token"]

    async with _refresh_lock:
        # Reload from SQLite in case another request refreshed it.
        stored = get_token(shop)

        if not stored:
            raise ValueError("Shopify store is not connected.")

        expires_at = parse_expiry(stored.get("expires_at"))
        now = datetime.now(timezone.utc)

        if expires_at and expires_at > now + timedelta(minutes=5):
            return stored["access_token"]

        refresh_token = stored.get("refresh_token")

        if not refresh_token:
            raise ValueError("Shopify refresh token is missing.")

        # Request new credentials from Shopify.
        token_data = await refresh_shopify_token(
            shop,
            refresh_token
        )

        if not token_data:
            raise ValueError("Shopify returned an empty refresh response.")

        # Calculate the new access token expiry.
        new_expires_at = (
            datetime.now(timezone.utc)
            + timedelta(seconds=token_data["expires_in"])
        )

        # Calculate the refresh token expiry, if provided.
        refresh_expires_in = token_data.get("refresh_token_expires_in")

        new_refresh_expires_at = (
            datetime.now(timezone.utc)
            + timedelta(seconds=refresh_expires_in)
            if refresh_expires_in
            else stored.get("refresh_token_expires_at")
        )

        # Save rotated credentials to SQLite.
        save_token(
            shop,
            {
                "customer_id": stored["customer_id"],
                "access_token": token_data["access_token"],
                "refresh_token": token_data["refresh_token"],
                "expires_at": new_expires_at.isoformat(),
                "refresh_token_expires_at": (
                    new_refresh_expires_at.isoformat()
                    if isinstance(new_refresh_expires_at, datetime)
                    else new_refresh_expires_at
                )
            }
        )

        return token_data["access_token"]


    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            token_url,
            data=payload,
            headers={"Accept": "application/json"}
        )

        response.raise_for_status()
        return response.json()


