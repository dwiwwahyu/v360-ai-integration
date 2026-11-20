import httpx
from datetime import datetime, timezone

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from urllib.parse import urlparse

from app.security.token_store import init_db

from app.security.token_store import save_token, get_token


from app.integrations.shopify_oauth import (
    generate_authorization_url,
    validate_callback_hmac,
    exchange_code_for_token,
    normalize_shop,
    oauth_states,
    get_granted_scopes,
    get_shopify_sales,
    refresh_shopify_token,
    get_valid_access_token,
)

app = FastAPI(
    title="V360 AI Integration Agent",
    description="Shopify integration and OAuth service",
    version="1.0.0"
)

init_db()


class ShopifyConnectRequest(BaseModel):
    shop: str
    # Local testing only. Production must use the
    # customer identity from authenticated V360 sessions.
    customer_id: str = Field(default="local-test")


@app.get("/")
async def home():
    return {
        "application": "V360 AI Integration Agent",
        "status": "online"
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/api/shopify/connect")
async def connect_shopify(data: ShopifyConnectRequest):

    try:
        authorization_url = generate_authorization_url(
            data.shop,
            data.customer_id
        )

        return {
            "status": "authorization_required",
            "authorization_url": authorization_url,
            "message": "Open this URL to authorize Shopify."
        }

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.get("/api/shopify/callback")
async def shopify_callback(request: Request):

    params = dict(request.query_params)

    shop = params.get("shop")
    code = params.get("code")
    state = params.get("state")

    if not shop or not state:
        raise HTTPException(
            status_code=400,
            detail="Missing Shopify callback parameters."
        )

    # Verify callback signature.
    if not validate_callback_hmac(params):
        raise HTTPException(
            status_code=403,
            detail="Invalid Shopify callback signature."
        )

    # Verify authorization state.
    state_data = oauth_states.get(state)

    if not state_data:
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired OAuth state."
        )

    age = (
        datetime.now(timezone.utc)
        - state_data["created_at"]
    ).total_seconds()

    if age > 600:
        oauth_states.pop(state, None)

        raise HTTPException(
            status_code=403,
            detail="OAuth session expired. Please try again."
        )

    try:
        normalized_shop = normalize_shop(shop)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid Shopify store."
        )

    if normalized_shop != state_data["shop"]:
        raise HTTPException(
            status_code=403,
            detail="Shopify store does not match OAuth request."
        )

    if params.get("error"):
        oauth_states.pop(state, None)

        return {
            "status": "authorization_denied",
            "message": "Customer did not authorize the application."
        }

    if not code:
        raise HTTPException(
            status_code=400,
            detail="Authorization code is missing."
        )

    # Consume state before exchanging the code to prevent replay.
    oauth_states.pop(state, None)

    try:
        token_data = await exchange_code_for_token(
            normalized_shop,
            code
        )

    
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=token_data["expires_in"]
        )

        refresh_token_expires_in = token_data.get(
            "refresh_token_expires_in"
        )

        refresh_token_expires_at = None

        if refresh_token_expires_in:
            refresh_token_expires_at = (
                datetime.now(timezone.utc)
                + timedelta(seconds=refresh_token_expires_in)
            )

        save_token(
            normalized_shop,
            {
                "customer_id": state_data["customer_id"],
                "access_token": token_data["access_token"],
                "refresh_token": token_data["refresh_token"],
                "expires_at": expires_at.isoformat(),
                "refresh_token_expires_at": (
                    refresh_token_expires_at.isoformat()
                    if refresh_token_expires_at
                    else None
                )
            }
        )

        # Do not expose or log tokens.
        # Next development step: securely hand them to V360.
        return {
            "status": "authorized",
            "shop": normalized_shop,
            "customer_id": state_data["customer_id"],
            "token_received": bool(token_data.get("access_token")),
            "expires_in": token_data.get("expires_in"),
            "refresh_token_received": bool(
                token_data.get("refresh_token")
            ),
            "message": "Shopify authorization successful."
        }

    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Shopify token exchange failed."
        )


@app.get("/api/shopify/scopes")
async def shopify_scopes(shop: str):
    normalized_shop = normalize_shop(shop)

    stored = get_token(normalized_shop)

    if not stored:
        raise HTTPException(
            status_code=404,
            detail="No Shopify token found. Please authorize the store first."
        )

    try:
        access_token = await get_valid_access_token(normalized_shop)

        result = await get_granted_scopes(
            normalized_shop,
            access_token
        )

        return {
            "shop": normalized_shop,
            "permissions": result.get("data", {})
                .get("currentAppInstallation", {})
                .get("accessScopes", []),
            "errors": result.get("errors", [])
        }

    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Shopify API returned HTTP {e.response.status_code}."
        )


@app.get("/api/shopify/analytics/sales")
async def shopify_sales(shop: str):
    normalized_shop = normalize_shop(shop)

    stored = get_token(normalized_shop)

    if not stored:
        raise HTTPException(
            status_code=404,
            detail="No Shopify token found. Please authorize the store first."
        )

    try:
        access_token = await get_valid_access_token(normalized_shop)

        result = await get_shopify_sales(
            normalized_shop,
            access_token
        )

        return result

    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Shopify API returned HTTP {e.response.status_code}."
        )
