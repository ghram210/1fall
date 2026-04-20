import httpx
from fastapi import Header, HTTPException
from config import SUPABASE_URL, SUPABASE_SERVICE_KEY


async def get_admin_user(authorization: str = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = authorization.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Invalid token")

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={
                "Authorization": f"Bearer {token}",
                "apikey": SUPABASE_SERVICE_KEY,
            },
            timeout=10,
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = resp.json()
    user_id = user.get("id")
    user_email = user.get("email", "")

    async with httpx.AsyncClient() as client:
        role_resp = await client.get(
            f"{SUPABASE_URL}/rest/v1/admin_users",
            params={"email": f"eq.{user_email}", "select": "role"},
            headers={
                "apikey": SUPABASE_SERVICE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
            },
            timeout=10,
        )

    if role_resp.status_code != 200 or not role_resp.json():
        raise HTTPException(status_code=403, detail="User not found in admin users")

    user_data = role_resp.json()[0]
    if user_data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return {"id": user_id, "email": user_email, "role": "admin"}
