import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

# --- THE ASSIGNED VALUES ---
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-d7a5rpgg.apps.exam.local"

# This is the "blacklight" we use to check the token's signature
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

# This tells FastAPI to expect a JSON body like {"token": "ey..."}
class TokenRequest(BaseModel):
    token: str

# --- THE BOUNCER (The Endpoint) ---
@app.post("/verify")
def verify_token(request: TokenRequest):
    try:
        # PyJWT is amazing. By passing the issuer and audience here,
        # it automatically checks the signature, expiry, issuer, AND audience all at once!
        decoded_payload = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE
        )
        
        # If the code reaches this line, the token passed ALL 4 checks!
        return {
            "valid": True,
            "email": decoded_payload.get("email"),
            "sub": decoded_payload.get("sub"),
            "aud": decoded_payload.get("aud")
        }
        
    except jwt.ExpiredSignatureError:
        # Token has expired
        return JSONResponse(status_code=401, content={"valid": False})
        
    except jwt.InvalidTokenError:
        # Fails signature, audience, issuer, or is totally tampered with
        return JSONResponse(status_code=401, content={"valid": False})
