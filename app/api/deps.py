"""
API Dependencies.
"""
from typing import Generator
# In this simple architecture, we might not need complex deps 
# since storage queries create their own connections.
# But we can add shared logic here.

def verify_remote_ip(ip: str) -> str:
    """Basic IP validation"""
    if len(ip) > 45: # IPv6 max length
        raise ValueError("Invalid IP length")
    # Could add regex or ipaddress check here
    return ip

# --- Authentication Dependency ---
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from app.core.security import ALGORITHM, SECRET_KEY, oauth2_scheme

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    return username
