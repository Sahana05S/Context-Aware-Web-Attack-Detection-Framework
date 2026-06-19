from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from app.core.security import get_password_hash, verify_password, create_access_token
from app.storage.db import get_db_connection
from app.core.config import settings
import sqlite3

try:
    import psycopg2
    DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError, psycopg2.IntegrityError)
except ImportError:
    DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,)

router = APIRouter()


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


def _stmt(query: str) -> str:
    """Format placeholders according to DATABASE_TYPE"""
    if settings.DATABASE_TYPE == "postgresql":
        return query.replace('?', '%s')
    return query


@router.post("/register", response_model=Token)
def register(user: UserCreate):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    hashed_password = get_password_hash(user.password)
    try:
        cursor.execute(
            _stmt("INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)"),
            (user.username, user.email, hashed_password)
        )
        conn.commit()
        # Automatically login upon register
        access_token = create_access_token(data={"sub": user.username})
        return {"access_token": access_token, "token_type": "bearer"}
    except DB_INTEGRITY_ERRORS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    finally:
        pass


@router.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        _stmt("SELECT username, hashed_password FROM users WHERE username = ?"), 
        (form_data.username,)
    )
    user = cursor.fetchone()
    
    if not user or not verify_password(form_data.password, user[1]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user[0]})
    return {"access_token": access_token, "token_type": "bearer"}
