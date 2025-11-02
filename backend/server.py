from fastapi import FastAPI, APIRouter, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
import os
import uuid
import hashlib
import requests
from datetime import datetime, timezone, timedelta
import jwt

# Environment variables
MONGO_URL = os.environ.get('MONGO_URL')
DB_NAME = os.environ.get('DB_NAME', 'convotalk_db')
JWT_SECRET = os.environ.get('JWT_SECRET', 'change-this-secret-key')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://votre-domaine.com')

# MongoDB connection
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# FastAPI app
app = FastAPI(
    title="ConvoTalk API",
    description="API pour ConvoTalk - Alternative Discord",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],  # En production, spécifier votre domaine
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    avatar_url: Optional[str] = None
    is_online: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Message(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    sender_id: str
    sender_username: str
    sender_avatar: Optional[str] = None
    channel_id: str = "general"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message_type: str = "text"

class Channel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    is_private: bool = False
    members: List[str] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Helper functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed_password: str) -> bool:
    return hash_password(password) == hashed_password

def create_jwt_token(user_id: str, email: str, username: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24 * 7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except:
        return None

async def get_current_user(request: Request) -> Optional[dict]:
    token = request.headers.get("authorization")
    if token and token.startswith("Bearer "):
        token = token.split("Bearer ")[1]
        return verify_jwt_token(token)
    return None

# Routes
@app.get("/")
async def root():
    return {"message": "ConvoTalk API", "version": "1.0", "status": "running"}

@app.post("/api/auth/register")
async def register(user_data: UserRegister):
    existing_user = await db.users.find_one({
        "$or": [{"email": user_data.email}, {"username": user_data.username}]
    })
    
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email ou nom d'utilisateur déjà utilisé"
        )
    
    user = User(
        username=user_data.username,
        email=user_data.email
    )
    
    user_dict = user.model_dump()
    user_dict["password"] = hash_password(user_data.password)
    
    await db.users.insert_one(user_dict)
    
    token = create_jwt_token(user.id, user.email, user.username)
    
    return {
        "message": "Utilisateur créé avec succès",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "avatar_url": user.avatar_url
        },
        "token": token
    }

@app.post("/api/auth/login")
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password"]):
        raise HTTPException(
            status_code=401,
            detail="Email ou mot de passe incorrect"
        )
    
    token = create_jwt_token(user["id"], user["email"], user["username"])
    
    return {
        "message": "Connexion réussie",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "avatar_url": user.get("avatar_url")
        },
        "token": token
    }

@app.get("/api/auth/google")
async def google_login(redirect_url: str = None):
    if not redirect_url:
        redirect_url = f"{FRONTEND_URL}/auth/callback"
    
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={redirect_url}"
        f"&response_type=code"
        f"&scope=openid email profile"
    )
    return {"auth_url": auth_url}

@app.post("/api/auth/google/callback")
async def google_callback(request: Request):
    body = await request.json()
    code = body.get("code")
    
    if not code:
        raise HTTPException(status_code=400, detail="Code manquant")
    
    try:
        token_url = "https://oauth2.googleapis.com/token"
        
        token_data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{FRONTEND_URL}/auth/callback"
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_info = token_response.json()
        
        if "access_token" not in token_info:
            raise HTTPException(status_code=400, detail="Erreur token Google")
        
        user_info_response = requests.get(
            f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={token_info['access_token']}"
        )
        user_info = user_info_response.json()
        
        existing_user = await db.users.find_one({"email": user_info["email"]})
        
        if existing_user:
            user = existing_user
        else:
            user = User(
                username=user_info["name"].replace(" ", "_"),
                email=user_info["email"],
                avatar_url=user_info.get("picture")
            )
            user_dict = user.model_dump()
            await db.users.insert_one(user_dict)
            user = user_dict
        
        token = create_jwt_token(user["id"], user["email"], user["username"])
        
        return {
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "avatar_url": user.get("avatar_url")
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/auth/me")
async def get_current_user_info(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Non authentifié")
    
    user = await db.users.find_one({"id": current_user["user_id"]})
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "avatar_url": user.get("avatar_url"),
        "is_online": user.get("is_online", False)
    }

@app.get("/api/channels")
async def get_channels(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Non authentifié")
    
    channels = await db.channels.find().to_list(length=None)
    result = []
    for channel in channels:
        if '_id' in channel:
            del channel['_id']
        if 'created_at' in channel and hasattr(channel['created_at'], 'isoformat'):
            channel['created_at'] = channel['created_at'].isoformat()
        result.append(channel)
    return result

@app.get("/api/channels/{channel_id}/messages")
async def get_messages(channel_id: str, request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Non authentifié")
    
    messages = await db.messages.find({"channel_id": channel_id}).sort("timestamp", 1).limit(50).to_list(length=None)
    result = []
    for message in messages:
        if '_id' in message:
            del message['_id']
        if 'timestamp' in message and hasattr(message['timestamp'], 'isoformat'):
            message['timestamp'] = message['timestamp'].isoformat()
        result.append(message)
    return result

@app.post("/api/channels/{channel_id}/messages")
async def send_message(channel_id: str, request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Non authentifié")
    
    body = await request.json()
    user = await db.users.find_one({"id": current_user["user_id"]})
    
    message = Message(
        content=body["content"],
        sender_id=current_user["user_id"],
        sender_username=user["username"],
        sender_avatar=user.get("avatar_url"),
        channel_id=channel_id,
        message_type=body.get("message_type", "text")
    )
    
    message_dict = message.model_dump()
    await db.messages.insert_one(message_dict)
    
    if '_id' in message_dict:
        del message_dict['_id']
    
    return message_dict

@app.get("/api/users/online")
async def get_online_users(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Non authentifié")
    
    users = await db.users.find({"is_online": True}).to_list(length=None)
    result = []
    for user in users:
        if '_id' in user:
            del user['_id']
        result.append({
            "id": user["id"],
            "username": user["username"],
            "avatar_url": user.get("avatar_url")
        })
    return result

# Initialize default channel
@app.on_event("startup")
async def startup_event():
    general_channel = await db.channels.find_one({"name": "general"})
    if not general_channel:
        channel = Channel(
            name="general",
            description="Canal général pour toutes les discussions",
            is_private=False,
            members=[]
        )
        await db.channels.insert_one(channel.model_dump())

# Vercel handler
def handler(request, context):
    return app(request, context)