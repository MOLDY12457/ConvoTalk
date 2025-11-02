from fastapi import FastAPI, APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Set
import os
import logging
import uuid
import hashlib
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from pathlib import Path
import jwt
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Secret Key
JWT_SECRET = os.environ.get('JWT_SECRET', 'votre_secret_key_tres_securise')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 7  # 7 days

# Create the main app
app = FastAPI(title="ConvoTalk API")
api_router = APIRouter(prefix="/api")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}  # user_id -> connection_id

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = websocket
        self.user_connections[user_id] = connection_id
        return connection_id

    def disconnect(self, connection_id: str, user_id: str):
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        if user_id in self.user_connections:
            del self.user_connections[user_id]

    async def send_personal_message(self, message: str, user_id: str):
        if user_id in self.user_connections:
            connection_id = self.user_connections[user_id]
            if connection_id in self.active_connections:
                websocket = self.active_connections[connection_id]
                await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections.values():
            await connection.send_text(message)

manager = ConnectionManager()

# Pydantic Models
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
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Message(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    sender_id: str
    sender_username: str
    sender_avatar: Optional[str] = None
    channel_id: str = "general"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message_type: str = "text"  # text, gif, image

class Channel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    is_private: bool = False
    members: List[str] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SessionData(BaseModel):
    user_id: str
    email: str
    username: str
    session_token: str
    expires_at: datetime

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
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # Convert exp timestamp to timezone-aware datetime for comparison
        if 'exp' in payload:
            payload['exp'] = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def get_current_user(request: Request) -> Optional[dict]:
    # Check cookie first
    token = request.cookies.get("session_token")
    
    # Fallback to Authorization header
    if not token:
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split("Bearer ")[1]
    
    if not token:
        return None
    
    # Verify token
    payload = verify_jwt_token(token)
    if not payload:
        return None
    
    # Check if session exists in database
    session = await db.sessions.find_one({"session_token": token})
    if not session:
        return None
    
    # Handle timezone comparison
    expires_at = session["expires_at"]
    if hasattr(expires_at, 'replace') and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    
    if expires_at < datetime.now(timezone.utc):
        return None
    
    return payload

# API Routes
@api_router.get("/")
async def api_root():
    return {"message": "ConvoTalk API v1.0", "status": "running"}

# Authentication Routes
@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({
        "$or": [{"email": user_data.email}, {"username": user_data.username}]
    })
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email ou nom d'utilisateur déjà utilisé"
        )
    
    # Create new user
    user = User(
        username=user_data.username,
        email=user_data.email
    )
    
    user_dict = user.model_dump()
    user_dict["password"] = hash_password(user_data.password)
    
    await db.users.insert_one(user_dict)
    
    # Create JWT token
    token = create_jwt_token(user.id, user.email, user.username)
    
    # Store session in database
    session_data = SessionData(
        user_id=user.id,
        email=user.email,
        username=user.username,
        session_token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    )
    
    await db.sessions.insert_one(session_data.model_dump())
    
    response_data = {
        "message": "Utilisateur créé avec succès",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "avatar_url": user.avatar_url
        },
        "token": token
    }
    
    return response_data

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    # Find user
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect"
        )
    
    # Create JWT token
    token = create_jwt_token(user["id"], user["email"], user["username"])
    
    # Store session in database
    session_data = SessionData(
        user_id=user["id"],
        email=user["email"],
        username=user["username"],
        session_token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    )
    
    await db.sessions.insert_one(session_data.model_dump())
    
    # Update user online status
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"is_online": True, "last_seen": datetime.now(timezone.utc)}}
    )
    
    response_data = {
        "message": "Connexion réussie",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "avatar_url": user.get("avatar_url")
        },
        "token": token
    }
    
    return response_data

@api_router.get("/auth/google")
async def google_auth(redirect_url: str = "http://localhost:3000/chat"):
    """Redirect to Google OAuth via Emergent Auth"""
    auth_url = f"https://auth.emergentagent.com/?redirect={redirect_url}"
    return {"auth_url": auth_url}

@api_router.post("/auth/google/callback")
async def google_callback(request: Request):
    """Handle Google OAuth callback from Emergent Auth"""
    session_id = request.headers.get("X-Session-ID")
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session ID manquant"
        )
    
    # Call Emergent Auth API to get user data
    try:
        response = requests.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": session_id}
        )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session invalide"
            )
        
        user_data = response.json()
        
        # Check if user exists
        existing_user = await db.users.find_one({"email": user_data["email"]})
        
        if existing_user:
            user = existing_user
        else:
            # Create new user
            user = User(
                username=user_data["name"].replace(" ", "_"),
                email=user_data["email"],
                avatar_url=user_data.get("picture")
            )
            user_dict = user.model_dump()
            await db.users.insert_one(user_dict)
            user = user_dict
        
        # Create our own JWT token
        token = create_jwt_token(user["id"], user["email"], user["username"])
        
        # Store session in database
        session_data = SessionData(
            user_id=user["id"],
            email=user["email"],
            username=user["username"],
            session_token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
        )
        
        await db.sessions.insert_one(session_data.model_dump())
        
        # Update user online status
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": {"is_online": True, "last_seen": datetime.now(timezone.utc)}}
        )
        
        return {
            "message": "Connexion Google réussie",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "avatar_url": user.get("avatar_url")
            },
            "token": token
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Erreur lors de l'authentification Google: {str(e)}"
        )

@api_router.post("/auth/logout")
async def logout(request: Request):
    current_user = await get_current_user(request)
    if current_user:
        # Delete session from database
        token = request.cookies.get("session_token")
        if not token:
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split("Bearer ")[1]
        
        if token:
            await db.sessions.delete_one({"session_token": token})
        
        # Update user offline status
        await db.users.update_one(
            {"id": current_user["user_id"]},
            {"$set": {"is_online": False, "last_seen": datetime.now(timezone.utc)}}
        )
    
    return {"message": "Déconnexion réussie"}

@api_router.get("/auth/me")
async def get_current_user_info(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Non authentifié"
        )
    
    user = await db.users.find_one({"id": current_user["user_id"]})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "avatar_url": user.get("avatar_url"),
        "is_online": user.get("is_online", False)
    }

# Chat Routes
@api_router.get("/channels")
async def get_channels(request: Request):
    try:
        current_user = await get_current_user(request)
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Non authentifié"
            )
        
        channels = await db.channels.find().to_list(length=None)
        result = []
        for channel in channels:
            # Remove MongoDB's _id field 
            if '_id' in channel:
                del channel['_id']
            # Convert datetime to ISO string for JSON serialization
            if 'created_at' in channel and hasattr(channel['created_at'], 'isoformat'):
                channel['created_at'] = channel['created_at'].isoformat()
            
            result.append(channel)
        return result
    except Exception as e:
        logger.error(f"Error in get_channels: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur serveur: {str(e)}"
        )

@api_router.post("/channels", response_model=Channel)
async def create_channel(channel_data: dict, request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Non authentifié"
        )
    
    channel = Channel(
        name=channel_data["name"],
        description=channel_data.get("description"),
        is_private=channel_data.get("is_private", False),
        members=[current_user["user_id"]]
    )
    
    await db.channels.insert_one(channel.model_dump())
    return channel

@api_router.get("/channels/{channel_id}/messages")
async def get_messages(channel_id: str, request: Request, limit: int = 50):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Non authentifié"
        )
    
    messages = await db.messages.find({"channel_id": channel_id}).sort("timestamp", -1).limit(limit).to_list(length=None)
    messages.reverse()  # Show oldest first
    return [Message(**message) for message in messages]

@api_router.post("/channels/{channel_id}/messages")
async def send_message(channel_id: str, message_data: dict, request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Non authentifié"
        )
    
    user = await db.users.find_one({"id": current_user["user_id"]})
    
    message = Message(
        content=message_data["content"],
        sender_id=current_user["user_id"],
        sender_username=user["username"],
        sender_avatar=user.get("avatar_url"),
        channel_id=channel_id,
        message_type=message_data.get("message_type", "text")
    )
    
    await db.messages.insert_one(message.model_dump())
    
    # Broadcast message to all connected users (simplified for now)
    await manager.broadcast(json.dumps({
        "type": "new_message",
        "data": message.model_dump(mode="json")
    }))
    
    return message

@api_router.get("/users/online")
async def get_online_users(request: Request):
    current_user = await get_current_user(request)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Non authentifié"
        )
    
    users = await db.users.find({"is_online": True}).to_list(length=None)
    return [{"id": u["id"], "username": u["username"], "avatar_url": u.get("avatar_url")} for u in users]

# WebSocket endpoint
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    connection_id = await manager.connect(websocket, user_id)
    try:
        # Update user online status
        await db.users.update_one(
            {"id": user_id},
            {"$set": {"is_online": True, "last_seen": datetime.now(timezone.utc)}}
        )
        
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            if message_data["type"] == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            elif message_data["type"] == "message":
                # Handle message sending via WebSocket
                await manager.broadcast(data)
                
    except WebSocketDisconnect:
        manager.disconnect(connection_id, user_id)
        # Update user offline status
        await db.users.update_one(
            {"id": user_id},
            {"$set": {"is_online": False, "last_seen": datetime.now(timezone.utc)}}
        )

# Initialize default channel
@app.on_event("startup")
async def startup_event():
    # Create general channel if it doesn't exist
    general_channel = await db.channels.find_one({"name": "general"})
    if not general_channel:
        channel = Channel(
            name="general",
            description="Canal général pour toutes les discussions",
            is_private=False,
            members=[]
        )
        await db.channels.insert_one(channel.model_dump())

# Include API router
app.include_router(api_router)

# Simple root route for testing
@app.get("/")
async def root():
    return {"message": "ConvoTalk API is running"}

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)