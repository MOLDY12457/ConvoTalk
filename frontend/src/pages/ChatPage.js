import React, { useState, useEffect, useRef } from 'react';
import { 
  MessageCircle, 
  Users, 
  Settings, 
  LogOut, 
  Send, 
  Plus, 
  Hash, 
  Phone, 
  Video, 
  Monitor,
  Smile,
  Image,
  Mic,
  MicOff,
  VideoOff,
  PhoneOff
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Card } from '../components/ui/card';
import { Avatar, AvatarFallback, AvatarImage } from '../components/ui/avatar';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';
import { ScrollArea } from '../components/ui/scroll-area';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '../components/ui/dialog';
import axios from 'axios';
import io from 'socket.io-client';
import GifPicker from '../components/GifPicker';
import VideoCall from '../components/VideoCall';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const ChatPage = ({ user, onLogout }) => {
  const [channels, setChannels] = useState([]);
  const [activeChannel, setActiveChannel] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [socket, setSocket] = useState(null);
  const [showGifPicker, setShowGifPicker] = useState(false);
  const [showVideoCall, setShowVideoCall] = useState(false);
  const [callData, setCallData] = useState(null);
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    initializeChat();
    connectWebSocket();
    
    return () => {
      if (socket) {
        socket.disconnect();
      }
    };
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const initializeChat = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      
      // Fetch channels
      const channelsResponse = await axios.get(`${API}/channels`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setChannels(channelsResponse.data);
      
      // Set default channel (general)
      const generalChannel = channelsResponse.data.find(ch => ch.name === 'general') || channelsResponse.data[0];
      if (generalChannel) {
        setActiveChannel(generalChannel);
        loadMessages(generalChannel.id);
      }
      
      // Fetch online users
      const usersResponse = await axios.get(`${API}/users/online`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setOnlineUsers(usersResponse.data);
      
    } catch (error) {
      console.error('Erreur lors de l\'initialisation:', error);
      toast.error('Erreur lors du chargement des données');
    }
  };

  const connectWebSocket = () => {
    const newSocket = io(BACKEND_URL, {
      query: { userId: user.id }
    });

    newSocket.on('connect', () => {
      console.log('WebSocket connecté');
    });

    newSocket.on('new_message', (data) => {
      if (data.data.channel_id === activeChannel?.id) {
        setMessages(prev => [...prev, data.data]);
      }
    });

    newSocket.on('user_joined', (data) => {
      setOnlineUsers(prev => [...prev, data.user]);
    });

    newSocket.on('user_left', (data) => {
      setOnlineUsers(prev => prev.filter(u => u.id !== data.userId));
    });

    newSocket.on('call_incoming', (data) => {
      setCallData(data);
      toast.info(`Appel entrant de ${data.caller.username}`);
    });

    setSocket(newSocket);
  };

  const loadMessages = async (channelId) => {
    try {
      const token = localStorage.getItem('auth_token');
      const response = await axios.get(`${API}/channels/${channelId}/messages`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setMessages(response.data);
    } catch (error) {
      console.error('Erreur lors du chargement des messages:', error);
    }
  };

  const sendMessage = async (content, messageType = 'text') => {
    if (!content.trim() || !activeChannel) return;

    try {
      const token = localStorage.getItem('auth_token');
      const response = await axios.post(`${API}/channels/${activeChannel.id}/messages`, {
        content,
        message_type: messageType
      }, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      setMessages(prev => [...prev, response.data]);
      setNewMessage('');
    } catch (error) {
      console.error('Erreur lors de l\'envoi du message:', error);
      toast.error('Erreur lors de l\'envoi du message');
    }
  };

  const handleSendMessage = (e) => {
    e.preventDefault();
    sendMessage(newMessage);
  };

  const handleGifSelect = (gifUrl) => {
    sendMessage(gifUrl, 'gif');
    setShowGifPicker(false);
  };

  const handleImageUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      // For demo purposes, we'll just send the file name
      // In a real app, you'd upload to a service like Cloudinary
      sendMessage(`Image: ${file.name}`, 'image');
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString('fr-FR', { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  const startVideoCall = (targetUser) => {
    setCallData({
      type: 'video',
      caller: user,
      target: targetUser,
      isInitiator: true
    });
    setShowVideoCall(true);
  };

  const startAudioCall = (targetUser) => {
    setCallData({
      type: 'audio',
      caller: user,
      target: targetUser,
      isInitiator: true
    });
    setShowVideoCall(true);
  };

  return (
    <div className="h-screen bg-gray-900 flex" data-testid="chat-page">
      {/* Sidebar */}
      <div className="w-64 bg-gray-800 flex flex-col border-r border-gray-700">
        {/* User Profile */}
        <div className="p-4 bg-gray-900/50 border-b border-gray-700">
          <div className="flex items-center space-x-3">
            <Avatar className="h-8 w-8">
              <AvatarImage src={user.avatar_url} alt={user.username} />
              <AvatarFallback className="bg-purple-600 text-white">
                {user.username[0].toUpperCase()}
              </AvatarFallback>
            </Avatar>
            <div className="flex-1">
              <p className="text-sm font-medium text-white">{user.username}</p>
              <div className="flex items-center space-x-1">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-xs text-gray-400">En ligne</span>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={onLogout}
              className="text-gray-400 hover:text-white"
              data-testid="logout-button"
            >
              <LogOut size={16} />
            </Button>
          </div>
        </div>

        {/* Channels */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-3">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                Canaux texte
              </h3>
              <Button variant="ghost" size="sm" className="h-4 w-4 p-0 text-gray-400">
                <Plus size={12} />
              </Button>
            </div>
            
            <div className="space-y-1">
              {channels.map((channel) => (
                <button
                  key={channel.id}
                  onClick={() => {
                    setActiveChannel(channel);
                    loadMessages(channel.id);
                  }}
                  className={`w-full flex items-center space-x-2 px-2 py-1.5 rounded text-left transition-colors ${
                    activeChannel?.id === channel.id
                      ? 'bg-gray-700 text-white'
                      : 'text-gray-300 hover:bg-gray-700/50 hover:text-white'
                  }`}
                  data-testid={`channel-${channel.name}`}
                >
                  <Hash size={16} className="text-gray-400" />
                  <span className="text-sm">{channel.name}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Online Users */}
          <div className="p-3 border-t border-gray-700">
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">
              En ligne — {onlineUsers.length}
            </h3>
            <div className="space-y-2">
              {onlineUsers.map((onlineUser) => (
                <div 
                  key={onlineUser.id}
                  className="flex items-center justify-between group"
                >
                  <div className="flex items-center space-x-2">
                    <div className="relative">
                      <Avatar className="h-6 w-6">
                        <AvatarImage src={onlineUser.avatar_url} alt={onlineUser.username} />
                        <AvatarFallback className="bg-gray-600 text-white text-xs">
                          {onlineUser.username[0].toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <div className="absolute -bottom-1 -right-1 w-3 h-3 bg-green-500 border-2 border-gray-800 rounded-full"></div>
                    </div>
                    <span className="text-sm text-gray-300">{onlineUser.username}</span>
                  </div>
                  
                  {onlineUser.id !== user.id && (
                    <div className="flex space-x-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 text-gray-400 hover:text-white"
                        onClick={() => startAudioCall(onlineUser)}
                        data-testid={`call-audio-${onlineUser.username}`}
                      >
                        <Phone size={12} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 text-gray-400 hover:text-white"
                        onClick={() => startVideoCall(onlineUser)}
                        data-testid={`call-video-${onlineUser.username}`}
                      >
                        <Video size={12} />
                      </Button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        {/* Chat Header */}
        {activeChannel && (
          <div className="h-14 bg-gray-800 border-b border-gray-700 flex items-center justify-between px-4">
            <div className="flex items-center space-x-2">
              <Hash size={20} className="text-gray-400" />
              <span className="font-semibold text-white">{activeChannel.name}</span>
              {activeChannel.description && (
                <span className="text-sm text-gray-400">— {activeChannel.description}</span>
              )}
            </div>
            
            <div className="flex items-center space-x-2">
              <Button variant="ghost" size="sm" className="text-gray-400 hover:text-white">
                <Users size={18} />
              </Button>
              <Button variant="ghost" size="sm" className="text-gray-400 hover:text-white">
                <Settings size={18} />
              </Button>
            </div>
          </div>
        )}

        {/* Messages Area */}
        <ScrollArea className="flex-1 px-4">
          <div className="py-4 space-y-4" data-testid="messages-container">
            {messages.map((message, index) => {
              const isOwn = message.sender_id === user.id;
              const showAvatar = index === 0 || messages[index - 1].sender_id !== message.sender_id;
              
              return (
                <div
                  key={message.id}
                  className={`flex items-start space-x-3 group ${isOwn ? 'justify-end' : ''}`}
                  data-testid={`message-${message.id}`}
                >
                  {!isOwn && showAvatar && (
                    <Avatar className="h-8 w-8 mt-0.5">
                      <AvatarImage src={message.sender_avatar} alt={message.sender_username} />
                      <AvatarFallback className="bg-gray-600 text-white text-sm">
                        {message.sender_username[0].toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                  )}
                  
                  {!isOwn && !showAvatar && (
                    <div className="w-8 h-8 mt-0.5"></div>
                  )}
                  
                  <div className={`flex-1 ${isOwn ? 'flex justify-end' : ''}`}>
                    {showAvatar && !isOwn && (
                      <div className="flex items-baseline space-x-2 mb-1">
                        <span className="font-semibold text-white text-sm">
                          {message.sender_username}
                        </span>
                        <span className="text-xs text-gray-400">
                          {formatTime(message.timestamp)}
                        </span>
                      </div>
                    )}
                    
                    <div className={`${isOwn ? 'max-w-xs ml-auto' : 'max-w-2xl'}`}>
                      {message.message_type === 'gif' ? (
                        <img
                          src={message.content}
                          alt="GIF"
                          className="rounded-lg max-w-xs max-h-60 object-cover"
                        />
                      ) : message.message_type === 'image' ? (
                        <div className="bg-gray-700 rounded-lg p-3">
                          <span className="text-sm text-gray-300">{message.content}</span>
                        </div>
                      ) : (
                        <div className={`rounded-lg px-3 py-2 ${
                          isOwn 
                            ? 'bg-purple-600 text-white' 
                            : 'bg-gray-700 text-gray-100'
                        }`}>
                          <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                          {isOwn && (
                            <span className="text-xs text-purple-200 opacity-70 mt-1 block">
                              {formatTime(message.timestamp)}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
            <div ref={messagesEndRef} />
          </div>
        </ScrollArea>

        {/* Message Input */}
        {activeChannel && (
          <div className="p-4 bg-gray-800 border-t border-gray-700">
            <form onSubmit={handleSendMessage} className="flex items-center space-x-2">
              <div className="flex-1 relative">
                <Input
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  placeholder={`Message #${activeChannel.name}`}
                  className="bg-gray-700 border-gray-600 text-white pr-20"
                  data-testid="message-input"
                />
                <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex items-center space-x-1">
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleImageUpload}
                    accept="image/*"
                    className="hidden"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0 text-gray-400 hover:text-white"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <Image size={14} />
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0 text-gray-400 hover:text-white"
                    onClick={() => setShowGifPicker(true)}
                    data-testid="gif-picker-button"
                  >
                    <Smile size={14} />
                  </Button>
                </div>
              </div>
              <Button
                type="submit"
                disabled={!newMessage.trim()}
                className="bg-purple-600 hover:bg-purple-700"
                data-testid="send-message-button"
              >
                <Send size={16} />
              </Button>
            </form>
          </div>
        )}
      </div>

      {/* GIF Picker Modal */}
      {showGifPicker && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 w-96 max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-white font-semibold">Choisir un GIF</h3>
              <button
                onClick={() => setShowGifPicker(false)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <GifPicker onGifSelect={handleGifSelect} />
          </div>
        </div>
      )}

      {/* Video Call Modal */}
      {showVideoCall && callData && (
        <VideoCall
          callData={callData}
          onClose={() => {
            setShowVideoCall(false);
            setCallData(null);
          }}
        />
      )}
    </div>
  );
};

export default ChatPage;