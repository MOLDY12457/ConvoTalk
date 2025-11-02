import React, { useState, useEffect, useRef } from 'react';
import { 
  Video, 
  VideoOff, 
  Mic, 
  MicOff, 
  Phone, 
  PhoneOff, 
  Monitor,
  MonitorOff,
  Users,
  Settings
} from 'lucide-react';
import { Button } from './ui/button';
import { Card } from './ui/card';
import { Avatar, AvatarFallback, AvatarImage } from './ui/avatar';
import { toast } from 'sonner';

const VideoCall = ({ callData, onClose }) => {
  const [isVideoEnabled, setIsVideoEnabled] = useState(callData.type === 'video');
  const [isAudioEnabled, setIsAudioEnabled] = useState(true);
  const [isScreenSharing, setIsScreenSharing] = useState(false);
  const [callStatus, setCallStatus] = useState('connecting'); // connecting, connected, ended
  const [localStream, setLocalStream] = useState(null);
  const [remoteStream, setRemoteStream] = useState(null);
  
  const localVideoRef = useRef(null);
  const remoteVideoRef = useRef(null);
  const peerConnectionRef = useRef(null);

  useEffect(() => {
    initializeCall();
    
    return () => {
      cleanup();
    };
  }, []);

  const initializeCall = async () => {
    try {
      // Get user media
      const stream = await navigator.mediaDevices.getUserMedia({
        video: isVideoEnabled,
        audio: isAudioEnabled
      });
      
      setLocalStream(stream);
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
      }

      // Create peer connection (simplified for demo)
      const peerConnection = new RTCPeerConnection({
        iceServers: [
          { urls: 'stun:stun.l.google.com:19302' }
        ]
      });

      // Add local stream tracks
      stream.getTracks().forEach(track => {
        peerConnection.addTrack(track, stream);
      });

      // Handle remote stream
      peerConnection.ontrack = (event) => {
        const [remoteStream] = event.streams;
        setRemoteStream(remoteStream);
        if (remoteVideoRef.current) {
          remoteVideoRef.current.srcObject = remoteStream;
        }
      };

      peerConnectionRef.current = peerConnection;
      
      // Simulate call connection after 2 seconds
      setTimeout(() => {
        setCallStatus('connected');
        toast.success('Appel connecté');
      }, 2000);

    } catch (error) {
      console.error('Erreur lors de l\'initialisation de l\'appel:', error);
      toast.error('Erreur d\'accès à la caméra/microphone');
      setCallStatus('ended');
    }
  };

  const cleanup = () => {
    if (localStream) {
      localStream.getTracks().forEach(track => track.stop());
    }
    if (peerConnectionRef.current) {
      peerConnectionRef.current.close();
    }
  };

  const toggleVideo = () => {
    if (localStream) {
      const videoTrack = localStream.getVideoTracks()[0];
      if (videoTrack) {
        videoTrack.enabled = !isVideoEnabled;
        setIsVideoEnabled(!isVideoEnabled);
      }
    }
  };

  const toggleAudio = () => {
    if (localStream) {
      const audioTrack = localStream.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !isAudioEnabled;
        setIsAudioEnabled(!isAudioEnabled);
      }
    }
  };

  const toggleScreenShare = async () => {
    try {
      if (!isScreenSharing) {
        // Start screen sharing
        const screenStream = await navigator.mediaDevices.getDisplayMedia({
          video: true,
          audio: true
        });
        
        // Replace video track
        if (peerConnectionRef.current && localStream) {
          const videoTrack = localStream.getVideoTracks()[0];
          const sender = peerConnectionRef.current.getSenders().find(s => 
            s.track && s.track.kind === 'video'
          );
          
          if (sender) {
            await sender.replaceTrack(screenStream.getVideoTracks()[0]);
          }
        }
        
        if (localVideoRef.current) {
          localVideoRef.current.srcObject = screenStream;
        }
        
        setIsScreenSharing(true);
        toast.success('Partage d\'écran activé');
        
        // Listen for screen share end
        screenStream.getVideoTracks()[0].onended = () => {
          setIsScreenSharing(false);
          // Revert to camera
          if (localVideoRef.current && localStream) {
            localVideoRef.current.srcObject = localStream;
          }
        };
        
      } else {
        // Stop screen sharing - revert to camera
        if (localVideoRef.current && localStream) {
          localVideoRef.current.srcObject = localStream;
        }
        setIsScreenSharing(false);
        toast.info('Partage d\'écran arrêté');
      }
    } catch (error) {
      console.error('Erreur lors du partage d\'écran:', error);
      toast.error('Erreur lors du partage d\'écran');
    }
  };

  const endCall = () => {
    cleanup();
    setCallStatus('ended');
    toast.info('Appel terminé');
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/95 flex flex-col" data-testid="video-call">
      {/* Header */}
      <div className="bg-gray-900 p-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Avatar className="h-8 w-8">
            <AvatarImage src={callData.target.avatar_url} alt={callData.target.username} />
            <AvatarFallback className="bg-gray-600 text-white">
              {callData.target.username[0].toUpperCase()}
            </AvatarFallback>
          </Avatar>
          <div>
            <p className="font-medium text-white">{callData.target.username}</p>
            <p className="text-sm text-gray-400">
              {callStatus === 'connecting' ? 'Connexion...' : 
               callStatus === 'connected' ? 'En appel' : 'Appel terminé'}
            </p>
          </div>
        </div>
        
        <Button
          variant="ghost"
          onClick={onClose}
          className="text-gray-400 hover:text-white"
        >
          ✕
        </Button>
      </div>

      {/* Video Area */}
      <div className="flex-1 relative">
        {/* Remote Video */}
        <div className="absolute inset-0">
          {callStatus === 'connected' ? (
            <video
              ref={remoteVideoRef}
              autoPlay
              playsInline
              className="w-full h-full object-cover"
              data-testid="remote-video"
            />
          ) : (
            <div className="w-full h-full flex items-center justify-center bg-gray-800">
              <div className="text-center">
                <Avatar className="h-24 w-24 mx-auto mb-4">
                  <AvatarImage src={callData.target.avatar_url} alt={callData.target.username} />
                  <AvatarFallback className="bg-gray-600 text-white text-2xl">
                    {callData.target.username[0].toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <p className="text-white font-medium text-lg">{callData.target.username}</p>
                <p className="text-gray-400">{callStatus === 'connecting' ? 'Connexion en cours...' : 'En attente...'}</p>
              </div>
            </div>
          )}
        </div>

        {/* Local Video (Picture-in-Picture) */}
        <div className="absolute top-4 right-4 w-48 h-36 bg-gray-800 rounded-lg overflow-hidden border-2 border-gray-600">
          {isVideoEnabled ? (
            <video
              ref={localVideoRef}
              autoPlay
              playsInline
              muted
              className="w-full h-full object-cover"
              data-testid="local-video"
            />
          ) : (
            <div className="w-full h-full flex items-center justify-center bg-gray-700">
              <Avatar className="h-12 w-12">
                <AvatarImage src={callData.caller.avatar_url} alt={callData.caller.username} />
                <AvatarFallback className="bg-gray-600 text-white">
                  {callData.caller.username[0].toUpperCase()}
                </AvatarFallback>
              </Avatar>
            </div>
          )}
        </div>
      </div>

      {/* Controls */}
      <div className="bg-gray-900 p-6">
        <div className="flex items-center justify-center space-x-4">
          {/* Microphone */}
          <Button
            variant={isAudioEnabled ? "outline" : "destructive"}
            size="lg"
            onClick={toggleAudio}
            className={`h-12 w-12 rounded-full ${
              isAudioEnabled 
                ? 'border-gray-600 hover:bg-gray-800' 
                : 'bg-red-600 hover:bg-red-700'
            }`}
            data-testid="toggle-audio-button"
          >
            {isAudioEnabled ? <Mic size={20} /> : <MicOff size={20} />}
          </Button>

          {/* Video */}
          <Button
            variant={isVideoEnabled ? "outline" : "destructive"}
            size="lg"
            onClick={toggleVideo}
            className={`h-12 w-12 rounded-full ${
              isVideoEnabled 
                ? 'border-gray-600 hover:bg-gray-800' 
                : 'bg-red-600 hover:bg-red-700'
            }`}
            data-testid="toggle-video-button"
          >
            {isVideoEnabled ? <Video size={20} /> : <VideoOff size={20} />}
          </Button>

          {/* Screen Share */}
          <Button
            variant={isScreenSharing ? "default" : "outline"}
            size="lg"
            onClick={toggleScreenShare}
            className={`h-12 w-12 rounded-full ${
              isScreenSharing 
                ? 'bg-blue-600 hover:bg-blue-700' 
                : 'border-gray-600 hover:bg-gray-800'
            }`}
            data-testid="toggle-screenshare-button"
          >
            {isScreenSharing ? <MonitorOff size={20} /> : <Monitor size={20} />}
          </Button>

          {/* End Call */}
          <Button
            variant="destructive"
            size="lg"
            onClick={endCall}
            className="h-12 w-12 rounded-full bg-red-600 hover:bg-red-700"
            data-testid="end-call-button"
          >
            <PhoneOff size={20} />
          </Button>
        </div>

        {/* Call Info */}
        <div className="mt-4 text-center">
          <p className="text-sm text-gray-400">
            {isScreenSharing && "🔗 Partage d'écran actif"}
          </p>
        </div>
      </div>
    </div>
  );
};

export default VideoCall;