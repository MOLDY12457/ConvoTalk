import React from 'react';

const LoadingPage = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-black to-gray-900">
      <div className="text-center space-y-6">
        {/* Logo/Brand */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold gradient-text">
            ConvoTalk
          </h1>
          <p className="text-gray-400 mt-2">Connexion en cours...</p>
        </div>
        
        {/* Loading Spinner */}
        <div className="flex justify-center">
          <div className="spinner"></div>
        </div>
        
        {/* Loading text */}
        <div className="space-y-2">
          <p className="text-gray-500 animate-pulse">
            Chargement de votre espace de chat...
          </p>
        </div>
        
        {/* Decorative elements */}
        <div className="absolute top-0 left-0 w-full h-full pointer-events-none overflow-hidden">
          <div className="absolute top-20 left-10 w-32 h-32 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse"></div>
          <div className="absolute top-40 right-10 w-32 h-32 bg-orange-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse" style={{ animationDelay: '1s' }}></div>
          <div className="absolute bottom-20 left-1/2 w-32 h-32 bg-pink-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse" style={{ animationDelay: '2s' }}></div>
        </div>
      </div>
    </div>
  );
};

export default LoadingPage;