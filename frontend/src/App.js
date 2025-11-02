import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import { Toaster } from 'sonner';
import './App.css';

// Pages
import LoginPage from './pages/LoginPage';
import ChatPage from './pages/ChatPage';
import LoadingPage from './pages/LoadingPage';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authChecked, setAuthChecked] = useState(false);

  // Check for session_id in URL fragment (Google OAuth callback)
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.hash.substring(1));
    const sessionId = urlParams.get('session_id');
    
    if (sessionId) {
      handleGoogleCallback(sessionId);
      return;
    }
    
    // Check existing session
    checkAuthStatus();
  }, []);

  const handleGoogleCallback = async (sessionId) => {
    try {
      setLoading(true);
      
      const response = await axios.post(`${API}/auth/google/callback`, {}, {
        headers: {
          'X-Session-ID': sessionId
        }
      });
      
      const { user: userData, token } = response.data;
      
      // Store token and set user
      localStorage.setItem('auth_token', token);
      setUser(userData);
      
      // Clear URL fragment
      window.history.replaceState({}, document.title, window.location.pathname);
      
      setAuthChecked(true);
      setLoading(false);
      
    } catch (error) {
      console.error('Erreur lors de l\'authentification Google:', error);
      setAuthChecked(true);
      setLoading(false);
    }
  };

  const checkAuthStatus = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      if (!token) {
        setAuthChecked(true);
        setLoading(false);
        return;
      }

      const response = await axios.get(`${API}/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      setUser(response.data);
    } catch (error) {
      console.error('Erreur de vérification d\'authentification:', error);
      localStorage.removeItem('auth_token');
    } finally {
      setAuthChecked(true);
      setLoading(false);
    }
  };

  const handleLogin = (userData, token) => {
    localStorage.setItem('auth_token', token);
    setUser(userData);
  };

  const handleLogout = async () => {
    try {
      const token = localStorage.getItem('auth_token');
      if (token) {
        await axios.post(`${API}/auth/logout`, {}, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
      }
    } catch (error) {
      console.error('Erreur lors de la déconnexion:', error);
    } finally {
      localStorage.removeItem('auth_token');
      setUser(null);
    }
  };

  if (loading || !authChecked) {
    return <LoadingPage />;
  }

  return (
    <div className="App">
      <Router>
        <Routes>
          <Route 
            path="/login" 
            element={
              user ? 
              <Navigate to="/chat" replace /> : 
              <LoginPage onLogin={handleLogin} />
            } 
          />
          <Route 
            path="/chat" 
            element={
              user ? 
              <ChatPage user={user} onLogout={handleLogout} /> : 
              <Navigate to="/login" replace />
            } 
          />
          <Route 
            path="/" 
            element={
              user ? 
              <Navigate to="/chat" replace /> : 
              <Navigate to="/login" replace />
            } 
          />
        </Routes>
      </Router>
      <Toaster position="top-right" richColors />
    </div>
  );
}

export default App;