import React, { useState } from 'react';
import { Eye, EyeOff, MessageCircle, Users, Zap, Shield } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { toast } from 'sonner';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const LoginPage = ({ onLogin }) => {
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  
  // Login form state
  const [loginData, setLoginData] = useState({
    email: '',
    password: ''
  });
  
  // Register form state
  const [registerData, setRegisterData] = useState({
    username: '',
    email: '',
    password: ''
  });

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await axios.post(`${API}/auth/login`, loginData);
      const { user, token } = response.data;
      
      toast.success('Connexion réussie!');
      onLogin(user, token);
      
    } catch (error) {
      console.error('Erreur de connexion:', error);
      toast.error(error.response?.data?.detail || 'Erreur de connexion');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await axios.post(`${API}/auth/register`, registerData);
      const { user, token } = response.data;
      
      toast.success('Compte créé avec succès!');
      onLogin(user, token);
      
    } catch (error) {
      console.error('Erreur d\'inscription:', error);
      toast.error(error.response?.data?.detail || 'Erreur lors de l\'inscription');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const redirectUrl = `${window.location.origin}/chat`;
      const response = await axios.get(`${API}/auth/google?redirect_url=${encodeURIComponent(redirectUrl)}`);
      window.location.href = response.data.auth_url;
    } catch (error) {
      console.error('Erreur Google OAuth:', error);
      toast.error('Erreur lors de la connexion Google');
    }
  };

  return (
    <div className="min-h-screen flex flex-col lg:flex-row">
      {/* Left Panel - Hero Section */}
      <div className="flex-1 relative overflow-hidden">
        <div 
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{
            backgroundImage: `url('https://images.unsplash.com/photo-1720962158858-5fb16991d2b8?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2000&q=80')`
          }}
        >
          <div className="absolute inset-0 bg-black/60"></div>
        </div>
        
        <div className="relative z-10 flex flex-col justify-center h-full px-12 lg:px-16 py-12">
          <div className="max-w-lg">
            <div className="mb-12">
              <h1 className="text-5xl lg:text-6xl font-bold text-white mb-6 leading-tight">
                Bienvenue sur{' '}
                <span className="gradient-text">ConvoTalk</span>
              </h1>
              <p className="text-xl text-gray-300 leading-relaxed">
                Une alternative moderne à Discord. Chattez, appelez, partagez votre écran avec vos amis en temps réel.
              </p>
            </div>
            
            {/* Features */}
            <div className="space-y-6">
              <div className="flex items-center space-x-4 text-white">
                <div className="w-12 h-12 rounded-full bg-purple-600/20 flex items-center justify-center">
                  <MessageCircle className="w-6 h-6 text-purple-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg">Chat en temps réel</h3>
                  <p className="text-gray-300">Messages instantanés avec support des GIFs</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-4 text-white">
                <div className="w-12 h-12 rounded-full bg-orange-600/20 flex items-center justify-center">
                  <Users className="w-6 h-6 text-orange-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg">Appels vidéo/audio</h3>
                  <p className="text-gray-300">Appelez vos amis en qualité HD</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-4 text-white">
                <div className="w-12 h-12 rounded-full bg-green-600/20 flex items-center justify-center">
                  <Zap className="w-6 h-6 text-green-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg">Partage d'écran</h3>
                  <p className="text-gray-300">Partagez votre écran facilement</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-4 text-white">
                <div className="w-12 h-12 rounded-full bg-blue-600/20 flex items-center justify-center">
                  <Shield className="w-6 h-6 text-blue-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg">Sécurisé et privé</h3>
                  <p className="text-gray-300">Vos conversations sont protégées</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Right Panel - Auth Forms */}
      <div className="flex-1 flex items-center justify-center p-8 lg:p-12 bg-gray-900/50">
        <div className="w-full max-w-md">
          <Card className="glass border-gray-700/50 shadow-2xl">
            <CardHeader className="text-center pb-6">
              <CardTitle className="text-2xl font-bold text-white">
                Rejoignez ConvoTalk
              </CardTitle>
              <CardDescription className="text-gray-400">
                Connectez-vous ou créez un compte pour commencer
              </CardDescription>
            </CardHeader>
            
            <CardContent>
              <Tabs defaultValue="login" className="space-y-6">
                <TabsList className="grid w-full grid-cols-2 bg-gray-800/50">
                  <TabsTrigger 
                    value="login" 
                    className="data-[state=active]:bg-purple-600 data-[state=active]:text-white"
                  >
                    Se connecter
                  </TabsTrigger>
                  <TabsTrigger 
                    value="register"
                    className="data-[state=active]:bg-purple-600 data-[state=active]:text-white"
                  >
                    S'inscrire
                  </TabsTrigger>
                </TabsList>
                
                {/* Login Tab */}
                <TabsContent value="login" className="space-y-4">
                  <form onSubmit={handleLogin} className="space-y-4">
                    <div className="space-y-2">
                      <Input
                        type="email"
                        placeholder="Email"
                        value={loginData.email}
                        onChange={(e) => setLoginData({...loginData, email: e.target.value})}
                        required
                        className="bg-gray-800/50 border-gray-600 text-white input-focus"
                        data-testid="login-email-input"
                      />
                    </div>
                    
                    <div className="space-y-2 relative">
                      <div className="relative">
                        <Input
                          type={showPassword ? "text" : "password"}
                          placeholder="Mot de passe"
                          value={loginData.password}
                          onChange={(e) => setLoginData({...loginData, password: e.target.value})}
                          required
                          className="bg-gray-800/50 border-gray-600 text-white pr-10 input-focus"
                          data-testid="login-password-input"
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"
                        >
                          {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                        </button>
                      </div>
                    </div>
                    
                    <Button
                      type="submit"
                      disabled={loading}
                      className="w-full bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 button-hover"
                      data-testid="login-submit-button"
                    >
                      {loading ? 'Connexion...' : 'Se connecter'}
                    </Button>
                  </form>
                </TabsContent>
                
                {/* Register Tab */}
                <TabsContent value="register" className="space-y-4">
                  <form onSubmit={handleRegister} className="space-y-4">
                    <div className="space-y-2">
                      <Input
                        type="text"
                        placeholder="Nom d'utilisateur"
                        value={registerData.username}
                        onChange={(e) => setRegisterData({...registerData, username: e.target.value})}
                        required
                        className="bg-gray-800/50 border-gray-600 text-white input-focus"
                        data-testid="register-username-input"
                      />
                    </div>
                    
                    <div className="space-y-2">
                      <Input
                        type="email"
                        placeholder="Email"
                        value={registerData.email}
                        onChange={(e) => setRegisterData({...registerData, email: e.target.value})}
                        required
                        className="bg-gray-800/50 border-gray-600 text-white input-focus"
                        data-testid="register-email-input"
                      />
                    </div>
                    
                    <div className="space-y-2 relative">
                      <div className="relative">
                        <Input
                          type={showPassword ? "text" : "password"}
                          placeholder="Mot de passe (min. 6 caractères)"
                          value={registerData.password}
                          onChange={(e) => setRegisterData({...registerData, password: e.target.value})}
                          required
                          minLength={6}
                          className="bg-gray-800/50 border-gray-600 text-white pr-10 input-focus"
                          data-testid="register-password-input"
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"
                        >
                          {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                        </button>
                      </div>
                    </div>
                    
                    <Button
                      type="submit"
                      disabled={loading}
                      className="w-full bg-gradient-to-r from-orange-600 to-orange-700 hover:from-orange-700 hover:to-orange-800 button-hover"
                      data-testid="register-submit-button"
                    >
                      {loading ? 'Création...' : 'Créer un compte'}
                    </Button>
                  </form>
                </TabsContent>
              </Tabs>
              
              {/* Google Login */}
              <div className="relative my-6">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t border-gray-600" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-gray-900 px-2 text-gray-400">Ou</span>
                </div>
              </div>
              
              <Button
                onClick={handleGoogleLogin}
                variant="outline"
                className="w-full bg-white/10 border-gray-600 text-white hover:bg-white/20 button-hover"
                data-testid="google-login-button"
              >
                <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                  <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                  <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Continuer avec Google
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;