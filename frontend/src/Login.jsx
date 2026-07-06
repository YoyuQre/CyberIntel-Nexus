import React, { useState } from 'react';
import { GoogleLogin, GoogleOAuthProvider } from '@react-oauth/google';
import { Shield, Lock, Mail } from 'lucide-react';

const API_BASE_URL = 'http://localhost:8080';
const GOOGLE_CLIENT_ID = '1088892229667-sdenmpdjkb3dor67rfu80lgvlr08bs7c.apps.googleusercontent.com';

export default function Login({ onLoginSuccess }) {
  const [isRegistering, setIsRegistering] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleGoogleSuccess = (credentialResponse) => {
    // Return credential response directly as the token
    onLoginSuccess(credentialResponse.credential);
  };

  const handleGoogleError = () => {
    setError('Google login failed.');
  };

  const handleLocalSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    const endpoint = isRegistering ? '/auth/register' : '/auth/login';
    
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.detail || 'Authentication failed');
      }
      
      if (isRegistering) {
        setIsRegistering(false);
        setError('Registration successful. Please log in.');
        setPassword('');
      } else {
        onLoginSuccess(data.access_token);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 flex flex-col items-center justify-center p-6">
      <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-8">
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 bg-blue-500/10 rounded-full flex items-center justify-center mb-4 border border-blue-500/20">
            <Shield className="w-8 h-8 text-blue-400" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">CyberIntel Nexus</h1>
          <p className="text-sm text-slate-400 mt-1">Authenticate to access SOC Dashboard</p>
        </div>

        {error && (
          <div className={`mb-6 p-3 rounded-lg border text-sm ${
            error.includes('successful') 
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
              : 'bg-red-500/10 border-red-500/20 text-red-400'
          }`}>
            {error}
          </div>
        )}

        <form onSubmit={handleLocalSubmit} className="space-y-4 mb-6">
          <div className="space-y-1">
            <label className="text-sm font-medium text-slate-300">Email</label>
            <div className="relative">
              <Mail className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
              <input 
                type="email" 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-white focus:outline-none focus:border-blue-500 transition-colors"
                placeholder="operator@soc.local"
                required
              />
            </div>
          </div>
          
          <div className="space-y-1">
            <label className="text-sm font-medium text-slate-300">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
              <input 
                type="password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-white focus:outline-none focus:border-blue-500 transition-colors"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          <button 
            type="submit" 
            className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 px-4 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900"
          >
            {isRegistering ? 'Register Account' : 'Sign In'}
          </button>
        </form>

        <div className="flex items-center justify-between mb-6">
          <div className="h-px bg-slate-800 flex-1"></div>
          <span className="px-4 text-xs font-medium text-slate-500 uppercase tracking-wider">OR</span>
          <div className="h-px bg-slate-800 flex-1"></div>
        </div>

        <div className="flex justify-center mb-6">
          <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
            <GoogleLogin
              onSuccess={handleGoogleSuccess}
              onError={handleGoogleError}
              useOneTap
              theme="filled_black"
              shape="rectangular"
            />
          </GoogleOAuthProvider>
        </div>
        
        <div className="text-center">
          <button 
            type="button"
            onClick={() => setIsRegistering(!isRegistering)}
            className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
          >
            {isRegistering ? 'Already have an account? Sign in' : 'Need an account? Register'}
          </button>
        </div>
      </div>
    </div>
  );
}
