import React, { useState } from 'react';
import { Flame, Lock, User as UserIcon, ShieldAlert, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('Admin@BlueOps2026!');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const data = await api.login({ username, password });
      login(data.accessToken, {
        id: 1,
        username: data.username,
        email: data.email,
        fullName: data.fullName,
        role: data.role as any,
        enabled: true,
      });
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const setPreset = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="min-h-screen bg-[#070a10] flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[#111726] border border-[#1e293b] rounded-xl shadow-2xl p-8 relative overflow-hidden">
        {/* Glow backdrop */}
        <div className="absolute top-0 right-0 -mr-16 -mt-16 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>

        {/* Brand */}
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2.5 bg-blue-600/20 border border-blue-500/40 rounded-lg text-blue-400">
            <Flame className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-slate-100 flex items-center space-x-2">
              <span>BLUEOPS</span>
              <span className="text-xs font-mono px-2 py-0.5 bg-blue-900/60 text-blue-300 border border-blue-700/50 rounded">SOC</span>
            </h1>
            <p className="text-xs text-slate-400">Threat Detection & Automated Incident Response</p>
          </div>
        </div>

        {error && (
          <div className="mb-5 p-3 bg-red-950/60 border border-red-800/80 rounded-lg text-xs text-red-300 flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Username</label>
            <div className="relative">
              <UserIcon className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full bg-[#0a0d14] border border-[#1e293b] rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-[#0a0d14] border border-[#1e293b] rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2.5 px-4 rounded-lg text-sm transition-colors flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            <span>{loading ? 'Authenticating...' : 'Sign In to SOC'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Quick Role Selectors for testing */}
        <div className="mt-6 pt-5 border-t border-[#1e293b]">
          <p className="text-[11px] text-slate-400 mb-2 font-mono uppercase tracking-wider">Quick Lab Roles:</p>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => setPreset('admin', 'Admin@BlueOps2026!')}
              className="text-xs bg-[#161f30] hover:bg-[#1e293b] text-slate-200 py-1.5 px-2 rounded border border-[#1e293b] text-center"
            >
              ADMIN
            </button>
            <button
              type="button"
              onClick={() => setPreset('analyst', 'Analyst@BlueOps2026!')}
              className="text-xs bg-[#161f30] hover:bg-[#1e293b] text-slate-200 py-1.5 px-2 rounded border border-[#1e293b] text-center"
            >
              ANALYST
            </button>
            <button
              type="button"
              onClick={() => setPreset('viewer', 'Viewer@BlueOps2026!')}
              className="text-xs bg-[#161f30] hover:bg-[#1e293b] text-slate-200 py-1.5 px-2 rounded border border-[#1e293b] text-center"
            >
              VIEWER
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
