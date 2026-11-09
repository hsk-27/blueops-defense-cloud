import React, { useState } from 'react';
import { Shield, Lock, User as UserIcon, ShieldAlert, ArrowRight, CheckCircle2, KeyRound } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('AdminPass123!');
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

  const selectPersona = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="min-h-screen bg-[#090a0f] flex flex-col items-center justify-center p-4 selection:bg-rose-900 selection:text-white relative">
      {/* Subtle Grid Lines */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#151926_1px,transparent_1px),linear-gradient(to_bottom,#151926_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-30 pointer-events-none"></div>

      <div className="w-full max-w-md bg-[#11141d] border border-[#212738] rounded-2xl shadow-2xl p-8 relative z-10 space-y-6">
        
        {/* Enterprise Brand Header */}
        <div className="flex items-center space-x-3.5 border-b border-[#212738] pb-5">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-700 to-indigo-800 border border-blue-500/40 flex items-center justify-center text-white shadow-md shadow-blue-900/20">
            <Shield className="w-5 h-5 text-blue-200" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-base font-bold tracking-widest text-white font-mono">BLUEOPS</h1>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-blue-950 text-blue-300 border border-blue-800 rounded">DEFENSE CLOUD</span>
            </div>
            <p className="text-xs text-slate-400 font-mono">Enterprise SecOps & Threat Intelligence</p>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-red-950/60 border border-red-800/80 rounded-lg text-xs text-red-300 flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5 font-semibold">Operator Username</label>
            <div className="relative">
              <UserIcon className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full bg-[#0c0e15] border border-[#212738] rounded-lg pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono transition"
                placeholder="operator.id"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5 font-semibold">Security Token / Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-[#0c0e15] border border-[#212738] rounded-lg pl-9 pr-3 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono transition"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 px-4 rounded-lg text-xs transition shadow-md flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            <span>{loading ? 'Authenticating with IdP...' : 'Authenticate to SecOps Session'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Enterprise Persona Selector */}
        <div className="pt-4 border-t border-[#212738] space-y-2.5">
          <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
            <span>SEEDED EVALUATION PERSONAS</span>
            <span className="text-slate-400">Click to fill</span>
          </div>
          <div className="grid grid-cols-3 gap-2 text-xs font-mono">
            <button
              type="button"
              onClick={() => selectPersona('admin', 'AdminPass123!')}
              className={`p-2 rounded-lg border text-left transition ${
                username === 'admin'
                  ? 'bg-blue-950/60 border-blue-600 text-blue-300'
                  : 'bg-[#0c0e15] border-[#212738] text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <div className="font-bold text-[11px]">SEC-ADMIN</div>
              <div className="text-[9px] text-slate-500">Full Access</div>
            </button>
            <button
              type="button"
              onClick={() => selectPersona('analyst', 'AnalystPass123!')}
              className={`p-2 rounded-lg border text-left transition ${
                username === 'analyst'
                  ? 'bg-blue-950/60 border-blue-600 text-blue-300'
                  : 'bg-[#0c0e15] border-[#212738] text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <div className="font-bold text-[11px]">ANALYST</div>
              <div className="text-[9px] text-slate-500">IR & Response</div>
            </button>
            <button
              type="button"
              onClick={() => selectPersona('viewer', 'ViewerPass123!')}
              className={`p-2 rounded-lg border text-left transition ${
                username === 'viewer'
                  ? 'bg-blue-950/60 border-blue-600 text-blue-300'
                  : 'bg-[#0c0e15] border-[#212738] text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <div className="font-bold text-[11px]">AUDITOR</div>
              <div className="text-[9px] text-slate-500">Read-Only</div>
            </button>
          </div>
        </div>

      </div>

      {/* Enterprise Security Compliance Footer */}
      <footer className="mt-8 text-center space-y-1.5 text-[11px] font-mono text-slate-400 relative z-10">
        <div className="flex items-center justify-center space-x-3 text-slate-400">
          <span className="flex items-center space-x-1">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
            <span>SOC 2 Type II Certified</span>
          </span>
          <span>•</span>
          <span>FIPS 140-3 Cryptographic Boundary</span>
          <span>•</span>
          <span>NIST SP 800-61r2 Compliant</span>
        </div>
        <p className="text-slate-400 text-xs font-semibold">© 2026 BlueOps Technologies Inc. All rights reserved.</p>
      </footer>
    </div>
  );
};
