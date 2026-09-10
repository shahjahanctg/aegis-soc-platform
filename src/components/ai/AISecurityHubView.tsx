import React, { useState } from 'react';
import { 
  Bot, 
  Send, 
  MailSearch, 
  ShieldCheck, 
  Sparkles, 
  Terminal, 
  AlertTriangle, 
  Copy, 
  Check, 
  FileCode,
  ArrowRight
} from 'lucide-react';
import { api } from '../../services/api';
import { UserSession } from '../../types';

interface AISecurityHubViewProps {
  user: UserSession;
}

interface ChatMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  timestamp: string;
}

export const AISecurityHubView: React.FC<AISecurityHubViewProps> = ({ user }) => {
  const [activeSubTab, setActiveSubTab] = useState<'copilot' | 'phishing' | 'playbook'>('copilot');

  // Copilot State
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: '1',
      sender: 'ai',
      text: `Greetings Analyst ${user.name}. I am Aegis AI, your SOC Copilot powered by Gemini 3.8 Flash. Ask me to correlate alerts, parse IOCs, draft containment commands, or explain MITRE techniques.`,
      timestamp: 'Just now',
    },
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);

  // Phishing Analyzer State
  const [emailRaw, setEmailRaw] = useState(
    `Received: from mail-attacker.xyz (unknown [198.51.100.44])\nFrom: "IT Support Helpdesk" <support@microsofft-sec-update.com>\nSubject: CRITICAL: Immediate Password Expiration Action Required\nDate: Mon, 09 Sep 2026 09:15:00 UTC\n\nDear Corporate User,\nYour Office 365 Enterprise credentials will expire in 2 hours. Click below to retain access:\nhttps://microsofft-sec-update.com/login?auth=token994\nFailure to verify will lead to immediate mailbox termination.`
  );
  const [phishingAnalysis, setPhishingAnalysis] = useState<any>(null);
  const [analyzingEmail, setAnalyzingEmail] = useState(false);

  // Playbook Generator State
  const [threatInput, setThreatInput] = useState('Cobalt Strike C2 Beaconing via DNS TXT');
  const [playbookResult, setPlaybookResult] = useState<string | null>(null);
  const [playbookLoading, setPlaybookLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Send message to Gemini SOC Copilot
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || chatLoading) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      sender: 'user',
      text: chatInput.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages(prev => [...prev, userMsg]);
    setChatInput('');
    setChatLoading(true);

    try {
      const res = await api.askAICopilot(userMsg.text, {
        analystName: user.name,
        recentContext: 'Active SOC Alert ALT-1092 Cobalt Strike Beaconing',
      });

      const aiMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'ai',
        text: res.reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages(prev => [...prev, aiMsg]);
    } catch (err) {
      console.error(err);
      setMessages(prev => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          sender: 'ai',
          text: 'Error contacting AI Copilot. Please verify network connectivity.',
          timestamp: 'Just now',
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  // Run Phishing Header & Body Analysis
  const handleAnalyzeEmail = async () => {
    if (!emailRaw.trim() || analyzingEmail) return;
    setAnalyzingEmail(true);
    try {
      const result = await api.analyzePhishingEmail(emailRaw);
      setPhishingAnalysis(result);
    } catch (err) {
      console.error(err);
    } finally {
      setAnalyzingEmail(false);
    }
  };

  // Generate Incident Response Playbook
  const handleGeneratePlaybook = async () => {
    if (!threatInput.trim() || playbookLoading) return;
    setPlaybookLoading(true);
    try {
      const prompt = `Generate a rigorous, step-by-step SOC Incident Response Containment Playbook for threat: "${threatInput}". Include: 1. Identification & Triaging, 2. Endpoint Isolation commands (PowerShell/Linux bash), 3. Network Egress Block rules, 4. Eradication & Post-Incident verification.`;
      const res = await api.askAICopilot(prompt, { mode: 'playbook' });
      setPlaybookResult(res.reply);
    } catch (err) {
      console.error(err);
    } finally {
      setPlaybookLoading(false);
    }
  };

  const handleCopyPlaybook = () => {
    if (!playbookResult) return;
    navigator.clipboard.writeText(playbookResult);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div>
          <h2 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide flex items-center gap-2">
            <Bot className="h-5 w-5 text-purple-400" />
            AI Security Operations &amp; Threat Engineering Hub
          </h2>
          <p className="text-xs text-gray-400">
            Automated tier-1 triage copilot, deep email header forensics, and autonomous containment playbook generation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-gray-800 bg-gray-900 p-0.5 text-xs font-mono">
            <button
              onClick={() => setActiveSubTab('copilot')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                activeSubTab === 'copilot' ? 'bg-purple-950 text-purple-300 border border-purple-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              SOC Copilot Chat
            </button>
            <button
              onClick={() => setActiveSubTab('phishing')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                activeSubTab === 'phishing' ? 'bg-purple-950 text-purple-300 border border-purple-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Email Threat Analyzer
            </button>
            <button
              onClick={() => setActiveSubTab('playbook')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                activeSubTab === 'playbook' ? 'bg-purple-950 text-purple-300 border border-purple-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Playbook Generator
            </button>
          </div>
        </div>
      </div>

      {/* Subtab 1: SOC Copilot Chat */}
      {activeSubTab === 'copilot' && (
        <div className="flex flex-col h-[560px] rounded-2xl border border-purple-950/80 bg-gray-950 shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-gray-800 bg-gray-900/60 px-5 py-3 font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-bold text-gray-200">Aegis AI Copilot v3.8</span>
              <span className="rounded bg-purple-950 px-2 py-0.5 text-[10px] text-purple-300 border border-purple-800">
                Gemini 3.8 Flash Active
              </span>
            </div>
            <span className="text-gray-500">Zero-Retention Confidential Channel</span>
          </div>

          {/* Message List */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {messages.map(msg => (
              <div
                key={msg.id}
                className={`flex gap-3 max-w-[85%] ${msg.sender === 'user' ? 'ml-auto flex-row-reverse' : 'mr-auto'}`}
              >
                <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
                  msg.sender === 'user' ? 'bg-cyan-600 text-gray-950 font-bold font-mono text-xs' : 'bg-purple-950 text-purple-400 border border-purple-800'
                }`}>
                  {msg.sender === 'user' ? user.name[0] : <Bot className="h-4 w-4" />}
                </div>

                <div className={`rounded-xl p-3.5 text-xs leading-relaxed ${
                  msg.sender === 'user'
                    ? 'bg-cyan-950/80 border border-cyan-800 text-cyan-100 font-sans'
                    : 'bg-gray-900 border border-gray-800 text-gray-200 font-mono whitespace-pre-wrap'
                }`}>
                  <p>{msg.text}</p>
                  <span className="mt-1 block text-[10px] text-gray-500 text-right">{msg.timestamp}</span>
                </div>
              </div>
            ))}

            {chatLoading && (
              <div className="flex items-center gap-2 text-xs font-mono text-purple-400 bg-purple-950/30 border border-purple-900/40 p-3 rounded-xl max-w-sm">
                <Sparkles className="h-4 w-4 animate-spin text-purple-400" />
                <span>Correlating SIEM telemetry and threat feeds...</span>
              </div>
            )}
          </div>

          {/* Chat Input */}
          <form onSubmit={handleSendMessage} className="border-t border-gray-800 bg-gray-900/60 p-4 flex gap-2">
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              placeholder="Ask Copilot (e.g., 'How do I contain a Kerberoasting attack on DC-01?')..."
              className="flex-1 rounded-xl border border-gray-800 bg-gray-950 px-4 py-2.5 text-xs text-gray-200 placeholder-gray-500 focus:border-purple-500 focus:outline-none font-mono"
            />
            <button
              type="submit"
              disabled={chatLoading || !chatInput.trim()}
              className="flex items-center gap-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 px-5 py-2.5 text-xs font-mono font-bold text-white transition-all cursor-pointer shadow-[0_0_15px_rgba(168,85,247,0.3)]"
            >
              <Send className="h-3.5 w-3.5" />
              Send
            </button>
          </form>
        </div>
      )}

      {/* Subtab 2: Phishing Header & Body Analyzer */}
      {activeSubTab === 'phishing' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 shadow-lg space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-mono text-sm font-bold text-gray-100 uppercase flex items-center gap-2">
                <MailSearch className="h-4 w-4 text-purple-400" />
                Raw Email Header &amp; Body Payload
              </h3>
              <span className="text-[10px] font-mono text-gray-500">RFC 822 / MIME</span>
            </div>

            <textarea
              rows={12}
              value={emailRaw}
              onChange={(e) => setEmailRaw(e.target.value)}
              className="w-full rounded-xl border border-gray-800 bg-gray-900 p-3 text-xs font-mono text-gray-300 placeholder-gray-600 focus:border-purple-500 focus:outline-none"
            />

            <button
              onClick={handleAnalyzeEmail}
              disabled={analyzingEmail}
              className="w-full flex items-center justify-center gap-2 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 py-2.5 text-xs font-mono font-bold text-white transition-all shadow-[0_0_15px_rgba(168,85,247,0.3)] cursor-pointer"
            >
              <Sparkles className="h-4 w-4" />
              {analyzingEmail ? 'Dissecting MIME & Headers...' : 'Run AI Deep Threat Analysis'}
            </button>
          </div>

          {/* Analysis Results View */}
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 shadow-lg">
            <h3 className="font-mono text-sm font-bold text-gray-100 uppercase mb-3 flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-400" />
              AI Forensic Verdict &amp; Scoring
            </h3>

            {phishingAnalysis ? (
              <div className="space-y-4 font-mono text-xs">
                {/* Risk Score Pill */}
                <div className="flex items-center justify-between p-3 rounded-xl bg-gray-900 border border-gray-800">
                  <span className="text-gray-400 uppercase">Calculated Risk Score</span>
                  <div className="flex items-center gap-2">
                    <span className={`text-lg font-bold ${
                      phishingAnalysis.riskScore > 75 ? 'text-rose-400' : phishingAnalysis.riskScore > 40 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {phishingAnalysis.riskScore}/100
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-rose-950 text-rose-300 border border-rose-800">
                      {phishingAnalysis.verdict}
                    </span>
                  </div>
                </div>

                {/* Email Authentication Checks */}
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="p-2.5 rounded-lg bg-gray-900 border border-gray-800">
                    <span className="text-[10px] text-gray-500 block">SPF Check</span>
                    <span className={`font-bold ${phishingAnalysis.spfCheck === 'FAIL' ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {phishingAnalysis.spfCheck}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-gray-900 border border-gray-800">
                    <span className="text-[10px] text-gray-500 block">DKIM Signature</span>
                    <span className={`font-bold ${phishingAnalysis.dkimCheck === 'FAIL' ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {phishingAnalysis.dkimCheck}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-gray-900 border border-gray-800">
                    <span className="text-[10px] text-gray-500 block">DMARC Policy</span>
                    <span className={`font-bold ${phishingAnalysis.dmarcCheck === 'REJECT' ? 'text-rose-400' : 'text-amber-400'}`}>
                      {phishingAnalysis.dmarcCheck}
                    </span>
                  </div>
                </div>

                {/* Detected Indicators list */}
                <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-3">
                  <span className="text-gray-400 block mb-1 uppercase text-[10px]">Suspicious Indicators Identified</span>
                  <ul className="list-disc list-inside space-y-1 text-gray-300">
                    {phishingAnalysis.indicators?.map((ind: string, idx: number) => (
                      <li key={idx}>{ind}</li>
                    ))}
                  </ul>
                </div>

                {/* Recommended Response */}
                <div className="rounded-xl border border-rose-900/40 bg-rose-950/20 p-3 text-rose-300">
                  <span className="font-bold block mb-1">SOAR AUTOMATION ACTION:</span>
                  <p className="text-[11px] text-gray-300 font-sans">
                    {phishingAnalysis.recommendedAction}
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-gray-500 font-mono text-xs">
                Paste an email header or suspicious lure message and click &quot;Run AI Deep Threat Analysis&quot; to evaluate authenticity.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Subtab 3: Playbook Generator */}
      {activeSubTab === 'playbook' && (
        <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-lg space-y-4 font-mono text-xs">
          <div>
            <h3 className="text-sm font-bold text-gray-100 uppercase mb-1 flex items-center gap-2">
              <FileCode className="h-4 w-4 text-purple-400" />
              Autonomous Incident Response Playbook Synthesizer
            </h3>
            <p className="text-gray-400">
              Generate battle-tested containment scripts and SOC runbooks tailored to specific adversary techniques.
            </p>
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={threatInput}
              onChange={(e) => setThreatInput(e.target.value)}
              placeholder="e.g. Kerberoasting against Domain Controller or Ransomware on File Share..."
              className="flex-1 rounded-xl border border-gray-800 bg-gray-900 px-4 py-2 text-xs text-gray-200 placeholder-gray-600 focus:border-purple-500 focus:outline-none"
            />
            <button
              onClick={handleGeneratePlaybook}
              disabled={playbookLoading}
              className="flex items-center gap-2 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 px-5 py-2 text-xs font-bold text-white transition-all cursor-pointer shadow-[0_0_15px_rgba(168,85,247,0.3)]"
            >
              <Sparkles className="h-4 w-4" />
              {playbookLoading ? 'Generating...' : 'Synthesize Playbook'}
            </button>
          </div>

          {playbookResult && (
            <div className="relative mt-4 rounded-xl border border-gray-800 bg-gray-900/80 p-4">
              <button
                onClick={handleCopyPlaybook}
                className="absolute top-4 right-4 flex items-center gap-1 rounded bg-gray-800 px-2.5 py-1 text-[10px] text-gray-300 hover:bg-gray-700 transition-all cursor-pointer"
              >
                {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                {copied ? 'Copied' : 'Copy'}
              </button>

              <pre className="whitespace-pre-wrap text-gray-200 text-xs font-mono leading-relaxed max-h-[380px] overflow-y-auto">
                {playbookResult}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
