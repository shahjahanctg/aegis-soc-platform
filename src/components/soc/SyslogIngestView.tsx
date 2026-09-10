import React, { useState } from 'react';
import { 
  Server, 
  Terminal, 
  Network, 
  ShieldCheck, 
  Copy, 
  Check, 
  Radio, 
  Play, 
  Cpu, 
  HardDrive, 
  Layers, 
  AlertCircle,
  FileCode,
  Laptop
} from 'lucide-react';
import { api } from '../../services/api';

interface DeviceGuide {
  id: string;
  name: string;
  category: 'Network Device' | 'Server Agent' | 'Collector Bridge';
  icon: any;
  summary: string;
  instructions: string[];
  codeSnippet: string;
  language: string;
}

export const SyslogIngestView: React.FC = () => {
  const [collectorIp, setCollectorIp] = useState<string>(() => {
    if (typeof window !== 'undefined' && window.location.hostname && window.location.hostname !== 'localhost') {
      return window.location.hostname;
    }
    return '10.0.0.50';
  });

  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [testResult, setTestResult] = useState<string>('');
  const [activeTab, setActiveTab] = useState<string>('cisco');

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleSendTestEvent = async () => {
    setTestStatus('testing');
    setTestResult('');
    try {
      const payload = {
        severity: 'high',
        title: 'Syslog Test: Unauthorized Admin Access Attempt',
        description: `Synthetic authentication failure log emitted from switch port via Syslog to collector at ${collectorIp}:514`,
        source: 'Core-Switch-01 (Syslog 514)',
        sourceIp: '10.0.4.88',
        destIp: collectorIp,
        asset: 'SW-CORE-AGGREGATION',
        mitreTechnique: 'T1078 - Valid Accounts',
        mitreTactic: 'Initial Access',
      };

      const data = await api.ingestTelemetry(payload);

      if (data.status === 'accepted') {
        setTestStatus('success');
        setTestResult(`Event ingested successfully! Created Alert ID: ${data.alertId || 'ALT-LOG'}. Check the Alerts & Triage tab to view it.`);
      } else {
        setTestStatus('error');
        setTestResult(`Failed to ingest event: ${JSON.stringify(data)}`);
      }
    } catch (err: any) {
      setTestStatus('error');
      setTestResult(`Error reaching endpoint: ${err.message}`);
    }
  };

  const guides: DeviceGuide[] = [
    {
      id: 'cisco',
      name: 'Cisco Switches & Routers',
      category: 'Network Device',
      icon: Network,
      summary: 'Standard Syslog configuration for Cisco Catalyst, Nexus, and IOS-XE routers/switches.',
      instructions: [
        'Connect to your Cisco switch or router console via SSH / Telnet.',
        'Enter configuration mode with `configure terminal`.',
        'Add the logging host pointing to your collector server on UDP port 514.',
        'Save running-config to startup-config.'
      ],
      codeSnippet: `configure terminal
logging on
logging host ${collectorIp}
logging trap warnings
logging facility local4
logging source-interface GigabitEthernet0/1
exit
write memory`,
      language: 'cisco',
    },
    {
      id: 'fortigate',
      name: 'Fortinet FortiGate Firewall',
      category: 'Network Device',
      icon: ShieldCheck,
      summary: 'Forward Internet & DMZ traffic logs, blocked malware, and IPS events to AegisSOC.',
      instructions: [
        'Via CLI: Connect via SSH or open the FortiGate Web Console CLI.',
        'Set syslog destination server to your collector IP with UDP port 514.',
        'Via Web UI: Go to Log & Report → Log Settings → Remote Syslog Server → Enable & enter server IP.'
      ],
      codeSnippet: `config log syslogd setting
    set status enable
    set server "${collectorIp}"
    set mode udp
    set port 514
    set facility local7
    set format default
end`,
      language: 'bash',
    },
    {
      id: 'paloalto',
      name: 'Palo Alto Networks NGFW',
      category: 'Network Device',
      icon: ShieldCheck,
      summary: 'Stream threat prevention, URL filtering, and traffic logs from PAN-OS.',
      instructions: [
        'Open PAN-OS Web GUI → Navigate to Device → Server Profiles → Syslog.',
        'Click "Add", enter profile name `AegisSOC-Syslog`.',
        'Click "Add" under servers: Name = `AegisCollector`, Syslog Server = `' + collectorIp + '`, Port = `514`, Facility = `LOG_USER`.',
        'Navigate to Objects → Log Forwarding → Add profile attaching the syslog server to all security policies and commit.'
      ],
      codeSnippet: `# PAN-OS CLI equivalent:
set shared log-settings syslog AegisSOC-Syslog server AegisCollector server ${collectorIp}
set shared log-settings syslog AegisSOC-Syslog server AegisCollector port 514
set shared log-settings syslog AegisSOC-Syslog server AegisCollector facility LOG_USER
commit`,
      language: 'bash',
    },
    {
      id: 'linux',
      name: 'Linux Servers (Ubuntu / Debian / RHEL)',
      category: 'Server Agent',
      icon: Terminal,
      summary: 'Collect SSH authentications, sudo failures, and system logs using native pre-installed rsyslog.',
      instructions: [
        'No new software required: rsyslog comes pre-installed on standard Linux distributions.',
        'Add a forwarder configuration file in `/etc/rsyslog.d/50-aegis-forward.conf`.',
        'Restart rsyslog to immediately start streaming logs to the collector.'
      ],
      codeSnippet: `# 1. Create forwarder rule pointing to collector:
echo "*.* @${collectorIp}:514" | sudo tee /etc/rsyslog.d/50-aegis-forward.conf

# 2. Restart rsyslog service:
sudo systemctl restart rsyslog

# 3. Verify logging connectivity:
logger -p auth.warn "AegisSOC Linux Agent Test Log from $(hostname)"`,
      language: 'bash',
    },
    {
      id: 'windows',
      name: 'Windows Servers (Event Log / NXLog)',
      category: 'Server Agent',
      icon: Laptop,
      summary: 'Stream Windows Event IDs (Logon 4624, Privilege 4672, Kerberos 4768) to port 514.',
      instructions: [
        'Download and install NXLog Community Edition or Winlogbeat (.msi) on your Windows Server.',
        'Open `C:\\Program Files\\nxlog\\conf\\nxlog.conf` in Administrator Notepad.',
        'Configure the Input for EventLog and Output for UDP 514, then restart the NXLog service.'
      ],
      codeSnippet: `# C:\\Program Files\\nxlog\\conf\\nxlog.conf
define ROOT C:\\Program Files\\nxlog

Moduledir %ROOT%\\modules
CacheDir %ROOT%\\data
Pidfile %ROOT%\\data\\nxlog.pid
SpoolDir %ROOT%\\data

<Extension _syslog>
    Module  xm_syslog
</Extension>

<Input in_eventlog>
    Module  im_msvistalog
    # Collects Security, System, and Application logs
</Input>

<Output out_syslog>
    Module  om_udp
    Host    ${collectorIp}
    Port    514
    Exec    to_syslog_ietf();
</Output>

<Route 1>
    Path    in_eventlog => out_syslog
</Route>`,
      language: 'apacheconf',
    },
    {
      id: 'bridge',
      name: 'Server Host: rsyslog Port 514 Bridge',
      category: 'Collector Bridge',
      icon: Server,
      summary: 'Configure your AegisSOC host server to receive Port 514 Syslog and pipe into the application.',
      instructions: [
        'On the server hosting AegisSOC, open `/etc/rsyslog.conf` and enable port 514 UDP/TCP reception.',
        'Install the HTTP output module `rsyslog-omhttp` (e.g., `sudo apt-get install rsyslog-omhttp`).',
        'Add the bridge rule in `/etc/rsyslog.d/99-aegis-bridge.conf` and restart rsyslog.'
      ],
      codeSnippet: `# Step 1: In /etc/rsyslog.conf, ensure UDP/TCP listeners are active:
module(load="imudp")
input(type="imudp" port="514")
module(load="imtcp")
input(type="imtcp" port="514")

# Step 2: In /etc/rsyslog.d/99-aegis-bridge.conf, bridge to AegisSOC:
module(load="omhttp")

template(name="AegisJSON" type="string" 
  string="{\\"source\\":\\"%HOSTNAME%\\",\\"title\\":\\"%syslogtag%\\",\\"description\\":\\"%msg:::json%\\",\\"severity\\":\\"%syslogseverity-text%\\",\\"asset\\":\\"%HOSTNAME%\\"}")

action(
  type="omhttp"
  server="127.0.0.1"
  serverport="3000"
  restpath="api/telemetry/ingest"
  template="AegisJSON"
  action.resumeRetryCount="-1"
)

# Step 3: Restart service:
# sudo systemctl restart rsyslog`,
      language: 'bash',
    },
    {
      id: 'docker',
      name: 'Docker / Container: Vector Syslog Collector',
      category: 'Collector Bridge',
      icon: Layers,
      summary: 'Run a high-performance, containerized Syslog 514 collector alongside AegisSOC.',
      instructions: [
        'Save `docker-compose.yml` and `vector.yaml` in your server directory.',
        'Run `docker compose up -d` to spin up a high-performance UDP/TCP 514 listener that converts Syslog to AegisSOC JSON.'
      ],
      codeSnippet: `# docker-compose.yml
version: '3.8'
services:
  syslog-collector:
    image: timberio/vector:0.38.X-alpine
    container_name: aegis-syslog-collector
    restart: always
    ports:
      - "514:514/udp"
      - "514:514/tcp"
    volumes:
      - ./vector.yaml:/etc/vector/vector.yaml:ro

---
# vector.yaml
sources:
  network_syslog:
    type: "syslog"
    address: "0.0.0.0:514"
    mode: "udp"

transforms:
  format_soc:
    type: "remap"
    inputs: ["network_syslog"]
    source: |
      .source = .appname || "Syslog Device"
      .sourceIp = to_string(.host) || "10.0.0.1"
      .title = "Syslog: " + to_string(.appname || "Alert")
      .description = to_string(.message)
      .severity = if .severity == "emergency" || .severity == "critical" { "critical" } else if .severity == "error" { "high" } else { "medium" }

sinks:
  aegis_api:
    type: "http"
    inputs: ["format_soc"]
    uri: "http://127.0.0.1:3000/api/telemetry/ingest"
    method: "post"
    encoding:
      codec: "json"`,
      language: 'yaml',
    },
  ];

  const currentGuide = guides.find(g => g.id === activeTab) || guides[0];

  return (
    <div className="space-y-6">
      {/* Top Banner / Ingestion Overview */}
      <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-xl relative overflow-hidden">
        <div className="absolute -top-16 -right-16 w-64 h-64 bg-cyan-900/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1 max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-800/60 bg-cyan-950/40 px-3 py-1 text-xs font-mono text-cyan-400">
              <Radio className="h-3.5 w-3.5 animate-pulse text-cyan-400" />
              <span>Enterprise Ingestion &amp; Syslog Gateway</span>
            </div>
            <h2 className="text-xl font-bold font-mono text-gray-100 uppercase tracking-tight">
              Network Device &amp; Server Agent Collector
            </h2>
            <p className="text-xs text-gray-400 leading-relaxed">
              Connect core switches, routers, firewalls (Cisco, Fortinet, Palo Alto) via native <strong className="text-cyan-300">Syslog Port 514</strong>, and stream server telemetry from Windows/Linux without writing custom client scripts.
            </p>
          </div>

          {/* Quick interactive IP customizer */}
          <div className="rounded-xl border border-gray-800 bg-gray-900/80 p-3.5 min-w-[280px]">
            <label className="text-[11px] font-mono text-gray-400 block mb-1.5 uppercase font-medium">
              Your Collector Server IP / Hostname
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={collectorIp}
                onChange={(e) => setCollectorIp(e.target.value)}
                placeholder="10.0.0.50"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-1.5 text-xs font-mono text-cyan-300 focus:border-cyan-500 focus:outline-none"
              />
              <span className="rounded bg-cyan-950 border border-cyan-800 px-2 py-1 text-[10px] font-mono text-cyan-400 whitespace-nowrap">
                PORT 514
              </span>
            </div>
            <p className="text-[10px] font-mono text-gray-500 mt-1.5">
              Updates all CLI scripts below in real time.
            </p>
          </div>
        </div>

        {/* Visual Architecture Flow Diagram */}
        <div className="mt-6 pt-6 border-t border-gray-800/80 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3 space-y-1.5">
            <div className="flex items-center justify-between text-gray-300 font-semibold">
              <span className="flex items-center gap-1.5">
                <Network className="h-4 w-4 text-cyan-400" />
                1. Devices &amp; Servers
              </span>
              <span className="text-[10px] text-cyan-400 bg-cyan-950/80 px-1.5 py-0.5 rounded border border-cyan-800/60">Source</span>
            </div>
            <p className="text-[11px] text-gray-400">
              Cisco, Fortinet, Palo Alto, Linux (rsyslog), Windows (NXLog/Winlogbeat).
            </p>
            <div className="text-[10px] text-gray-500 font-mono">Output: UDP/TCP 514</div>
          </div>

          <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3 space-y-1.5">
            <div className="flex items-center justify-between text-gray-300 font-semibold">
              <span className="flex items-center gap-1.5">
                <Server className="h-4 w-4 text-purple-400" />
                2. Port 514 Bridge
              </span>
              <span className="text-[10px] text-purple-400 bg-purple-950/80 px-1.5 py-0.5 rounded border border-purple-800/60">Collector</span>
            </div>
            <p className="text-[11px] text-gray-400">
              Host rsyslog or Vector listening on <span className="text-purple-300 font-bold">{collectorIp}:514</span>.
            </p>
            <div className="text-[10px] text-gray-500 font-mono">Relay: HTTP JSON POST</div>
          </div>

          <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3 space-y-1.5">
            <div className="flex items-center justify-between text-gray-300 font-semibold">
              <span className="flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                3. AegisSOC Dashboard
              </span>
              <span className="text-[10px] text-emerald-400 bg-emerald-950/80 px-1.5 py-0.5 rounded border border-emerald-800/60">Live UI</span>
            </div>
            <p className="text-[11px] text-gray-400">
              Ingests into Alerts Feed, DFIR microsecond timeline &amp; Gemini AI Triage.
            </p>
            <div className="text-[10px] text-emerald-400 font-mono">Target: /api/telemetry/ingest</div>
          </div>
        </div>
      </div>

      {/* Main Grid: Device Switcher & Instructions */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Device Selection Sidebar */}
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-3 space-y-1.5">
          <div className="px-2 py-1 text-[11px] font-mono text-gray-500 uppercase font-bold tracking-wider">
            Device &amp; Agent Profiles
          </div>

          {guides.map((g) => {
            const Icon = g.icon;
            const isSelected = activeTab === g.id;
            return (
              <button
                key={g.id}
                onClick={() => setActiveTab(g.id)}
                className={`w-full text-left rounded-lg p-2.5 transition-all flex items-start gap-2.5 ${
                  isSelected
                    ? 'bg-cyan-950/60 border border-cyan-800 text-gray-100 shadow-sm'
                    : 'text-gray-400 hover:bg-gray-900 hover:text-gray-200 border border-transparent'
                }`}
              >
                <div className={`p-1.5 rounded-md mt-0.5 ${isSelected ? 'bg-cyan-900/50 text-cyan-300' : 'bg-gray-900 text-gray-400'}`}>
                  <Icon className="h-4 w-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-mono font-semibold truncate">{g.name}</div>
                  <div className="text-[10px] text-gray-500 font-mono">{g.category}</div>
                </div>
              </button>
            );
          })}

          {/* Test Pipeline Action Card */}
          <div className="mt-4 pt-3 border-t border-gray-800">
            <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 space-y-2">
              <div className="text-xs font-mono font-bold text-gray-200 flex items-center gap-1.5">
                <Play className="h-3.5 w-3.5 text-cyan-400" />
                Pipeline Test Utility
              </div>
              <p className="text-[11px] text-gray-400">
                Simulate an incoming Syslog event directly to verify ingestion into AegisSOC.
              </p>
              <button
                onClick={handleSendTestEvent}
                disabled={testStatus === 'testing'}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-gray-950 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors disabled:opacity-50"
              >
                {testStatus === 'testing' ? (
                  <>
                    <Radio className="h-3.5 w-3.5 animate-spin" /> Ingesting...
                  </>
                ) : (
                  <>
                    <Terminal className="h-3.5 w-3.5" /> Send Test Syslog
                  </>
                )}
              </button>

              {testResult && (
                <div className={`rounded p-2 text-[10px] font-mono ${
                  testStatus === 'success' 
                    ? 'bg-emerald-950/70 border border-emerald-800 text-emerald-300' 
                    : 'bg-rose-950/70 border border-rose-800 text-rose-300'
                }`}>
                  {testResult}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Selected Guide Details */}
        <div className="lg:col-span-3 space-y-4">
          <div className="rounded-xl border border-gray-800 bg-gray-950 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-gray-800/80 pb-3">
              <div>
                <div className="inline-flex items-center gap-1.5 text-[10px] font-mono text-cyan-400 uppercase font-bold">
                  <span>{currentGuide.category}</span>
                  <span>•</span>
                  <span>Syslog Port 514 UDP/TCP</span>
                </div>
                <h3 className="text-lg font-mono font-bold text-gray-100">{currentGuide.name}</h3>
                <p className="text-xs text-gray-400 mt-0.5">{currentGuide.summary}</p>
              </div>

              <button
                onClick={() => copyToClipboard(currentGuide.codeSnippet, currentGuide.id)}
                className="inline-flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-900 hover:bg-gray-800 px-3 py-1.5 text-xs font-mono text-gray-200 transition-colors self-start"
              >
                {copiedId === currentGuide.id ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5 text-gray-400" />
                    <span>Copy Config</span>
                  </>
                )}
              </button>
            </div>

            {/* Implementation Steps */}
            <div className="space-y-2">
              <div className="text-xs font-mono font-bold text-gray-300 uppercase">
                Step-by-Step Setup
              </div>
              <ul className="space-y-1.5 text-xs text-gray-400">
                {currentGuide.instructions.map((step, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="rounded bg-gray-800 text-cyan-400 font-mono text-[10px] px-1.5 py-0.2 mt-0.5 font-bold">
                      {idx + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Code / Configuration Snippet Box */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono text-gray-400">
                <span className="flex items-center gap-1.5">
                  <FileCode className="h-3.5 w-3.5 text-cyan-400" />
                  Configuration / CLI Snippet
                </span>
                <span className="text-[10px] text-gray-500">Destination: {collectorIp}:514</span>
              </div>
              <div className="relative rounded-lg border border-gray-800 bg-gray-900/90 p-4 font-mono text-xs overflow-x-auto text-cyan-300 leading-relaxed selection:bg-cyan-900">
                <pre className="whitespace-pre">{currentGuide.codeSnippet}</pre>
              </div>
            </div>
          </div>

          {/* Quick Ingestion Endpoint Reference */}
          <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
            <h4 className="text-xs font-mono font-bold text-gray-300 uppercase mb-2 flex items-center gap-1.5">
              <HardDrive className="h-3.5 w-3.5 text-cyan-400" />
              Direct REST Ingestion API Reference
            </h4>
            <p className="text-xs text-gray-400 mb-3">
              If forwarding via HTTP or custom integration scripts, send raw or normalized logs directly to the platform ingress:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              <div className="rounded border border-gray-800 bg-gray-900/60 p-2.5 space-y-1">
                <div className="text-[11px] text-emerald-400 font-bold">POST /api/telemetry/ingest</div>
                <div className="text-[10px] text-gray-400">
                  Accepts single log objects or JSON arrays. Promotes medium/high/critical logs into live alerts and the DFIR timeline.
                </div>
              </div>
              <div className="rounded border border-gray-800 bg-gray-900/60 p-2.5 space-y-1">
                <div className="text-[11px] text-purple-400 font-bold">GET /api/events/stream (SSE)</div>
                <div className="text-[10px] text-gray-400">
                  Real-time Server-Sent Events stream emitting <code className="text-purple-300">alert:new</code> events for connected SOC dashboards.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
