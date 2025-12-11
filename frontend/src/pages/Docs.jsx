import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  Book,
  Code,
  Terminal,
  Settings,
  Zap,
  Database,
  Lock,
  ArrowLeft,
  ChevronRight,
  Search,
  Copy,
  Check,
  ExternalLink,
} from "lucide-react";

const Docs = () => {
  const [activeSection, setActiveSection] = useState("getting-started");
  const [copiedCode, setCopiedCode] = useState(null);

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const sections = [
    { id: "getting-started", title: "Getting Started", icon: Zap },
    { id: "installation", title: "Installation", icon: Terminal },
    { id: "configuration", title: "Configuration", icon: Settings },
    { id: "api-reference", title: "API Reference", icon: Code },
    { id: "agents", title: "AI Agents", icon: Shield },
    { id: "ml-model", title: "ML Model", icon: Database },
    { id: "security", title: "Security", icon: Lock },
  ];

  const CodeBlock = ({ code, language, id }) => (
    <div className="relative group">
      <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800">
          <span className="text-xs text-slate-400">{language}</span>
          <button
            onClick={() => copyToClipboard(code, id)}
            className="text-slate-400 hover:text-emerald-400 transition-colors"
          >
            {copiedCode === id ? (
              <Check className="w-4 h-4" />
            ) : (
              <Copy className="w-4 h-4" />
            )}
          </button>
        </div>
        <pre className="p-4 overflow-x-auto">
          <code className="text-sm text-slate-300">{code}</code>
        </pre>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-900/95 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <Link
                to="/"
                className="flex items-center space-x-2 text-slate-400 hover:text-emerald-400 transition-colors"
              >
                <ArrowLeft className="w-5 h-5" />
                <span>Back</span>
              </Link>
              <div className="h-6 w-px bg-slate-700"></div>
              <div className="flex items-center space-x-2">
                <Book className="w-5 h-5 text-emerald-400" />
                <span className="text-white font-semibold">Documentation</span>
              </div>
            </div>
            <div className="relative">
              <Search className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search docs..."
                className="bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 w-64"
              />
            </div>
          </div>
        </div>
      </nav>

      <div className="pt-16 flex">
        {/* Sidebar */}
        <aside className="fixed left-0 top-16 bottom-0 w-64 bg-slate-900/50 border-r border-slate-800 overflow-y-auto">
          <nav className="p-4 space-y-1">
            {sections.map((section) => (
              <button
                key={section.id}
                onClick={() => setActiveSection(section.id)}
                className={`w-full flex items-center space-x-3 px-4 py-2.5 rounded-lg transition-all ${
                  activeSection === section.id
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                }`}
              >
                <section.icon className="w-5 h-5" />
                <span className="text-sm font-medium">{section.title}</span>
              </button>
            ))}
          </nav>
        </aside>

        {/* Content */}
        <main className="ml-64 flex-1 p-8 max-w-4xl">
          {activeSection === "getting-started" && (
            <div className="space-y-8">
              <div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  Getting Started
                </h1>
                <p className="text-slate-400 leading-relaxed">
                  Welcome to ACDS (Autonomous Cyber Defense System)! This guide
                  will help you get up and running with our AI-powered phishing
                  detection platform.
                </p>
              </div>

              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Quick Start
                </h2>
                <ol className="space-y-4">
                  <li className="flex items-start space-x-3">
                    <span className="w-6 h-6 bg-emerald-500 rounded-full flex items-center justify-center text-white text-sm font-bold shrink-0">
                      1
                    </span>
                    <div>
                      <p className="text-white font-medium">
                        Clone the repository
                      </p>
                      <CodeBlock
                        code="git clone https://github.com/acds/acds-fyp.git"
                        language="bash"
                        id="clone"
                      />
                    </div>
                  </li>
                  <li className="flex items-start space-x-3">
                    <span className="w-6 h-6 bg-emerald-500 rounded-full flex items-center justify-center text-white text-sm font-bold shrink-0">
                      2
                    </span>
                    <div>
                      <p className="text-white font-medium">
                        Start with Docker Compose
                      </p>
                      <CodeBlock
                        code="docker-compose up -d"
                        language="bash"
                        id="docker"
                      />
                    </div>
                  </li>
                  <li className="flex items-start space-x-3">
                    <span className="w-6 h-6 bg-emerald-500 rounded-full flex items-center justify-center text-white text-sm font-bold shrink-0">
                      3
                    </span>
                    <div>
                      <p className="text-white font-medium">
                        Access the dashboard
                      </p>
                      <p className="text-slate-400 text-sm mt-1">
                        Open{" "}
                        <code className="text-emerald-400 bg-slate-800 px-2 py-0.5 rounded">
                          http://localhost:3000
                        </code>{" "}
                        in your browser
                      </p>
                    </div>
                  </li>
                </ol>
              </div>

              <div>
                <h2 className="text-xl font-semibold text-white mb-4">
                  System Architecture
                </h2>
                <p className="text-slate-400 mb-4">
                  ACDS consists of four main components working together:
                </p>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    {
                      title: "Detection Agent",
                      desc: "ML-powered phishing detection",
                    },
                    { title: "Intel Agent", desc: "IOC extraction & analysis" },
                    {
                      title: "Response Agent",
                      desc: "Automated threat response",
                    },
                    { title: "Alert Agent", desc: "Notification management" },
                  ].map((agent, i) => (
                    <div
                      key={i}
                      className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
                    >
                      <h3 className="text-white font-medium mb-1">
                        {agent.title}
                      </h3>
                      <p className="text-slate-400 text-sm">{agent.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeSection === "api-reference" && (
            <div className="space-y-8">
              <div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  API Reference
                </h1>
                <p className="text-slate-400 leading-relaxed">
                  Complete reference for the ACDS REST API endpoints.
                </p>
              </div>

              <div className="space-y-6">
                {/* Scan Endpoint */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="flex items-center space-x-3 px-6 py-4 border-b border-slate-800">
                    <span className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-bold rounded">
                      POST
                    </span>
                    <code className="text-white">/api/v1/scan</code>
                  </div>
                  <div className="p-6">
                    <p className="text-slate-400 mb-4">
                      Analyze an email for phishing threats.
                    </p>
                    <h4 className="text-white font-medium mb-2">
                      Request Body
                    </h4>
                    <CodeBlock
                      code={`{
  "content": "Email content to analyze...",
  "metadata": {
    "sender": "sender@example.com",
    "subject": "Email subject"
  }
}`}
                      language="json"
                      id="scan-req"
                    />
                    <h4 className="text-white font-medium mt-4 mb-2">
                      Response
                    </h4>
                    <CodeBlock
                      code={`{
  "success": true,
  "result": {
    "is_phishing": true,
    "confidence": 0.95,
    "risk_level": "high",
    "indicators": ["suspicious_url", "urgency_keywords"]
  }
}`}
                      language="json"
                      id="scan-res"
                    />
                  </div>
                </div>

                {/* Stats Endpoint */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="flex items-center space-x-3 px-6 py-4 border-b border-slate-800">
                    <span className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs font-bold rounded">
                      GET
                    </span>
                    <code className="text-white">/api/v1/stats</code>
                  </div>
                  <div className="p-6">
                    <p className="text-slate-400 mb-4">
                      Get system statistics and metrics.
                    </p>
                    <CodeBlock
                      code={`{
  "success": true,
  "result": {
    "total_scanned": 12847,
    "threats_detected": 247,
    "accuracy": 0.959
  }
}`}
                      language="json"
                      id="stats-res"
                    />
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSection === "installation" && (
            <div className="space-y-8">
              <div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  Installation
                </h1>
                <p className="text-slate-400 leading-relaxed">
                  Multiple ways to install and run ACDS.
                </p>
              </div>

              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4 flex items-center space-x-2">
                  <span>Docker Installation</span>
                  <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 text-xs rounded">
                    Recommended
                  </span>
                </h2>
                <CodeBlock
                  code={`# Clone repository
git clone https://github.com/acds/acds-fyp.git
cd acds-fyp

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f`}
                  language="bash"
                  id="docker-install"
                />
              </div>

              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Manual Installation
                </h2>
                <CodeBlock
                  code={`# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend (new terminal)
cd frontend
npm install
npm run dev`}
                  language="bash"
                  id="manual-install"
                />
              </div>
            </div>
          )}

          {activeSection === "configuration" && (
            <div className="space-y-8">
              <div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  Configuration
                </h1>
                <p className="text-slate-400 leading-relaxed">
                  Configure ACDS to match your environment and requirements.
                </p>
              </div>

              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Environment Variables
                </h2>
                <div className="space-y-4">
                  {[
                    {
                      name: "API_HOST",
                      default: "0.0.0.0",
                      desc: "API server host",
                    },
                    {
                      name: "API_PORT",
                      default: "8000",
                      desc: "API server port",
                    },
                    {
                      name: "LOG_LEVEL",
                      default: "INFO",
                      desc: "Logging level",
                    },
                    {
                      name: "MODEL_PATH",
                      default: "models/",
                      desc: "ML model directory",
                    },
                  ].map((env, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between py-3 border-b border-slate-800 last:border-0"
                    >
                      <div>
                        <code className="text-emerald-400">{env.name}</code>
                        <p className="text-slate-400 text-sm mt-1">
                          {env.desc}
                        </p>
                      </div>
                      <code className="text-slate-500 text-sm">
                        {env.default}
                      </code>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeSection === "agents" && (
            <div className="space-y-8">
              <div>
                <h1 className="text-3xl font-bold text-white mb-4">
                  AI Agents
                </h1>
                <p className="text-slate-400 leading-relaxed">
                  ACDS uses a multi-agent architecture for comprehensive threat
                  detection and response.
                </p>
              </div>

              <div className="grid gap-6">
                {[
                  {
                    name: "Detection Agent",
                    desc: "Uses TF-IDF + Logistic Regression ML model to classify emails as phishing or legitimate.",
                    methods: ["analyze()", "get_confidence()"],
                  },
                  {
                    name: "Intel Agent",
                    desc: "Extracts IOCs including URLs, domains, IP addresses, and suspicious keywords.",
                    methods: ["analyze()", "extract_iocs()"],
                  },
                  {
                    name: "Response Agent",
                    desc: "Determines and executes appropriate response actions based on threat severity.",
                    methods: ["analyze()", "execute_action()"],
                  },
                  {
                    name: "Alert Agent",
                    desc: "Manages notifications and alert routing based on severity levels.",
                    methods: ["analyze()", "send_alert()"],
                  },
                ].map((agent, i) => (
                  <div
                    key={i}
                    className="bg-slate-900/50 border border-slate-800 rounded-xl p-6"
                  >
                    <h3 className="text-xl font-semibold text-white mb-2">
                      {agent.name}
                    </h3>
                    <p className="text-slate-400 mb-4">{agent.desc}</p>
                    <div className="flex flex-wrap gap-2">
                      {agent.methods.map((method, j) => (
                        <code
                          key={j}
                          className="px-3 py-1 bg-slate-800 text-emerald-400 text-sm rounded"
                        >
                          {method}
                        </code>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeSection === "ml-model" && (
            <div className="space-y-8">
              <div>
                <h1 className="text-3xl font-bold text-white mb-4">ML Model</h1>
                <p className="text-slate-400 leading-relaxed">
                  Technical details about our phishing detection model.
                </p>
              </div>

              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Model Specifications
                </h2>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { label: "Algorithm", value: "Logistic Regression" },
                    { label: "Vectorizer", value: "TF-IDF" },
                    { label: "Accuracy", value: "95.90%" },
                    { label: "Training Samples", value: "18,650" },
                    { label: "Max Features", value: "5,000" },
                    { label: "N-gram Range", value: "(1, 2)" },
                  ].map((spec, i) => (
                    <div key={i} className="bg-slate-800/50 rounded-lg p-4">
                      <p className="text-slate-400 text-sm">{spec.label}</p>
                      <p className="text-white font-semibold">{spec.value}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeSection === "security" && (
            <div className="space-y-8">
              <div>
                <h1 className="text-3xl font-bold text-white mb-4">Security</h1>
                <p className="text-slate-400 leading-relaxed">
                  Security best practices and configurations for ACDS.
                </p>
              </div>

              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">
                  Security Features
                </h2>
                <ul className="space-y-3">
                  {[
                    "JWT-based authentication",
                    "Role-based access control (RBAC)",
                    "API rate limiting",
                    "Input sanitization",
                    "Audit logging",
                    "CORS configuration",
                  ].map((feature, i) => (
                    <li key={i} className="flex items-center space-x-3">
                      <Check className="w-5 h-5 text-emerald-400" />
                      <span className="text-slate-300">{feature}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Docs;
