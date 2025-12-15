import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Shield,
  Zap,
  Brain,
  Lock,
  ChevronRight,
  Mail,
  AlertTriangle,
  CheckCircle,
  BarChart3,
  Eye,
  Menu,
  X,
  ArrowRight,
  Github,
  Twitter,
  Linkedin,
} from "lucide-react";

const Landing = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    setLoaded(true);
  }, []);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const features = [
    {
      icon: Brain,
      title: "AI-Powered Detection",
      description:
        "Advanced ML model with 95.9% accuracy using TF-IDF and Logistic Regression for real-time phishing detection.",
    },
    {
      icon: Zap,
      title: "Instant Analysis",
      description:
        "Process emails in milliseconds with our optimized pipeline. Get immediate threat assessments and risk scores.",
    },
    {
      icon: Eye,
      title: "Explainable AI",
      description:
        "Understand why emails are flagged with detailed IOC extraction, keyword analysis, and evidence trails.",
    },
    {
      icon: Shield,
      title: "Automated Response",
      description:
        "Intelligent orchestration system that automatically quarantines threats and notifies administrators.",
    },
    {
      icon: BarChart3,
      title: "Real-time Dashboard",
      description:
        "Monitor your security posture with live statistics, threat trends, and incident tracking.",
    },
    {
      icon: Lock,
      title: "Enterprise Security",
      description:
        "Role-based access control, audit logging, and compliance-ready security infrastructure.",
    },
  ];

  const stats = [
    { value: "95.9%", label: "Detection Accuracy" },
    { value: "<100ms", label: "Analysis Time" },
    { value: "18K+", label: "Training Samples" },
    { value: "24/7", label: "Monitoring" },
  ];

  return (
    <div
      className={`min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950 transition-opacity duration-500 ${
        loaded ? "opacity-100" : "opacity-0"
      }`}
    >
      {/* Navigation */}
      <nav
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled
            ? "bg-slate-900/95 backdrop-blur-md shadow-lg shadow-emerald-500/5"
            : "bg-transparent"
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <div className="flex items-center space-x-2">
              <div className="w-10 h-10 bg-gradient-to-br from-emerald-400 to-emerald-600 rounded-xl flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-transparent">
                ACDS
              </span>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center space-x-8">
              <a
                href="#features"
                className="text-slate-300 hover:text-emerald-400 transition-colors"
              >
                Features
              </a>
              <a
                href="#how-it-works"
                className="text-slate-300 hover:text-emerald-400 transition-colors"
              >
                How It Works
              </a>
              <Link
                to="/docs"
                className="text-slate-300 hover:text-emerald-400 transition-colors"
              >
                Docs
              </Link>
              <Link
                to="/pricing"
                className="text-slate-300 hover:text-emerald-400 transition-colors"
              >
                Pricing
              </Link>
              <Link
                to="/blog"
                className="text-slate-300 hover:text-emerald-400 transition-colors"
              >
                Blog
              </Link>
            </div>

            {/* Auth Buttons */}
            <div className="hidden md:flex items-center space-x-4">
              <Link
                to="/login"
                className="text-slate-300 hover:text-emerald-400 transition-colors px-4 py-2"
              >
                Sign In
              </Link>
              <Link
                to="/login"
                className="bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 text-white px-5 py-2 rounded-lg font-medium transition-all duration-200 shadow-lg shadow-emerald-500/25"
              >
                Get Started
              </Link>
            </div>

            {/* Mobile Menu Button */}
            <button
              className="md:hidden text-slate-300"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
              {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {isMenuOpen && (
          <div className="md:hidden bg-slate-900/95 backdrop-blur-md border-t border-slate-800">
            <div className="px-4 py-4 space-y-3">
              <a
                href="#features"
                className="block text-slate-300 hover:text-emerald-400 py-2"
              >
                Features
              </a>
              <a
                href="#how-it-works"
                className="block text-slate-300 hover:text-emerald-400 py-2"
              >
                How It Works
              </a>
              <Link
                to="/docs"
                className="block text-slate-300 hover:text-emerald-400 py-2"
              >
                Docs
              </Link>
              <Link
                to="/pricing"
                className="block text-slate-300 hover:text-emerald-400 py-2"
              >
                Pricing
              </Link>
              <Link
                to="/blog"
                className="block text-slate-300 hover:text-emerald-400 py-2"
              >
                Blog
              </Link>
              <div className="pt-4 border-t border-slate-800 space-y-3">
                <Link
                  to="/login"
                  className="block text-center text-slate-300 hover:text-emerald-400 py-2"
                >
                  Sign In
                </Link>
                <Link
                  to="/login"
                  className="block text-center bg-gradient-to-r from-emerald-500 to-emerald-600 text-white py-2 rounded-lg font-medium"
                >
                  Get Started
                </Link>
              </div>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4 sm:px-6 lg:px-8 relative overflow-hidden">
        {/* Background Effects */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-96 h-96 bg-emerald-500/20 rounded-full blur-3xl"></div>
          <div className="absolute top-60 -left-40 w-96 h-96 bg-emerald-600/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-full h-px bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent"></div>
        </div>

        <div className="max-w-7xl mx-auto relative">
          <div className="text-center max-w-4xl mx-auto">
            {/* Badge */}
            <div className="inline-flex items-center space-x-2 bg-emerald-500/10 border border-emerald-500/20 rounded-full px-4 py-1.5 mb-8">
              <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
              <span className="text-emerald-400 text-sm font-medium">
                AI-Powered Cyber Defense System
              </span>
            </div>

            {/* Headline */}
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-white mb-6 leading-tight">
              Protect Your Organization from{" "}
              <span className="bg-gradient-to-r from-emerald-400 via-emerald-300 to-teal-400 bg-clip-text text-transparent">
                Digital Attacks
              </span>
            </h1>

            {/* Subheadline */}
            <p className="text-lg sm:text-xl text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
              ACDS uses advanced machine learning to detect, analyze, and
              respond to phishing threats in real-time. Secure your emails with
              95.9% accuracy.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
              <button
                onClick={() => navigate("/login")}
                className="group w-full sm:w-auto bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 text-white px-8 py-3.5 rounded-xl font-semibold text-lg transition-all duration-200 shadow-xl shadow-emerald-500/25 flex items-center justify-center space-x-2"
              >
                <span>Start Free Trial</span>
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </button>
              <a
                href="#how-it-works"
                className="w-full sm:w-auto bg-slate-800/50 hover:bg-slate-800 text-slate-300 hover:text-white px-8 py-3.5 rounded-xl font-semibold text-lg transition-all duration-200 border border-slate-700 hover:border-slate-600 flex items-center justify-center space-x-2"
              >
                <span>See How It Works</span>
              </a>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8 max-w-3xl mx-auto">
              {stats.map((stat, index) => (
                <div key={index} className="text-center">
                  <div className="text-3xl sm:text-4xl font-bold bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-transparent mb-1">
                    {stat.value}
                  </div>
                  <div className="text-sm text-slate-500">{stat.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Dashboard Preview */}
          <div className="mt-20 relative">
            <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-transparent to-transparent z-10 pointer-events-none"></div>
            <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800 rounded-2xl p-2 shadow-2xl shadow-emerald-500/5">
              <div className="bg-slate-950 rounded-xl overflow-hidden">
                {/* Mock Dashboard Header */}
                <div className="bg-slate-900 border-b border-slate-800 px-6 py-4 flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="flex space-x-2">
                      <div className="w-3 h-3 rounded-full bg-red-500"></div>
                      <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                      <div className="w-3 h-3 rounded-full bg-green-500"></div>
                    </div>
                    <span className="text-slate-500 text-sm">
                      ACDS Dashboard
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></div>
                    <span className="text-emerald-400 text-xs">Live</span>
                  </div>
                </div>

                {/* Mock Dashboard Content */}
                <div className="p-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Stat Cards */}
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-slate-400 text-sm">
                        Threats Detected
                      </span>
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">247</div>
                    <div className="text-emerald-400 text-xs mt-1">
                      +12% from last week
                    </div>
                  </div>
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-slate-400 text-sm">
                        Emails Scanned
                      </span>
                      <Mail className="w-5 h-5 text-blue-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">12,847</div>
                    <div className="text-emerald-400 text-xs mt-1">
                      +5% from last week
                    </div>
                  </div>
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-slate-400 text-sm">
                        Blocked Attacks
                      </span>
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">98.2%</div>
                    <div className="text-slate-400 text-xs mt-1">
                      Success rate
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
              Enterprise-Grade Security Features
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              Comprehensive protection powered by cutting-edge AI technology and
              security best practices.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => (
              <div
                key={index}
                className="group bg-slate-900/50 hover:bg-slate-900/80 border border-slate-800 hover:border-emerald-500/30 rounded-2xl p-6 transition-all duration-300"
              >
                <div className="w-12 h-12 bg-gradient-to-br from-emerald-500/20 to-emerald-600/20 rounded-xl flex items-center justify-center mb-4 group-hover:from-emerald-500/30 group-hover:to-emerald-600/30 transition-all duration-300">
                  <feature.icon className="w-6 h-6 text-emerald-400" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-2">
                  {feature.title}
                </h3>
                <p className="text-slate-400 leading-relaxed">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section
        id="how-it-works"
        className="py-20 px-4 sm:px-6 lg:px-8 bg-slate-900/30"
      >
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
              How ACDS Works
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              Our intelligent pipeline processes emails through multiple stages
              for comprehensive threat detection.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            {[
              {
                step: "01",
                title: "Email Ingestion",
                description:
                  "Emails are securely received and preprocessed for analysis.",
                icon: Mail,
              },
              {
                step: "02",
                title: "AI Detection",
                description:
                  "ML model analyzes content using TF-IDF vectorization.",
                icon: Brain,
              },
              {
                step: "03",
                title: "IOC Extraction",
                description:
                  "URLs, domains, and suspicious patterns are identified.",
                icon: Eye,
              },
              {
                step: "04",
                title: "Auto Response",
                description:
                  "Threats are quarantined and administrators notified.",
                icon: Shield,
              },
            ].map((item, index) => (
              <div key={index} className="relative">
                {index < 3 && (
                  <div className="hidden md:block absolute top-12 left-full w-full h-px bg-gradient-to-r from-emerald-500/50 to-transparent z-0"></div>
                )}
                <div className="relative z-10 text-center">
                  <div className="w-24 h-24 mx-auto bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 rounded-2xl flex items-center justify-center mb-4 relative">
                    <item.icon className="w-10 h-10 text-emerald-400" />
                    <div className="absolute -top-2 -right-2 w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center text-white text-sm font-bold">
                      {item.step}
                    </div>
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">
                    {item.title}
                  </h3>
                  <p className="text-slate-400 text-sm">{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <div className="bg-gradient-to-r from-emerald-600/20 to-teal-600/20 border border-emerald-500/30 rounded-3xl p-8 sm:p-12 text-center relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-r from-emerald-500/5 to-teal-500/5"></div>
            <div className="relative">
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
                Ready to Secure Your Organization?
              </h2>
              <p className="text-slate-300 mb-8 max-w-xl mx-auto">
                Start protecting your emails from phishing attacks today. No
                credit card required for the free trial.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <button
                  onClick={() => navigate("/login")}
                  className="w-full sm:w-auto bg-white hover:bg-slate-100 text-slate-900 px-8 py-3.5 rounded-xl font-semibold text-lg transition-all duration-200 shadow-xl flex items-center justify-center space-x-2"
                >
                  <span>Get Started Free</span>
                  <ChevronRight className="w-5 h-5" />
                </button>
                <Link
                  to="/docs"
                  className="w-full sm:w-auto text-emerald-400 hover:text-emerald-300 px-8 py-3.5 font-semibold text-lg transition-colors flex items-center justify-center space-x-2"
                >
                  <span>Read Documentation</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-4 sm:px-6 lg:px-8 border-t border-slate-800">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
            {/* Brand */}
            <div className="md:col-span-1">
              <div className="flex items-center space-x-2 mb-4">
                <div className="w-10 h-10 bg-gradient-to-br from-emerald-400 to-emerald-600 rounded-xl flex items-center justify-center">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <span className="text-xl font-bold bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-transparent">
                  ACDS
                </span>
              </div>
              <p className="text-slate-400 text-sm">
                Autonomous Cyber Defense System. Protecting organizations from
                phishing threats with AI.
              </p>
            </div>

            {/* Links */}
            <div>
              <h4 className="text-white font-semibold mb-4">Product</h4>
              <ul className="space-y-2">
                <li>
                  <a
                    href="#features"
                    className="text-slate-400 hover:text-emerald-400 text-sm transition-colors"
                  >
                    Features
                  </a>
                </li>
                <li>
                  <Link
                    to="/pricing"
                    className="text-slate-400 hover:text-emerald-400 text-sm transition-colors"
                  >
                    Pricing
                  </Link>
                </li>
                <li>
                  <Link
                    to="/docs"
                    className="text-slate-400 hover:text-emerald-400 text-sm transition-colors"
                  >
                    Documentation
                  </Link>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="text-white font-semibold mb-4">Company</h4>
              <ul className="space-y-2">
                <li>
                  <Link
                    to="/blog"
                    className="text-slate-400 hover:text-emerald-400 text-sm transition-colors"
                  >
                    Blog
                  </Link>
                </li>
                <li>
                  <a
                    href="#"
                    className="text-slate-400 hover:text-emerald-400 text-sm transition-colors"
                  >
                    About Us
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="text-slate-400 hover:text-emerald-400 text-sm transition-colors"
                  >
                    Contact
                  </a>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="text-white font-semibold mb-4">Legal</h4>
              <ul className="space-y-2">
                <li>
                  <a
                    href="#"
                    className="text-slate-400 hover:text-emerald-400 text-sm transition-colors"
                  >
                    Privacy Policy
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className="text-slate-400 hover:text-emerald-400 text-sm transition-colors"
                  >
                    Terms of Service
                  </a>
                </li>
              </ul>
            </div>
          </div>

          <div className="flex flex-col md:flex-row items-center justify-between pt-8 border-t border-slate-800">
            <p className="text-slate-500 text-sm mb-4 md:mb-0">
              © 2025 ACDS. All rights reserved.
            </p>
            <div className="flex items-center space-x-4">
              <a
                href="#"
                className="text-slate-400 hover:text-emerald-400 transition-colors"
              >
                <Github className="w-5 h-5" />
              </a>
              <a
                href="#"
                className="text-slate-400 hover:text-emerald-400 transition-colors"
              >
                <Twitter className="w-5 h-5" />
              </a>
              <a
                href="#"
                className="text-slate-400 hover:text-emerald-400 transition-colors"
              >
                <Linkedin className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
