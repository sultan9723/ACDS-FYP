import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  ArrowLeft,
  Calendar,
  Clock,
  User,
  ArrowRight,
  Search,
  Tag,
} from "lucide-react";

const Blog = () => {
  const [activeCategory, setActiveCategory] = useState("all");
  const [loaded, setLoaded] = useState(false);

  React.useEffect(() => {
    setLoaded(true);
  }, []);

  const categories = [
    { id: "all", label: "All Posts" },
    { id: "security", label: "Security" },
    { id: "ai-ml", label: "AI & ML" },
    { id: "product", label: "Product Updates" },
    { id: "guides", label: "Guides" },
  ];

  const blogPosts = [
    {
      id: 1,
      title: "Understanding Modern Phishing Attacks: A 2025 Guide",
      excerpt:
        "Explore the latest phishing techniques and how AI-powered detection systems are evolving to combat increasingly sophisticated threats.",
      category: "security",
      author: "Sarah Chen",
      date: "Jan 15, 2025",
      readTime: "8 min read",
      image: "🛡️",
      featured: true,
    },
    {
      id: 2,
      title: "How We Built Our 95.9% Accurate Phishing Detection Model",
      excerpt:
        "A deep dive into the machine learning architecture behind ACDS, including TF-IDF vectorization and model optimization techniques.",
      category: "ai-ml",
      author: "Dr. Michael Torres",
      date: "Jan 10, 2025",
      readTime: "12 min read",
      image: "🤖",
      featured: true,
    },
    {
      id: 3,
      title: "ACDS v2.0: New Features and Improvements",
      excerpt:
        "Announcing our latest release with enhanced detection capabilities, improved dashboard, and new API endpoints.",
      category: "product",
      author: "ACDS Team",
      date: "Jan 5, 2025",
      readTime: "5 min read",
      image: "🚀",
      featured: false,
    },
    {
      id: 4,
      title: "Setting Up ACDS for Enterprise: A Complete Guide",
      excerpt:
        "Step-by-step instructions for deploying ACDS in enterprise environments with custom configurations and integrations.",
      category: "guides",
      author: "Alex Kim",
      date: "Dec 28, 2024",
      readTime: "15 min read",
      image: "📚",
      featured: false,
    },
    {
      id: 5,
      title: "The Psychology of Phishing: Why People Still Fall for Scams",
      excerpt:
        "Understanding the human factors that make phishing effective and how technical solutions can help protect users.",
      category: "security",
      author: "Dr. Emily Watson",
      date: "Dec 20, 2024",
      readTime: "10 min read",
      image: "🧠",
      featured: false,
    },
    {
      id: 6,
      title: "Integrating ACDS with Your SIEM: Best Practices",
      excerpt:
        "Learn how to connect ACDS with popular SIEM platforms for comprehensive security monitoring and incident response.",
      category: "guides",
      author: "James Rodriguez",
      date: "Dec 15, 2024",
      readTime: "9 min read",
      image: "🔗",
      featured: false,
    },
    {
      id: 7,
      title: "The Future of Email Security: Predictions for 2025",
      excerpt:
        "Industry experts share their predictions for email security trends and emerging threats in the coming year.",
      category: "security",
      author: "Sarah Chen",
      date: "Dec 10, 2024",
      readTime: "7 min read",
      image: "🔮",
      featured: false,
    },
    {
      id: 8,
      title: "Understanding IOC Extraction in Threat Detection",
      excerpt:
        "A technical overview of how ACDS extracts and analyzes Indicators of Compromise from suspicious emails.",
      category: "ai-ml",
      author: "Dr. Michael Torres",
      date: "Dec 5, 2024",
      readTime: "11 min read",
      image: "🔍",
      featured: false,
    },
  ];

  const filteredPosts =
    activeCategory === "all"
      ? blogPosts
      : blogPosts.filter((post) => post.category === activeCategory);

  const featuredPosts = blogPosts.filter((post) => post.featured);

  return (
    <div
      className={`min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950 transition-opacity duration-500 ${
        loaded ? "opacity-100" : "opacity-0"
      }`}
    >
      {/* Abstract Decorations */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-20 w-80 h-80 bg-emerald-500/10 rounded-full blur-3xl" />
        <div className="absolute bottom-32 right-10 w-72 h-72 bg-teal-500/5 rounded-full blur-3xl" />
        <div className="absolute top-1/3 right-1/3 w-48 h-48 bg-emerald-600/10 rounded-full blur-3xl" />
        <div className="absolute inset-0 bg-[linear-gradient(rgba(16,185,129,0.02)_1px,transparent_1px),linear_gradient(90deg,rgba(16,185,129,0.02)_1px,transparent_1px)] bg-[size:60px_60px]" />
      </div>

      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-900/80 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link
              to="/"
              className="flex items-center space-x-2 text-slate-400 hover:text-emerald-400 transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              <span>Back to Home</span>
            </Link>
            <div className="relative hidden sm:block">
              <Search className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search articles..."
                className="bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 w-64"
              />
            </div>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-32 pb-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4">
            ACDS Blog
          </h1>
          <p className="text-xl text-slate-400 max-w-2xl mx-auto">
            Insights on cybersecurity, AI/ML, and protecting your organization
            from phishing threats.
          </p>
        </div>
      </section>

      {/* Featured Posts */}
      <section className="pb-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-2xl font-bold text-white mb-6">Featured</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {featuredPosts.map((post) => (
              <article
                key={post.id}
                className="group bg-slate-900/50 border border-slate-800 hover:border-emerald-500/30 rounded-2xl overflow-hidden transition-all duration-300"
              >
                <div className="p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <span className="text-4xl">{post.image}</span>
                    <span className="px-3 py-1 bg-emerald-500/10 text-emerald-400 text-xs font-medium rounded-full capitalize">
                      {post.category.replace("-", " & ")}
                    </span>
                  </div>
                  <h3 className="text-xl font-bold text-white mb-3 group-hover:text-emerald-400 transition-colors">
                    {post.title}
                  </h3>
                  <p className="text-slate-400 mb-4 line-clamp-2">
                    {post.excerpt}
                  </p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4 text-sm text-slate-500">
                      <span className="flex items-center space-x-1">
                        <User className="w-4 h-4" />
                        <span>{post.author}</span>
                      </span>
                      <span className="flex items-center space-x-1">
                        <Clock className="w-4 h-4" />
                        <span>{post.readTime}</span>
                      </span>
                    </div>
                    <button className="text-emerald-400 hover:text-emerald-300 transition-colors flex items-center space-x-1 text-sm font-medium">
                      <span>Read More</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* Category Filter */}
      <section className="pb-8 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-wrap gap-2">
            {categories.map((category) => (
              <button
                key={category.id}
                onClick={() => setActiveCategory(category.id)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  activeCategory === category.id
                    ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                    : "bg-slate-800/50 text-slate-400 hover:text-white border border-slate-700"
                }`}
              >
                {category.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* All Posts */}
      <section className="pb-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-2xl font-bold text-white mb-6">
            {activeCategory === "all"
              ? "All Posts"
              : categories.find((c) => c.id === activeCategory)?.label}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredPosts.map((post) => (
              <article
                key={post.id}
                className="group bg-slate-900/50 border border-slate-800 hover:border-emerald-500/30 rounded-xl overflow-hidden transition-all duration-300"
              >
                <div className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-3xl">{post.image}</span>
                    <span className="text-slate-500 text-sm">{post.date}</span>
                  </div>
                  <span className="inline-block px-2 py-0.5 bg-slate-800 text-slate-400 text-xs rounded mb-3 capitalize">
                    {post.category.replace("-", " & ")}
                  </span>
                  <h3 className="text-lg font-bold text-white mb-2 group-hover:text-emerald-400 transition-colors line-clamp-2">
                    {post.title}
                  </h3>
                  <p className="text-slate-400 text-sm mb-4 line-clamp-2">
                    {post.excerpt}
                  </p>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 text-sm">
                      {post.author}
                    </span>
                    <span className="text-slate-500 text-sm">
                      {post.readTime}
                    </span>
                  </div>
                </div>
              </article>
            ))}
          </div>

          {filteredPosts.length === 0 && (
            <div className="text-center py-12">
              <p className="text-slate-400">No posts found in this category.</p>
            </div>
          )}
        </div>
      </section>

      {/* Newsletter */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-slate-900/30">
        <div className="max-w-2xl mx-auto text-center">
          <h2 className="text-3xl font-bold text-white mb-4">Stay Updated</h2>
          <p className="text-slate-400 mb-8">
            Subscribe to our newsletter for the latest security insights and
            product updates.
          </p>
          <form className="flex flex-col sm:flex-row gap-4 max-w-md mx-auto">
            <input
              type="email"
              placeholder="Enter your email"
              className="flex-1 bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              className="bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 text-white px-6 py-3 rounded-xl font-semibold transition-all duration-200 shadow-lg shadow-emerald-500/25"
            >
              Subscribe
            </button>
          </form>
          <p className="text-slate-500 text-sm mt-4">
            No spam, unsubscribe anytime.
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-4 sm:px-6 lg:px-8 border-t border-slate-800">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between">
          <div className="flex items-center space-x-2 mb-4 md:mb-0">
            <div className="w-8 h-8 bg-gradient-to-br from-emerald-400 to-emerald-600 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="text-lg font-bold bg-gradient-to-r from-emerald-400 to-emerald-200 bg-clip-text text-transparent">
              ACDS
            </span>
          </div>
          <p className="text-slate-500 text-sm">
            © 2025 ACDS. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Blog;
