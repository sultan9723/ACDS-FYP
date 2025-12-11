import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  Check,
  ArrowLeft,
  Zap,
  Building,
  Rocket,
  HelpCircle,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

const Pricing = () => {
  const [annual, setAnnual] = useState(true);
  const [openFaq, setOpenFaq] = useState(null);

  const plans = [
    {
      name: "Starter",
      icon: Zap,
      description:
        "Perfect for small teams getting started with email security",
      monthlyPrice: 29,
      annualPrice: 24,
      features: [
        "Up to 1,000 emails/month",
        "Basic phishing detection",
        "Email dashboard",
        "7-day log retention",
        "Email support",
      ],
      cta: "Start Free Trial",
      highlighted: false,
    },
    {
      name: "Professional",
      icon: Rocket,
      description: "For growing organizations with advanced security needs",
      monthlyPrice: 79,
      annualPrice: 66,
      features: [
        "Up to 10,000 emails/month",
        "Advanced ML detection",
        "IOC extraction & analysis",
        "Automated response actions",
        "30-day log retention",
        "API access",
        "Priority support",
        "Custom integrations",
      ],
      cta: "Start Free Trial",
      highlighted: true,
    },
    {
      name: "Enterprise",
      icon: Building,
      description: "Custom solutions for large organizations",
      monthlyPrice: null,
      annualPrice: null,
      features: [
        "Unlimited emails",
        "Custom ML model training",
        "Full orchestration suite",
        "SIEM integration",
        "Unlimited log retention",
        "Dedicated support",
        "SLA guarantee",
        "On-premise deployment",
        "Compliance reporting",
      ],
      cta: "Contact Sales",
      highlighted: false,
    },
  ];

  const faqs = [
    {
      question: "How does the free trial work?",
      answer:
        "Start with a 14-day free trial of any plan. No credit card required. You'll have full access to all features during the trial period.",
    },
    {
      question: "Can I change plans later?",
      answer:
        "Yes, you can upgrade or downgrade your plan at any time. When upgrading, you'll get immediate access to new features. When downgrading, changes take effect at the next billing cycle.",
    },
    {
      question: "What payment methods do you accept?",
      answer:
        "We accept all major credit cards, PayPal, and bank transfers for annual plans. Enterprise customers can also pay via invoice.",
    },
    {
      question: "Is there a setup fee?",
      answer:
        "No setup fees for Starter and Professional plans. Enterprise deployments may have custom implementation costs depending on requirements.",
    },
    {
      question: "What's the accuracy of the phishing detection?",
      answer:
        "Our ML model achieves 95.9% accuracy on standard benchmarks. Enterprise plans include custom model training on your organization's data for even higher accuracy.",
    },
    {
      question: "Do you offer educational discounts?",
      answer:
        "Yes! Educational institutions and non-profits receive a 50% discount on all plans. Contact our sales team for verification.",
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-900/95 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link
              to="/"
              className="flex items-center space-x-2 text-slate-400 hover:text-emerald-400 transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
              <span>Back to Home</span>
            </Link>
            <Link
              to="/login"
              className="bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 text-white px-5 py-2 rounded-lg font-medium transition-all duration-200"
            >
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-32 pb-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4">
            Simple, Transparent Pricing
          </h1>
          <p className="text-xl text-slate-400 max-w-2xl mx-auto mb-8">
            Choose the plan that fits your organization. All plans include a
            14-day free trial.
          </p>

          {/* Billing Toggle */}
          <div className="flex items-center justify-center space-x-4 mb-12">
            <span
              className={`text-sm ${!annual ? "text-white" : "text-slate-400"}`}
            >
              Monthly
            </span>
            <button
              onClick={() => setAnnual(!annual)}
              className="relative w-14 h-7 bg-slate-700 rounded-full p-1 transition-colors"
            >
              <div
                className={`absolute w-5 h-5 bg-emerald-500 rounded-full transition-transform ${
                  annual ? "translate-x-7" : "translate-x-0"
                }`}
              ></div>
            </button>
            <span
              className={`text-sm ${annual ? "text-white" : "text-slate-400"}`}
            >
              Annual
              <span className="ml-2 px-2 py-0.5 bg-emerald-500/20 text-emerald-400 text-xs rounded-full">
                Save 20%
              </span>
            </span>
          </div>
        </div>
      </section>

      {/* Pricing Cards */}
      <section className="pb-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {plans.map((plan, index) => (
              <div
                key={index}
                className={`relative rounded-2xl p-8 ${
                  plan.highlighted
                    ? "bg-gradient-to-b from-emerald-500/10 to-slate-900/50 border-2 border-emerald-500/50"
                    : "bg-slate-900/50 border border-slate-800"
                }`}
              >
                {plan.highlighted && (
                  <div className="absolute -top-4 left-1/2 -translate-x-1/2">
                    <span className="bg-gradient-to-r from-emerald-500 to-emerald-600 text-white text-sm font-semibold px-4 py-1 rounded-full">
                      Most Popular
                    </span>
                  </div>
                )}

                <div className="text-center mb-8">
                  <div
                    className={`w-14 h-14 mx-auto rounded-xl flex items-center justify-center mb-4 ${
                      plan.highlighted ? "bg-emerald-500/20" : "bg-slate-800"
                    }`}
                  >
                    <plan.icon
                      className={`w-7 h-7 ${
                        plan.highlighted ? "text-emerald-400" : "text-slate-400"
                      }`}
                    />
                  </div>
                  <h3 className="text-2xl font-bold text-white mb-2">
                    {plan.name}
                  </h3>
                  <p className="text-slate-400 text-sm">{plan.description}</p>
                </div>

                <div className="text-center mb-8">
                  {plan.monthlyPrice ? (
                    <>
                      <div className="flex items-baseline justify-center">
                        <span className="text-4xl font-bold text-white">
                          ${annual ? plan.annualPrice : plan.monthlyPrice}
                        </span>
                        <span className="text-slate-400 ml-2">/month</span>
                      </div>
                      {annual && (
                        <p className="text-emerald-400 text-sm mt-1">
                          Billed annually (${plan.annualPrice * 12}/year)
                        </p>
                      )}
                    </>
                  ) : (
                    <div className="text-3xl font-bold text-white">
                      Custom Pricing
                    </div>
                  )}
                </div>

                <ul className="space-y-4 mb-8">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-start space-x-3">
                      <Check className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                      <span className="text-slate-300 text-sm">{feature}</span>
                    </li>
                  ))}
                </ul>

                <button
                  className={`w-full py-3 rounded-xl font-semibold transition-all duration-200 ${
                    plan.highlighted
                      ? "bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 text-white shadow-lg shadow-emerald-500/25"
                      : "bg-slate-800 hover:bg-slate-700 text-white border border-slate-700"
                  }`}
                >
                  {plan.cta}
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Feature Comparison */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-slate-900/30">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-12">
            Feature Comparison
          </h2>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="py-4 px-4 text-left text-slate-400 font-medium">
                    Feature
                  </th>
                  <th className="py-4 px-4 text-center text-slate-400 font-medium">
                    Starter
                  </th>
                  <th className="py-4 px-4 text-center text-emerald-400 font-medium">
                    Professional
                  </th>
                  <th className="py-4 px-4 text-center text-slate-400 font-medium">
                    Enterprise
                  </th>
                </tr>
              </thead>
              <tbody>
                {[
                  ["Email scanning", "1K/mo", "10K/mo", "Unlimited"],
                  ["ML detection", "Basic", "Advanced", "Custom"],
                  ["IOC extraction", "—", "✓", "✓"],
                  ["Automated response", "—", "✓", "✓"],
                  ["API access", "—", "✓", "✓"],
                  ["Log retention", "7 days", "30 days", "Unlimited"],
                  ["SIEM integration", "—", "—", "✓"],
                  ["Custom training", "—", "—", "✓"],
                  ["Support", "Email", "Priority", "Dedicated"],
                ].map((row, i) => (
                  <tr key={i} className="border-b border-slate-800/50">
                    <td className="py-4 px-4 text-white">{row[0]}</td>
                    <td className="py-4 px-4 text-center text-slate-400">
                      {row[1]}
                    </td>
                    <td className="py-4 px-4 text-center text-white bg-emerald-500/5">
                      {row[2]}
                    </td>
                    <td className="py-4 px-4 text-center text-slate-400">
                      {row[3]}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-4">
            Frequently Asked Questions
          </h2>
          <p className="text-slate-400 text-center mb-12">
            Have questions? We've got answers.
          </p>

          <div className="space-y-4">
            {faqs.map((faq, index) => (
              <div
                key={index}
                className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden"
              >
                <button
                  onClick={() => setOpenFaq(openFaq === index ? null : index)}
                  className="w-full flex items-center justify-between p-6 text-left"
                >
                  <span className="text-white font-medium pr-4">
                    {faq.question}
                  </span>
                  {openFaq === index ? (
                    <ChevronUp className="w-5 h-5 text-emerald-400 shrink-0" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-slate-400 shrink-0" />
                  )}
                </button>
                {openFaq === index && (
                  <div className="px-6 pb-6">
                    <p className="text-slate-400 leading-relaxed">
                      {faq.answer}
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <div className="bg-gradient-to-r from-emerald-600/20 to-teal-600/20 border border-emerald-500/30 rounded-3xl p-12 text-center">
            <h2 className="text-3xl font-bold text-white mb-4">
              Still have questions?
            </h2>
            <p className="text-slate-300 mb-8">
              Our team is here to help you find the perfect plan for your
              organization.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <a
                href="mailto:sales@acds.io"
                className="w-full sm:w-auto bg-white hover:bg-slate-100 text-slate-900 px-8 py-3 rounded-xl font-semibold transition-colors"
              >
                Contact Sales
              </a>
              <Link
                to="/docs"
                className="w-full sm:w-auto text-emerald-400 hover:text-emerald-300 px-8 py-3 font-semibold transition-colors"
              >
                Read Documentation
              </Link>
            </div>
          </div>
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

export default Pricing;
