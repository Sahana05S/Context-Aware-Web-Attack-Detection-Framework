import { Link, Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  Shield,
  Globe,
  Activity,
  Brain,
  ArrowRight,
  Lock,
  Server,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import { motion, Variants } from 'framer-motion';

/* ─── animation variants ─────────────────────────────────────── */
const fadeUp: Variants = {
  hidden: { opacity: 0, y: 32 },
  visible: (i = 0) => ({
    opacity: 1,
    y: 0,
    transition: { type: 'spring', stiffness: 90, damping: 18, delay: i * 0.12 },
  }),
};

const scaleIn: Variants = {
  hidden: { opacity: 0, scale: 0.88 },
  visible: {
    opacity: 1,
    scale: 1,
    transition: { type: 'spring', stiffness: 80, damping: 16, delay: 0.25 },
  },
};

const stagger: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.15, delayChildren: 0.1 } },
};

/* ─── color tokens ───────────────────────────────────────────── */
const C = {
  purple: '#493D9E',
  lavender: '#B2A5FF',
  softLavender: '#DAD2FF',
  cream: '#FFF2AF',
  bg: '#F5F3FF',
  bgCard: '#FFFFFF',
  textPrimary: '#1A1433',
  textSecondary: '#4B4569',
  textMuted: '#7B7599',
};

/* ─── feature cards data ─────────────────────────────────────── */
const features = [
  {
    Icon: Globe,
    title: 'Workflow Modeling',
    desc: 'Maps complete HTTP request chains as stateful workflows, detecting attack progressions that span multiple steps — invisible to signature-only WAFs.',
    accent: C.purple,
    bg: C.softLavender,
  },
  {
    Icon: Activity,
    title: 'Behavioral Analysis',
    desc: 'Profiles each session end-to-end, flagging low-and-slow threats, credential stuffing, and anomalous navigation sequences with sub-second latency.',
    accent: '#6C5CE7',
    bg: '#EAE6FF',
  },
  {
    Icon: Brain,
    title: 'AI Intent Detection',
    desc: 'Dual-layer ML ensemble (rule-based + anomaly model) infers attacker intent from contextual signals, slashing false-positive fatigue for your SOC team.',
    accent: '#493D9E',
    bg: '#DAD2FF',
  },
];

/* ─── trust stats ────────────────────────────────────────────── */
const stats = [
  { value: '99.3%', label: 'Detection Accuracy' },
  { value: '<2ms', label: 'Avg. Latency Overhead' },
  { value: '10×', label: 'Fewer False Positives' },
  { value: '360°', label: 'Context Coverage' },
];

/* ══════════════════════════════════════════════════════════════ */
export function Landing() {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

  return (
    <div
      className="min-h-screen font-sans antialiased overflow-x-hidden"
      style={{ background: C.bg, color: C.textPrimary }}
    >
      {/* ── NAV ─────────────────────────────────────────────── */}
      <nav
        className="sticky top-0 z-50 backdrop-blur-md border-b"
        style={{
          background: 'rgba(245,243,255,0.85)',
          borderColor: C.softLavender,
        }}
      >
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center gap-2.5 select-none">
            <div
              className="p-1.5 rounded-lg"
              style={{ background: C.purple }}
            >
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span
              className="font-extrabold text-lg tracking-tight"
              style={{ color: C.purple }}
            >
              SecureEye
            </span>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-3">
            <Link
              to="/login"
              className="hidden sm:inline-block px-4 py-2 rounded-lg font-semibold text-sm transition-colors hover:underline"
              style={{ color: C.purple }}
            >
              Sign In
            </Link>
            <Link
              to="/register"
              className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl font-semibold text-sm text-white transition-all shadow-lg hover:-translate-y-0.5 hover:shadow-xl"
              style={{
                background: C.purple,
                boxShadow: `0 4px 20px ${C.purple}44`,
              }}
            >
              Get Started <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </nav>

      {/* ── HERO ────────────────────────────────────────────── */}
      <section className="relative overflow-hidden">
        {/* Background blobs */}
        <div
          className="pointer-events-none absolute -top-32 -left-32 w-[600px] h-[600px] rounded-full blur-3xl opacity-40"
          style={{ background: C.softLavender }}
        />
        <div
          className="pointer-events-none absolute top-20 right-0 w-[400px] h-[400px] rounded-full blur-3xl opacity-30"
          style={{ background: C.lavender }}
        />
        <div
          className="pointer-events-none absolute bottom-0 left-1/2 -translate-x-1/2 w-[700px] h-[200px] rounded-full blur-3xl opacity-20"
          style={{ background: C.cream }}
        />

        <div className="max-w-7xl mx-auto px-6 pt-20 pb-28 grid lg:grid-cols-2 gap-16 items-center relative z-10">
          {/* Left copy */}
          <motion.div
            variants={stagger}
            initial="hidden"
            animate="visible"
            className="space-y-8"
          >
            {/* Badge */}
            <motion.div variants={fadeUp} custom={0}>
              <span
                className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-widest border"
                style={{
                  background: C.softLavender,
                  color: C.purple,
                  borderColor: C.lavender,
                }}
              >
                <span
                  className="w-2 h-2 rounded-full animate-pulse"
                  style={{ background: C.purple }}
                />
                Next-Gen SOC Platform
              </span>
            </motion.div>

            {/* Headline */}
            <motion.h1
              variants={fadeUp}
              custom={1}
              className="text-5xl lg:text-6xl xl:text-7xl font-extrabold tracking-tight leading-[1.08]"
              style={{ color: C.textPrimary }}
            >
              Context-Aware
              <br />
              <span
                className="text-transparent bg-clip-text"
                style={{
                  backgroundImage: `linear-gradient(135deg, ${C.purple} 0%, ${C.lavender} 100%)`,
                }}
              >
                Web Attack
              </span>
              <br />
              Detection
            </motion.h1>

            {/* Sub */}
            <motion.p
              variants={fadeUp}
              custom={2}
              className="text-lg leading-relaxed max-w-xl"
              style={{ color: C.textSecondary }}
            >
              An advanced framework that identifies, analyzes, and mitigates web
              anomalies using{' '}
              <strong style={{ color: C.purple }}>behavioral context</strong> and
              machine learning — purpose-built for modern Security Operations Centers.
            </motion.p>

            {/* CTAs */}
            <motion.div variants={fadeUp} custom={3} className="flex flex-wrap gap-4 pt-2">
              <Link
                to="/register"
                className="flex items-center gap-2 px-8 py-4 rounded-xl font-bold text-base text-white transition-all hover:-translate-y-1 hover:shadow-2xl"
                style={{
                  background: `linear-gradient(135deg, ${C.purple} 0%, #6C5CE7 100%)`,
                  boxShadow: `0 6px 30px ${C.purple}55`,
                }}
              >
                Start Monitoring <ArrowRight className="w-5 h-5" />
              </Link>
              <Link
                to="/login"
                className="flex items-center gap-2 px-8 py-4 rounded-xl font-bold text-base border-2 transition-all hover:-translate-y-1"
                style={{
                  borderColor: C.purple,
                  color: C.purple,
                  background: 'transparent',
                }}
              >
                Sign In
              </Link>
            </motion.div>

            {/* Mini trust row */}
            <motion.div
              variants={fadeUp}
              custom={4}
              className="flex flex-wrap gap-6 pt-2"
            >
              {[
                { icon: Lock, label: 'Enterprise-grade security' },
                { icon: CheckCircle2, label: 'No signature databases' },
              ].map(({ icon: Icon, label }) => (
                <div
                  key={label}
                  className="flex items-center gap-2 text-sm font-medium"
                  style={{ color: C.textMuted }}
                >
                  <Icon className="w-4 h-4" style={{ color: C.purple }} />
                  {label}
                </div>
              ))}
            </motion.div>
          </motion.div>

          {/* Right – animated security graphic */}
          <motion.div
            variants={scaleIn}
            initial="hidden"
            animate="visible"
            className="relative flex items-center justify-center"
          >
            {/* Main card */}
            <div
              className="relative w-full max-w-lg rounded-3xl overflow-hidden border p-6"
              style={{
                background: 'rgba(255,255,255,0.80)',
                borderColor: C.softLavender,
                boxShadow: `0 24px 80px ${C.purple}22, 0 4px 20px ${C.softLavender}88`,
                backdropFilter: 'blur(20px)',
              }}
            >
              {/* Header row */}
              <div className="flex items-center justify-between mb-5">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-400 animate-pulse" />
                  <div className="w-2.5 h-2.5 rounded-full bg-yellow-400" />
                  <div className="w-2.5 h-2.5 rounded-full bg-green-400" />
                </div>
                <span
                  className="text-xs font-bold px-3 py-1 rounded-full"
                  style={{ background: C.softLavender, color: C.purple }}
                >
                  LIVE — Attack Monitor
                </span>
              </div>

              {/* Chart bars */}
              <div
                className="rounded-2xl p-4 mb-4 border"
                style={{ background: C.bg, borderColor: C.softLavender }}
              >
                <p className="text-xs font-semibold mb-3" style={{ color: C.textMuted }}>
                  Request Threat Score · last 7 intervals
                </p>
                <div className="flex items-end gap-2 h-28">
                  {[38, 72, 44, 91, 57, 33, 78].map((h, i) => (
                    <motion.div
                      key={i}
                      initial={{ height: 0 }}
                      animate={{ height: `${h}%` }}
                      transition={{ delay: 0.6 + i * 0.08, duration: 0.5, type: 'spring' }}
                      className="flex-1 rounded-t-md"
                      style={{
                        background:
                          h > 70
                            ? `linear-gradient(to top, #EF4444, #F87171)`
                            : `linear-gradient(to top, ${C.purple}, ${C.lavender})`,
                        opacity: 0.85,
                      }}
                    />
                  ))}
                </div>
              </div>

              {/* Alert log */}
              <div className="space-y-2">
                {[
                  { type: 'CRITICAL', msg: 'SQL Injection — 192.168.1.5', color: '#EF4444' },
                  { type: 'HIGH', msg: 'XSS payload in query param', color: '#F59E0B' },
                  { type: 'BLOCKED', msg: 'Rate limit exceeded · Rule 942100', color: '#10B981' },
                ].map(({ type, msg, color }, i) => (
                  <motion.div
                    key={type}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 1.2 + i * 0.15 }}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-xl border text-xs font-mono"
                    style={{
                      background: `${color}08`,
                      borderColor: `${color}30`,
                    }}
                  >
                    <span
                      className="font-bold shrink-0 px-2 py-0.5 rounded-md text-[10px]"
                      style={{ background: `${color}20`, color }}
                    >
                      {type}
                    </span>
                    <span style={{ color: C.textSecondary }}>{msg}</span>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Floating badges */}
            <motion.div
              animate={{ y: [-10, 8, -10] }}
              transition={{ repeat: Infinity, duration: 4, ease: 'easeInOut' }}
              className="absolute -top-5 -right-5 rounded-2xl border px-4 py-3 flex items-center gap-2 shadow-lg"
              style={{
                background: '#fff',
                borderColor: C.softLavender,
                boxShadow: `0 8px 24px ${C.purple}22`,
              }}
            >
              <Server className="w-5 h-5" style={{ color: C.purple }} />
              <div>
                <p className="text-[10px] font-bold" style={{ color: C.textMuted }}>
                  Requests/sec
                </p>
                <p className="text-base font-extrabold" style={{ color: C.purple }}>
                  4,832
                </p>
              </div>
            </motion.div>

            <motion.div
              animate={{ y: [8, -10, 8] }}
              transition={{ repeat: Infinity, duration: 5, ease: 'easeInOut' }}
              className="absolute -bottom-6 -left-6 rounded-2xl border px-4 py-3 flex items-center gap-2.5 shadow-lg"
              style={{
                background: '#fff',
                borderColor: '#FECACA',
                boxShadow: '0 8px 24px #EF444422',
              }}
            >
              <div
                className="w-8 h-8 rounded-full flex items-center justify-center"
                style={{ background: '#FEE2E2' }}
              >
                <AlertTriangle className="w-4 h-4 text-red-500" />
              </div>
              <div>
                <p className="text-[10px] font-bold text-red-500">Threat Blocked</p>
                <p className="text-[10px]" style={{ color: C.textMuted }}>
                  Rule 942100 · 0.3ms
                </p>
              </div>
            </motion.div>

            <motion.div
              animate={{ y: [-6, 10, -6] }}
              transition={{ repeat: Infinity, duration: 3.5, ease: 'easeInOut' }}
              className="absolute top-1/2 -translate-y-1/2 -left-10 rounded-2xl border px-4 py-3 shadow-lg"
              style={{
                background: C.softLavender,
                borderColor: C.lavender,
                boxShadow: `0 8px 24px ${C.purple}22`,
              }}
            >
              <p className="text-[10px] font-bold" style={{ color: C.purple }}>
                AI Confidence
              </p>
              <p className="text-xl font-extrabold" style={{ color: C.purple }}>
                98.7%
              </p>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* ── STATS STRIP ─────────────────────────────────────── */}
      <section
        className="border-y"
        style={{ borderColor: C.softLavender, background: '#fff' }}
      >
        <div className="max-w-7xl mx-auto px-6 py-10 grid grid-cols-2 md:grid-cols-4 gap-6">
          {stats.map(({ value, label }, i) => (
            <motion.div
              key={label}
              variants={fadeUp}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              custom={i}
              className="text-center"
            >
              <p
                className="text-3xl font-extrabold"
                style={{ color: C.purple }}
              >
                {value}
              </p>
              <p className="text-sm mt-1 font-medium" style={{ color: C.textMuted }}>
                {label}
              </p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ── FEATURES ────────────────────────────────────────── */}
      <section className="py-28 px-6" style={{ background: C.bg }}>
        <div className="max-w-7xl mx-auto">
          {/* Section label */}
          <motion.div
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            className="text-center mb-16 space-y-4"
          >
            <span
              className="inline-block px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-widest border"
              style={{
                background: C.softLavender,
                color: C.purple,
                borderColor: C.lavender,
              }}
            >
              Core Capabilities
            </span>
            <h2
              className="text-4xl font-extrabold tracking-tight"
              style={{ color: C.textPrimary }}
            >
              Why Context Awareness Matters
            </h2>
            <p className="max-w-2xl mx-auto text-base leading-relaxed" style={{ color: C.textSecondary }}>
              Traditional WAFs rely on static signatures. SecureEye layers behavioral
              history, workflow graphs, and AI inference to precisely separate threat
              actors from real users.
            </p>
          </motion.div>

          {/* Cards */}
          <motion.div
            variants={stagger}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-80px' }}
            className="grid md:grid-cols-3 gap-8"
          >
            {features.map(({ Icon, title, desc, accent, bg }, i) => (
              <motion.div
                key={title}
                variants={fadeUp}
                custom={i}
                whileHover={{ y: -6, boxShadow: `0 20px 60px ${accent}22` }}
                className="group p-8 rounded-3xl border transition-all cursor-default"
                style={{
                  background: C.bgCard,
                  borderColor: C.softLavender,
                  boxShadow: `0 4px 20px ${C.purple}0d`,
                }}
              >
                <div
                  className="w-14 h-14 rounded-2xl flex items-center justify-center mb-6 transition-transform group-hover:scale-110"
                  style={{ background: bg }}
                >
                  <Icon className="w-7 h-7" style={{ color: accent }} />
                </div>
                <h3
                  className="text-xl font-bold mb-3"
                  style={{ color: C.textPrimary }}
                >
                  {title}
                </h3>
                <p className="leading-relaxed text-sm" style={{ color: C.textSecondary }}>
                  {desc}
                </p>

                {/* Bottom accent line */}
                <div
                  className="mt-6 h-1 w-12 rounded-full transition-all group-hover:w-full"
                  style={{ background: `linear-gradient(90deg, ${accent}, ${C.lavender})` }}
                />
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── HOW IT WORKS (mini) ──────────────────────────────── */}
      <section className="py-20 px-6" style={{ background: '#fff' }}>
        <div className="max-w-5xl mx-auto">
          <motion.div
            variants={fadeUp}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            className="text-center mb-14"
          >
            <h2
              className="text-3xl font-extrabold tracking-tight mb-4"
              style={{ color: C.textPrimary }}
            >
              From Raw Request to Actionable Insight
            </h2>
            <p className="text-base" style={{ color: C.textSecondary }}>
              A three-stage pipeline that turns HTTP noise into precise threat intelligence.
            </p>
          </motion.div>

          <div className="relative flex flex-col md:flex-row items-start md:items-center gap-0">
            {[
              {
                step: '01',
                icon: Globe,
                title: 'Ingest & Normalize',
                desc: 'Every HTTP request is parsed, timestamped, and enriched with geo and session metadata in real time.',
              },
              {
                step: '02',
                icon: Activity,
                title: 'Context Graph',
                desc: 'Requests are linked into a stateful workflow graph per session, exposing multi-step attack chains.',
              },
              {
                step: '03',
                icon: Brain,
                title: 'AI Verdict',
                desc: 'Dual ML ensemble scores intent. Alerts fire only when confidence exceeds dynamic thresholds.',
              },
            ].map(({ step, icon: Icon, title, desc }, i) => (
              <motion.div
                key={step}
                variants={fadeUp}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true }}
                custom={i}
                className="flex-1 flex flex-col items-center text-center px-6 relative"
              >
                {/* Connector line */}
                {i < 2 && (
                  <div
                    className="hidden md:block absolute top-9 left-[calc(50%+3rem)] right-0 h-0.5"
                    style={{
                      background: `linear-gradient(90deg, ${C.lavender}, ${C.softLavender})`,
                    }}
                  />
                )}
                <div
                  className="w-16 h-16 rounded-2xl flex items-center justify-center mb-5 relative z-10"
                  style={{
                    background: C.softLavender,
                    boxShadow: `0 0 0 6px ${C.bg}`,
                  }}
                >
                  <Icon className="w-7 h-7" style={{ color: C.purple }} />
                </div>
                <span
                  className="text-xs font-black tracking-widest mb-2"
                  style={{ color: C.lavender }}
                >
                  STEP {step}
                </span>
                <h3 className="font-bold text-base mb-2" style={{ color: C.textPrimary }}>
                  {title}
                </h3>
                <p className="text-sm leading-relaxed" style={{ color: C.textMuted }}>
                  {desc}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────── */}
      <section className="py-28 px-6">
        <motion.div
          variants={fadeUp}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          className="max-w-4xl mx-auto rounded-3xl overflow-hidden relative text-center"
          style={{
            background: `linear-gradient(135deg, ${C.purple} 0%, #6C5CE7 60%, #9C88FF 100%)`,
            boxShadow: `0 30px 100px ${C.purple}55`,
          }}
        >
          {/* Decorative circles */}
          <div
            className="pointer-events-none absolute -top-24 -right-24 w-64 h-64 rounded-full opacity-20"
            style={{ background: C.cream }}
          />
          <div
            className="pointer-events-none absolute -bottom-16 -left-16 w-48 h-48 rounded-full opacity-10"
            style={{ background: C.lavender }}
          />

          <div className="relative z-10 px-10 py-20">
            <span
              className="inline-block mb-6 px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-widest"
              style={{ background: 'rgba(255,242,175,0.25)', color: C.cream }}
            >
              Ready to Secure Your Perimeter?
            </span>
            <h2 className="text-4xl md:text-5xl font-extrabold text-white mb-6 leading-tight">
              Stop Attacks Before
              <br />
              They Become Breaches
            </h2>
            <p className="text-base mb-10 max-w-xl mx-auto" style={{ color: C.softLavender }}>
              Join security teams already protecting their infrastructure with
              context-aware, AI-driven threat detection — zero signature databases required.
            </p>
            <div className="flex flex-wrap justify-center gap-4">
              <Link
                to="/register"
                className="flex items-center gap-2 px-9 py-4 rounded-xl font-bold text-base transition-all hover:-translate-y-1 hover:shadow-2xl"
                style={{
                  background: C.cream,
                  color: C.purple,
                  boxShadow: `0 6px 24px rgba(0,0,0,0.2)`,
                }}
              >
                Get Started Free <ArrowRight className="w-5 h-5" />
              </Link>
              <Link
                to="/login"
                className="flex items-center gap-2 px-9 py-4 rounded-xl font-bold text-base border-2 border-white text-white transition-all hover:-translate-y-1 hover:bg-white/10"
              >
                Sign In
              </Link>
            </div>

            {/* Bottom micro-text */}
            <p className="mt-8 text-xs" style={{ color: 'rgba(218,210,255,0.7)' }}>
              No credit card required · Deploy in minutes · SOC-ready out of the box
            </p>
          </div>
        </motion.div>
      </section>

      {/* ── FOOTER ──────────────────────────────────────────── */}
      <footer
        className="border-t py-8 px-6 text-center"
        style={{ borderColor: C.softLavender, background: C.bg }}
      >
        <div className="flex items-center justify-center gap-2 mb-3">
          <div className="p-1 rounded-md" style={{ background: C.purple }}>
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="font-extrabold text-sm" style={{ color: C.purple }}>
            SecureEye
          </span>
        </div>
        <p className="text-xs" style={{ color: C.textMuted }}>
          © {new Date().getFullYear()} Context-Aware Web Attack Detection Framework. Built for modern SOC teams.
        </p>
      </footer>
    </div>
  );
}
