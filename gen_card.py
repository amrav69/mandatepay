#!/usr/bin/env python3
"""Generate mandate-verification terminal SVG for mandatepay README.

ILLUSTRATIVE ONLY: all ids/amounts/latencies/signature bytes below are hardcoded
diagram values, NOT output from `cargo run --bin eval`. Do not cite the card as
measurement; cite a real eval run. See README "What's real vs simulated".
"""

# Hex bytes for decorative signature display (realistic Ed25519 output)
SIG_BYTES = "4a3f b291 e80c 7d12 a4f9 3b56 c1d8 9e2a 6f7b 0c4d 8e3f 1a2b 9c5d e7f0 4a1c 8b3e"
PUBKEY_BYTES= "d9f2 a1c4 8e7b 3f0d 5a92 c6e1 4b8d 2f7a"

SVG = f"""<svg xmlns="http://www.w3.org/2000/svg" width="720" height="320" viewBox="0 0 720 320">
  <defs>
    <filter id="glow">
      <feGaussianBlur stdDeviation="2.5" result="b"/>
      <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow-sm">
      <feGaussianBlur stdDeviation="1.5" result="b"/>
      <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#0d1117"/>
      <stop offset="100%" stop-color="#111827"/>
    </linearGradient>
    <linearGradient id="bar-green" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#3fb950"/>
      <stop offset="100%" stop-color="#26a641"/>
    </linearGradient>
  </defs>

  <!-- Background -->
  <rect width="720" height="320" rx="12" fill="url(#bg)" stroke="#21262d" stroke-width="1"/>

  <!-- Title bar -->
  <rect width="720" height="36" rx="12" fill="#161b22"/>
  <rect y="24" width="720" height="12" fill="#161b22"/>
  <rect y="35" width="720" height="1" fill="#21262d"/>
  <circle cx="18" cy="18" r="5.5" fill="#FF5F57"/>
  <circle cx="36" cy="18" r="5.5" fill="#FFBD2E"/>
  <circle cx="54" cy="18" r="5.5" fill="#28C840"/>
  <text x="360" y="22" text-anchor="middle"
    font-family="JetBrains Mono,monospace" font-size="11" fill="#8b949e">
    MANDATEPAY · MANDATE VERIFICATION ENGINE · Rust + Ed25519
  </text>

  <!-- ── LEFT PANEL: Mandate card ── -->

  <!-- Panel label -->
  <text x="18" y="56" font-family="JetBrains Mono,monospace" font-size="9"
    font-weight="700" fill="#CE422B" letter-spacing="1">MANDATE #mnd_SWaj4aIL54v1</text>

  <!-- Mandate field rows -->
  <!-- Agent -->
  <text x="18" y="74" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">agent      </text>
  <text x="100" y="74" font-family="JetBrains Mono,monospace" font-size="9" fill="#e6edf3">research_agent_v2</text>

  <!-- Intent -->
  <text x="18" y="89" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">intent     </text>
  <text x="100" y="89" font-family="JetBrains Mono,monospace" font-size="9" fill="#e6edf3">api.razorpay.com/v1/orders</text>

  <!-- Amount -->
  <text x="18" y="104" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">amount     </text>
  <text x="100" y="104" font-family="JetBrains Mono,monospace" font-size="9" fill="#FFBD2E">&#8377;450.00</text>

  <!-- Spend cap -->
  <text x="18" y="119" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">spend_cap  </text>
  <text x="100" y="119" font-family="JetBrains Mono,monospace" font-size="9" fill="#e6edf3">&#8377;5,000 / 24h</text>

  <!-- Merchant -->
  <text x="18" y="134" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">merchant   </text>
  <text x="100" y="134" font-family="JetBrains Mono,monospace" font-size="9" fill="#e6edf3">merchant-001  ✓ allowlisted</text>

  <!-- Expiry -->
  <text x="18" y="149" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">expires    </text>
  <text x="100" y="149" font-family="JetBrains Mono,monospace" font-size="9" fill="#e6edf3">2026-09-01 00:00 UTC</text>

  <!-- Nonce -->
  <text x="18" y="164" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">nonce      </text>
  <text x="100" y="164" font-family="JetBrains Mono,monospace" font-size="9" fill="#e6edf3">0x9c3d...f12a  (fresh)</text>

  <!-- Divider -->
  <line x1="14" y1="172" x2="350" y2="172" stroke="#21262d" stroke-width="1"/>

  <!-- Pubkey -->
  <text x="18" y="184" font-family="JetBrains Mono,monospace" font-size="8" fill="#8b949e">pubkey  </text>
  <text x="76" y="184" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">{PUBKEY_BYTES}</text>

  <!-- Sig label -->
  <text x="18" y="197" font-family="JetBrains Mono,monospace" font-size="8" fill="#8b949e">sig     </text>
  <text x="76" y="197" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">{SIG_BYTES}</text>

  <!-- Divider -->
  <line x1="14" y1="207" x2="350" y2="207" stroke="#21262d" stroke-width="1"/>

  <!-- Status badge -->
  <rect x="18" y="213" width="94" height="20" rx="4" fill="#3fb95020" stroke="#3fb950" stroke-width="1"/>
  <circle cx="30" cy="223" r="4" fill="#3fb950" filter="url(#glow-sm)"/>
  <text x="66" y="227" text-anchor="middle" font-family="JetBrains Mono,monospace"
    font-size="10" font-weight="700" fill="#3fb950">AUTHORIZED</text>

  <text x="122" y="227" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">320ms  ·  gateway: razorpay-test</text>

  <!-- Divider -->
  <line x1="14" y1="243" x2="350" y2="243" stroke="#21262d" stroke-width="1"/>

  <!-- Attack suite summary -->
  <text x="18" y="257" font-family="JetBrains Mono,monospace" font-size="9"
    font-weight="700" fill="#CE422B" letter-spacing="1">ATTACK SUITE</text>
  <text x="18" y="271" font-family="JetBrains Mono,monospace" font-size="9" fill="#3fb950">10/10 attacks rejected</text>
  <text x="130" y="271" font-family="JetBrains Mono,monospace" font-size="9" fill="#8b949e">·  mean latency 5ms</text>

  <!-- Progress bar: 10/10 -->
  <rect x="18" y="276" width="320" height="6" rx="3" fill="#21262d"/>
  <rect x="18" y="276" width="320" height="6" rx="3" fill="url(#bar-green)"/>
  <text x="348" y="282" text-anchor="end" font-family="JetBrains Mono,monospace"
    font-size="8" fill="#3fb950">SUITE GREEN</text>

  <!-- ── VERTICAL DIVIDER ── -->
  <line x1="370" y1="40" x2="370" y2="300" stroke="#21262d" stroke-width="1"/>

  <!-- ── RIGHT PANEL: Verification log ── -->
  <text x="386" y="56" font-family="JetBrains Mono,monospace" font-size="9"
    font-weight="700" fill="#00D9FF" letter-spacing="1">VERIFICATION LOG  · 9 GATES</text>

  <!-- Gate rows: 13 policy checks (illustrative timings) -->
  <!-- 1 -->
  <text x="386" y="70" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="70" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">version check</text>
  <text x="700" y="70" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 2 -->
  <text x="386" y="80" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="80" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">action in scope</text>
  <text x="700" y="80" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 3 -->
  <text x="386" y="90" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="90" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">currency = INR</text>
  <text x="700" y="90" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 4 -->
  <text x="386" y="100" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="100" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">max_amount &gt; 0</text>
  <text x="700" y="100" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 5 -->
  <text x="386" y="110" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="110" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">expires &gt; issued</text>
  <text x="700" y="110" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 6 -->
  <text x="386" y="120" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="120" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">agent + merchant present</text>
  <text x="700" y="120" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 7 -->
  <text x="386" y="130" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="130" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">issued_at leeway (60s)</text>
  <text x="700" y="130" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 8 -->
  <text x="386" y="140" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="140" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">mandate not expired</text>
  <text x="700" y="140" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 9 — the big one -->
  <text x="386" y="150" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950" filter="url(#glow-sm)">&#10003;</text>
  <text x="398" y="150" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">Ed25519 signature valid</text>
  <text x="700" y="150" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#FFBD2E">0.12ms</text>

  <!-- 10 -->
  <text x="386" y="160" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="160" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">merchant allowlisted</text>
  <text x="700" y="160" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.02ms</text>

  <!-- 11 -->
  <text x="386" y="170" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="170" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">amount &gt; 0</text>
  <text x="700" y="170" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 12 -->
  <text x="386" y="180" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="180" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">amount ≤ cap</text>
  <text x="700" y="180" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.01ms</text>

  <!-- 13 -->
  <text x="386" y="190" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">&#10003;</text>
  <text x="398" y="190" font-family="JetBrains Mono,monospace" font-size="8" fill="#e6edf3">nonce fresh (SQLite PK)</text>
  <text x="700" y="190" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">0.04ms</text>

  <!-- Divider -->
  <line x1="382" y1="202" x2="710" y2="202" stroke="#21262d" stroke-width="1"/>

  <!-- Result -->
  <text x="386" y="218" font-family="JetBrains Mono,monospace" font-size="9"
    font-weight="700" fill="#00D9FF" letter-spacing="1">RESULT</text>
  <rect x="437" y="208" width="94" height="18" rx="3" fill="#3fb95020" stroke="#3fb950" stroke-width="1"/>
  <text x="484" y="220" text-anchor="middle" font-family="JetBrains Mono,monospace"
    font-size="10" font-weight="700" fill="#3fb950">ALLOW</text>

  <!-- Agent demo output -->
  <line x1="382" y1="228" x2="710" y2="228" stroke="#21262d" stroke-width="1"/>
  <text x="386" y="242" font-family="JetBrains Mono,monospace" font-size="8" fill="#8b949e">[agent] model  nvidia/nemotron-3-super-120b</text>
  <text x="386" y="254" font-family="JetBrains Mono,monospace" font-size="8" fill="#8b949e">[agent] order  order_TV8RBWXVecmj1m</text>
  <text x="386" y="266" font-family="JetBrains Mono,monospace" font-size="8" fill="#3fb950">[agent] decision  ALLOW  ·  gateway: razorpay-test</text>

  <!-- Prompt -->
  <line x1="382" y1="276" x2="710" y2="276" stroke="#21262d" stroke-width="1"/>
  <text x="386" y="292" font-family="JetBrains Mono,monospace" font-size="10" fill="#CE422B">&#10095;</text>
  <text x="400" y="292" font-family="JetBrains Mono,monospace" font-size="10" fill="#e6edf3">cargo run --bin eval</text>
  <rect x="536" y="281" width="7" height="13" rx="1" fill="#CE422B" opacity="0.9"/>

  <!-- Footer -->
  <line x1="0" y1="300" x2="720" y2="300" stroke="#21262d" stroke-width="1"/>
  <text x="18" y="314" font-family="JetBrains Mono,monospace" font-size="8" fill="#484f58">
    LLM proposes · determinism disposes · ed25519-dalek v3 · SQLite replay guard · Razorpay test-mode
  </text>
</svg>"""

with open("mandate_card.svg", "w", encoding="utf-8") as f:
    f.write(SVG)

print("mandate_card.svg written")
