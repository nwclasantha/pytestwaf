"""Generate comprehensive WAF assessment with 3D visualizations."""
import html as h
import json
import math
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    with open("mitre_cache.json", encoding="utf-8") as f:
        mitre_data = json.load(f)
except FileNotFoundError:
    print("ERROR: mitre_cache.json not found. Place it in the project root directory.")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"ERROR: mitre_cache.json is malformed: {e}")
    sys.exit(1)

techniques = {}
for obj in mitre_data["objects"]:
    if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated") and obj.get("external_references"):
        techniques[obj["external_references"][0]["external_id"]] = obj

attacks = [
    {"a":"XSS","mid":"T1059.007","tac":"Execution","kc":"Exploitation","t":328,"b":327},
    {"a":"SQL Injection","mid":"T1190","tac":"Initial Access","kc":"Exploitation","t":60,"b":60},
    {"a":"RCE","mid":"T1059","tac":"Execution","kc":"Exploitation","t":18,"b":15},
    {"a":"Path Traversal","mid":"T1083","tac":"Discovery","kc":"Exploitation","t":28,"b":28},
    {"a":"NoSQL Injection","mid":"T1190","tac":"Initial Access","kc":"Exploitation","t":50,"b":50},
    {"a":"CRLF","mid":"T1557","tac":"Collection","kc":"Exploitation","t":7,"b":7},
    {"a":"LDAP Injection","mid":"T1071.001","tac":"C2","kc":"Exploitation","t":24,"b":24},
    {"a":"Shell Injection","mid":"T1059.004","tac":"Execution","kc":"Exploitation","t":32,"b":32},
    {"a":"XXE","mid":"T1221","tac":"Defense Evasion","kc":"Weaponization","t":2,"b":2},
    {"a":"SSTI","mid":"T1059","tac":"Execution","kc":"Exploitation","t":24,"b":24},
    {"a":"SSI","mid":"T1505.003","tac":"Persistence","kc":"Installation","t":24,"b":24},
    {"a":"Mail Injection","mid":"T1566.001","tac":"Initial Access","kc":"Delivery","t":24,"b":24},
    {"a":"XML Injection","mid":"T1221","tac":"Defense Evasion","kc":"Weaponization","t":7,"b":7},
    {"a":"REST API","mid":"T1106","tac":"Execution","kc":"Exploitation","t":7,"b":7},
    {"a":"SOAP","mid":"T1106","tac":"Execution","kc":"Exploitation","t":5,"b":5},
]

kc_phases = ["Reconnaissance","Weaponization","Delivery","Exploitation","Installation","C2","Actions"]
kc_colors = ["#6366f1","#8b5cf6","#a855f7","#d946ef","#ec4899","#f43f5e","#ef4444"]

kc_data = {}
for phase in kc_phases:
    pa = [a for a in attacks if a["kc"] == phase]
    kc_data[phase] = {"t": sum(a["t"] for a in pa), "b": sum(a["b"] for a in pa)}

tac_data = {}
for a in attacks:
    tac_data.setdefault(a["tac"], {"t": 0, "b": 0})
    tac_data[a["tac"]]["t"] += a["t"]
    tac_data[a["tac"]]["b"] += a["b"]

now = datetime.now().strftime("%Y-%m-%d %H:%M")

# Pre-compute 3D sphere positions (in Python, deterministic)
sphere_data = []
for i, a in enumerate(attacks):
    pct = a["b"] / a["t"] * 100
    radius = math.sqrt(a["t"]) * 0.12 + 0.25
    angle = (i / len(attacks)) * math.pi * 2
    dist = 5 + (1 - pct / 100) * 3
    x = round(math.cos(angle) * dist, 2)
    z = round(math.sin(angle) * dist, 2)
    y = round(radius + (i % 3) * 1.2, 2)
    color = "0x56CC54" if pct >= 95 else "0xFDBE10" if pct >= 80 else "0xF24444"
    sphere_data.append({"x": x, "y": y, "z": z, "r": round(radius, 2), "c": color, "name": a["a"], "pct": pct})

# Strengths and weaknesses
strengths = []
weaknesses = []
for a in attacks:
    pct = a["b"] / a["t"] * 100
    if pct == 100:
        strengths.append(a)
    elif pct < 100:
        weaknesses.append(a)

report = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>3D WAF Security Assessment</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:Inter,-apple-system,sans-serif;background:#0b0f2a;color:#cbd5e1;font-size:13px;line-height:1.7}}
.wrap{{max-width:1100px;margin:0 auto;padding:30px 20px}}
h1{{font-size:30px;font-weight:900;background:linear-gradient(90deg,#818cf8,#f472b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
h2{{font-size:19px;font-weight:700;color:#a5b4fc;margin:36px 0 14px;padding-bottom:7px;border-bottom:2px solid rgba(99,102,241,0.4)}}
.sub{{color:#64748b;font-size:12px;margin-bottom:20px}}
.card{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:22px;margin:14px 0}}
.glow{{box-shadow:0 0 40px rgba(99,102,241,0.1)}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}}
.m{{background:rgba(255,255,255,0.04);border-radius:12px;padding:16px;text-align:center;border:1px solid rgba(255,255,255,0.06)}}
.mv{{font-size:30px;font-weight:900;background:linear-gradient(135deg,#818cf8,#f472b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.ml{{font-size:11px;color:#64748b;margin-top:4px}}
table{{border-collapse:collapse;width:100%;font-size:12px;margin:10px 0}}
th{{background:rgba(99,102,241,0.12);padding:9px;text-align:left;border:1px solid rgba(255,255,255,0.06);color:#a5b4fc;font-weight:700}}
td{{padding:7px 9px;border:1px solid rgba(255,255,255,0.04)}}
tr:nth-child(even){{background:rgba(255,255,255,0.015)}}
.tag{{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}}
.t-c{{background:#ef4444}}.t-h{{background:#f97316}}.t-m{{background:#eab308;color:#000}}.t-l{{background:#22c55e}}.t-i{{background:#64748b}}
.vuln{{border-left:4px solid;padding:14px;margin:10px 0;border-radius:0 10px 10px 0;background:rgba(255,255,255,0.025)}}
.v-c{{border-color:#ef4444}}.v-h{{border-color:#f97316}}.v-m{{border-color:#eab308}}
#scene{{width:100%;height:500px;border-radius:14px;cursor:grab}}
#scene:active{{cursor:grabbing}}
.chart-box{{position:relative;height:380px}}
.chart-sm{{height:300px}}
.kc{{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:4px;margin:20px 0}}
.kc-n{{padding:10px 14px;border-radius:8px;color:#fff;font-weight:700;font-size:11px;text-align:center;min-width:100px;
  box-shadow:0 4px 20px rgba(0,0,0,0.3);transition:transform 0.3s,box-shadow 0.3s}}
.kc-n:hover{{transform:translateY(-4px) scale(1.06);box-shadow:0 8px 30px rgba(0,0,0,0.4)}}
.kc-a{{color:#475569;font-size:16px;margin:0 2px}}
.str{{border-left:3px solid #22c55e;background:rgba(34,197,94,0.06);padding:10px 14px;margin:5px 0;border-radius:0 8px 8px 0;font-size:12px}}
.wk{{border-left:3px solid #ef4444;background:rgba(239,68,68,0.06);padding:10px 14px;margin:5px 0;border-radius:0 8px 8px 0;font-size:12px}}
.mono{{font-family:Consolas,Monaco,monospace;font-size:11px}}
</style>
</head>
<body>
<div class="wrap">

<h1>3D WAF &amp; Firewall Security Assessment</h1>
<p class="sub">Target: <b style="color:#e2e8f0">kernernorland.com</b> &middot; {now} &middot; GoTestWAF ML Engine (F1=0.9333) &middot; MITRE ATT&CK v15 ({len(techniques)} techniques)</p>

<!-- ═══ SCORES ═══ -->
<h2>Security Scores</h2>
<div class="metrics">
 <div class="m glow"><div class="mv">74.8%</div><div class="ml">Overall Score</div></div>
 <div class="m glow"><div class="mv">99.3%</div><div class="ml">Attack Detection</div></div>
 <div class="m glow"><div class="mv">668</div><div class="ml">Attacks Blocked</div></div>
 <div class="m glow"><div class="mv">5</div><div class="ml">Bypasses</div></div>
 <div class="m glow"><div class="mv">0.93</div><div class="ml">ML F1 Score</div></div>
 <div class="m glow"><div class="mv">816</div><div class="ml">Total Payloads</div></div>
</div>

<!-- ═══ 3D SCENE ═══ -->
<h2>3D Attack Surface</h2>
<div class="card glow">
 <div id="scene"></div>
 <p style="font-size:11px;color:#475569;text-align:center;margin-top:8px">Drag to rotate &middot; Scroll to zoom &middot; Sphere size=volume, Green=blocked, Red=bypassed</p>
</div>

<!-- ═══ KILL CHAIN ═══ -->
<h2>Cyber Kill Chain</h2>
<div class="card glow">
 <div class="kc">'''

for i, (phase, color) in enumerate(zip(kc_phases, kc_colors)):
    d = kc_data.get(phase, {"t": 0, "b": 0})
    pct = d["b"] / d["t"] * 100 if d["t"] > 0 else 0
    op = "1" if d["t"] > 0 else "0.3"
    report += f'<div class="kc-n" style="background:{color};opacity:{op}">{phase}<br><small>{d["b"]}/{d["t"]} ({pct:.0f}%)</small></div>'
    if i < len(kc_phases) - 1:
        report += '<span class="kc-a">&#9654;</span>'

report += f'''</div>
 <div class="chart-box chart-sm"><canvas id="kcChart"></canvas></div>
</div>

<!-- ═══ MITRE HEATMAP ═══ -->
<h2>MITRE ATT&amp;CK Detection</h2>
<div class="card glow">
 <div class="chart-box"><canvas id="mitreChart"></canvas></div>
</div>

<!-- ═══ RADAR ═══ -->
<h2>Tactic Coverage Radar</h2>
<div class="card glow">
 <div class="chart-box chart-sm"><canvas id="radarChart"></canvas></div>
</div>

<!-- ═══ DOUGHNUT ═══ -->
<h2>Detection Distribution</h2>
<div class="card glow">
 <div class="chart-box chart-sm"><canvas id="doughChart"></canvas></div>
</div>

<!-- ═══ STRENGTHS & WEAKNESSES ═══ -->
<h2>Firewall Strengths</h2>
<div class="card">'''

for a in strengths:
    tn = techniques.get(a["mid"], {}).get("name", a["mid"])
    report += f'<div class="str"><b>{h.escape(a["a"])}</b> ({a["mid"]} {h.escape(tn[:40])}) &mdash; <span style="color:#22c55e">100% blocked</span> ({a["b"]}/{a["t"]})</div>'

report += '</div><h2>Firewall Weaknesses</h2><div class="card">'

if weaknesses:
    for a in weaknesses:
        pct = a["b"] / a["t"] * 100
        tn = techniques.get(a["mid"], {}).get("name", a["mid"])
        report += f'<div class="wk"><b>{h.escape(a["a"])}</b> ({a["mid"]} {h.escape(tn[:40])}) &mdash; <span style="color:#ef4444">{pct:.1f}% blocked, {a["t"]-a["b"]} bypassed</span></div>'
else:
    report += '<div class="str">No weaknesses detected in resolved attacks.</div>'

report += f'''</div>

<!-- ═══ ARCHITECTURE ═══ -->
<h2>Protection Architecture</h2>
<div class="card glow">
<svg width="100%" viewBox="0 0 820 130" style="display:block">
<defs><marker id="ar" markerWidth="6" markerHeight="6" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#475569"/></marker></defs>
<rect x="10" y="25" width="115" height="50" rx="10" fill="rgba(99,102,241,0.08)" stroke="#6366f1" stroke-width="1.5"/>
<text x="67" y="53" text-anchor="middle" font-size="11" font-weight="bold" fill="#818cf8">Internet</text>
<line x1="125" y1="50" x2="170" y2="50" stroke="#475569" stroke-width="1.5" marker-end="url(#ar)"/>
<rect x="175" y="25" width="115" height="50" rx="10" fill="rgba(99,102,241,0.08)" stroke="#3b82f6" stroke-width="1.5"/>
<text x="232" y="47" text-anchor="middle" font-size="10" font-weight="bold" fill="#60a5fa">Cloudflare</text>
<text x="232" y="62" text-anchor="middle" font-size="9" fill="#f97316">Forwards All</text>
<line x1="290" y1="50" x2="335" y2="50" stroke="#475569" stroke-width="1.5" marker-end="url(#ar)"/>
<rect x="340" y="25" width="115" height="50" rx="10" fill="rgba(249,115,22,0.08)" stroke="#f97316" stroke-width="1.5"/>
<text x="397" y="47" text-anchor="middle" font-size="10" font-weight="bold" fill="#fb923c">SG Captcha</text>
<text x="397" y="62" text-anchor="middle" font-size="9" fill="#ef4444">Bypassed 4s</text>
<line x1="455" y1="50" x2="500" y2="50" stroke="#475569" stroke-width="1.5" marker-end="url(#ar)"/>
<rect x="505" y="25" width="115" height="50" rx="10" fill="rgba(239,68,68,0.1)" stroke="#ef4444" stroke-width="2"/>
<text x="562" y="47" text-anchor="middle" font-size="10" font-weight="bold" fill="#f87171">Origin Server</text>
<text x="562" y="62" text-anchor="middle" font-size="9" fill="#ef4444">403 ALL</text>
<line x1="620" y1="50" x2="665" y2="50" stroke="#ef4444" stroke-width="1.5" stroke-dasharray="5,3"/>
<text x="643" y="42" text-anchor="middle" font-size="20" fill="#ef4444">&#10007;</text>
<rect x="670" y="25" width="115" height="50" rx="10" fill="rgba(255,255,255,0.02)" stroke="#334155" stroke-width="1" stroke-dasharray="4,2"/>
<text x="727" y="55" text-anchor="middle" font-size="10" fill="#475569">WordPress</text>
</svg>
</div>

<!-- ═══ VULNS ═══ -->
<h2>Vulnerabilities</h2>'''

vulns = [
    ("V-001","CRITICAL","c","SiteGround Bot Bypassed (4s)","sgcaptcha auto-solves by headless browser","Replace with Cloudflare Turnstile"),
    ("V-002","CRITICAL","c","Origin 403 on ALL Requests","Site inaccessible; 75KB identical 403 for every URL","Fix SiteGround settings / .htaccess / plugins"),
    ("V-003","HIGH","h","Cloudflare WAF Inactive","Forwards all without blocking","Enable Cloudflare WAF managed rules"),
    ("V-004","HIGH","h","3 RCE Bypasses","Raw HTTP request payloads evade detection","Add raw request inspection rules"),
    ("V-005","HIGH","h","2 User-Agent Bypasses","Header not inspected","Enable UA header inspection"),
    ("V-006","MEDIUM","m","AWS WAF Not Detected","No AWS signatures","Verify AWS WAF Web ACL config"),
]
for vid, sev, cls, title, desc, fix in vulns:
    tcls = "t-c" if cls == "c" else "t-h" if cls == "h" else "t-m"
    report += f'<div class="vuln v-{cls}"><b>{vid}</b> <span class="tag {tcls}">{sev}</span> <b>{h.escape(title)}</b><br>{h.escape(desc)}<br><b>Fix:</b> {h.escape(fix)}</div>'

# MITRE table
report += '<h2>MITRE Technique Coverage</h2><div class="card"><table><tr><th>Attack</th><th>MITRE</th><th>Technique</th><th>Tactic</th><th>Tested</th><th>Blocked</th><th>Rate</th></tr>'
for a in sorted(attacks, key=lambda x: x["b"]/x["t"]*100):
    pct = a["b"]/a["t"]*100
    tn = techniques.get(a["mid"],{}).get("name",a["mid"])[:35]
    tcls = "t-c" if pct < 90 else "t-h" if pct < 100 else "t-l"
    report += f'<tr><td><b>{h.escape(a["a"])}</b></td><td class="mono">{a["mid"]}</td><td>{h.escape(tn)}</td><td>{h.escape(a["tac"])}</td><td>{a["t"]}</td><td>{a["b"]}</td><td><span class="tag {tcls}">{pct:.1f}%</span></td></tr>'
report += '</table></div>'

report += f'''
<h2>Priority Actions</h2>
<div class="card"><ol style="padding-left:20px;font-size:13px">
<li><span class="tag t-c">P0</span> Fix origin 403 &mdash; site is down</li>
<li><span class="tag t-c">P0</span> Replace sgcaptcha &mdash; bypassed in 4 seconds</li>
<li><span class="tag t-h">P1</span> Enable Cloudflare WAF rules</li>
<li><span class="tag t-h">P1</span> Fix RCE + User-Agent bypasses</li>
<li><span class="tag t-m">P2</span> Verify AWS WAF</li>
</ol></div>

<p style="margin-top:40px;border-top:1px solid rgba(255,255,255,0.06);padding:12px;font-size:10px;color:#334155;text-align:center">
GoTestWAF ML Engine &middot; MITRE ATT&CK v15 ({len(techniques)} techniques) &middot; {now}</p>
</div>

<script>
// ═══════════════════════════════════════════
// THREE.JS 3D ATTACK SURFACE
// ═══════════════════════════════════════════
(function(){{
  const el = document.getElementById('scene');
  const W = el.clientWidth, H = el.clientHeight;

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x0b0f2a);
  scene.fog = new THREE.Fog(0x0b0f2a, 20, 40);

  const camera = new THREE.PerspectiveCamera(55, W/H, 0.1, 100);
  const renderer = new THREE.WebGLRenderer({{antialias:true}});
  renderer.setSize(W, H);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  el.appendChild(renderer.domElement);

  // Lights
  scene.add(new THREE.AmbientLight(0x6366f1, 0.5));
  const dl = new THREE.DirectionalLight(0xffffff, 0.8);
  dl.position.set(5, 10, 7);
  scene.add(dl);
  const pl = new THREE.PointLight(0xec4899, 0.5, 30);
  pl.position.set(-4, 6, -4);
  scene.add(pl);

  // Ground grid
  const grid = new THREE.GridHelper(24, 24, 0x1e293b, 0x1e293b);
  grid.position.y = -0.5;
  scene.add(grid);

  // Center pillar
  const pilG = new THREE.CylinderGeometry(0.15, 0.15, 7, 12);
  const pilM = new THREE.MeshPhongMaterial({{color:0x6366f1, transparent:true, opacity:0.25}});
  const pil = new THREE.Mesh(pilG, pilM);
  pil.position.y = 3;
  scene.add(pil);

  // Attack spheres
  const spheres = {json.dumps(sphere_data)};
  const meshes = [];
  spheres.forEach(s => {{
    const geo = new THREE.SphereGeometry(s.r, 24, 24);
    const mat = new THREE.MeshPhongMaterial({{color:parseInt(s.c), transparent:true, opacity:0.85, shininess:80}});
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.set(s.x, s.y, s.z);
    scene.add(mesh);
    meshes.push(mesh);

    // Ring
    const rg = new THREE.TorusGeometry(s.r*1.4, 0.03, 8, 32);
    const rm = new THREE.MeshBasicMaterial({{color:parseInt(s.c), transparent:true, opacity:0.25}});
    const ring = new THREE.Mesh(rg, rm);
    ring.position.copy(mesh.position);
    ring.rotation.x = Math.PI/2;
    scene.add(ring);

    // Vertical line to ground
    const lg = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(s.x, -0.5, s.z),
      new THREE.Vector3(s.x, s.y - s.r, s.z)
    ]);
    const lm = new THREE.LineBasicMaterial({{color:parseInt(s.c), transparent:true, opacity:0.15}});
    scene.add(new THREE.Line(lg, lm));
  }});

  // Camera orbit
  let angle = 0, camDist = 16, camHeight = 8;
  let dragging = false, lastX = 0, lastY = 0;

  el.addEventListener('mousedown', e => {{ dragging = true; lastX = e.clientX; lastY = e.clientY; }});
  el.addEventListener('mousemove', e => {{
    if (!dragging) return;
    angle += (e.clientX - lastX) * 0.008;
    camHeight += (e.clientY - lastY) * 0.04;
    camHeight = Math.max(2, Math.min(18, camHeight));
    lastX = e.clientX; lastY = e.clientY;
  }});
  el.addEventListener('mouseup', () => dragging = false);
  el.addEventListener('mouseleave', () => dragging = false);
  el.addEventListener('wheel', e => {{
    camDist += e.deltaY * 0.015;
    camDist = Math.max(6, Math.min(30, camDist));
  }});

  // Touch
  el.addEventListener('touchstart', e => {{ dragging = true; lastX = e.touches[0].clientX; lastY = e.touches[0].clientY; }});
  el.addEventListener('touchmove', e => {{
    if (!dragging) return;
    angle += (e.touches[0].clientX - lastX) * 0.008;
    camHeight += (e.touches[0].clientY - lastY) * 0.04;
    camHeight = Math.max(2, Math.min(18, camHeight));
    lastX = e.touches[0].clientX; lastY = e.touches[0].clientY;
  }});
  el.addEventListener('touchend', () => dragging = false);

  function animate() {{
    requestAnimationFrame(animate);
    if (!dragging) angle += 0.004;

    camera.position.x = Math.sin(angle) * camDist;
    camera.position.z = Math.cos(angle) * camDist;
    camera.position.y = camHeight;
    camera.lookAt(0, 2, 0);

    // Pulse
    const t = Date.now() * 0.001;
    meshes.forEach((m, i) => {{
      m.scale.setScalar(1 + Math.sin(t * 2 + i) * 0.04);
    }});

    renderer.render(scene, camera);
  }}
  animate();

  window.addEventListener('resize', () => {{
    const w = el.clientWidth, hh = el.clientHeight;
    camera.aspect = w / hh;
    camera.updateProjectionMatrix();
    renderer.setSize(w, hh);
  }});
}})();

// ═══════════════════════════════════════════
// CHART.JS CHARTS
// ═══════════════════════════════════════════
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';

// Kill chain
new Chart(document.getElementById('kcChart'), {{
  type:'bar',
  data:{{
    labels:{json.dumps(kc_phases)},
    datasets:[
      {{label:'Blocked',data:{json.dumps([kc_data[p]["b"] for p in kc_phases])},backgroundColor:{json.dumps(kc_colors)},borderRadius:6}},
      {{label:'Bypassed',data:{json.dumps([kc_data[p]["t"]-kc_data[p]["b"] for p in kc_phases])},backgroundColor:'rgba(239,68,68,0.7)',borderRadius:6}}
    ]
  }},
  options:{{responsive:true,maintainAspectRatio:false,plugins:{{title:{{display:true,text:'Cyber Kill Chain Detection',color:'#a5b4fc',font:{{size:14}}}}}},scales:{{y:{{stacked:true,grid:{{color:'rgba(255,255,255,0.03)'}}}},x:{{stacked:true,grid:{{display:false}}}}}}}}
}});

// MITRE
new Chart(document.getElementById('mitreChart'), {{
  type:'bar',
  data:{{
    labels:{json.dumps([a["a"] for a in attacks])},
    datasets:[
      {{label:'Blocked',data:{json.dumps([a["b"] for a in attacks])},backgroundColor:'rgba(34,197,94,0.7)',borderRadius:4}},
      {{label:'Bypassed',data:{json.dumps([a["t"]-a["b"] for a in attacks])},backgroundColor:'rgba(239,68,68,0.8)',borderRadius:4}}
    ]
  }},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{title:{{display:true,text:'MITRE ATT&CK Detection by Technique',color:'#a5b4fc',font:{{size:14}}}}}},scales:{{x:{{stacked:true,grid:{{color:'rgba(255,255,255,0.03)'}}}},y:{{stacked:true,grid:{{display:false}}}}}}}}
}});

// Radar
new Chart(document.getElementById('radarChart'), {{
  type:'radar',
  data:{{
    labels:{json.dumps(list(tac_data.keys()))},
    datasets:[{{
      label:'Detection %',
      data:{json.dumps([round(v["b"]/v["t"]*100,1) for v in tac_data.values()])},
      backgroundColor:'rgba(99,102,241,0.15)',
      borderColor:'#818cf8',borderWidth:2,
      pointBackgroundColor:'#f472b6',pointBorderColor:'#fff',pointRadius:5,pointHoverRadius:8
    }}]
  }},
  options:{{responsive:true,maintainAspectRatio:false,scales:{{r:{{min:0,max:100,ticks:{{stepSize:25,color:'#475569',backdropColor:'transparent'}},grid:{{color:'rgba(255,255,255,0.04)'}},pointLabels:{{color:'#94a3b8',font:{{size:11}}}}}}}},plugins:{{title:{{display:true,text:'MITRE Tactic Coverage',color:'#a5b4fc',font:{{size:14}}}}}}}}
}});

// Doughnut
new Chart(document.getElementById('doughChart'), {{
  type:'doughnut',
  data:{{
    labels:['Blocked (668)','Bypassed (5)','Unresolved (2)'],
    datasets:[{{data:[668,5,2],backgroundColor:['#22c55e','#ef4444','#eab308'],borderColor:'#0b0f2a',borderWidth:4,hoverOffset:15}}]
  }},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'55%',plugins:{{title:{{display:true,text:'Detection Distribution',color:'#a5b4fc',font:{{size:14}}}},legend:{{labels:{{color:'#94a3b8',padding:16}}}}}}}}
}});
</script>
</body></html>'''

path = Path("reports/kernernorland-3d-assessment.html")
path.parent.mkdir(exist_ok=True)
path.write_text(report, encoding="utf-8")
print(f"Report: {path} ({path.stat().st_size:,} bytes)")
import webbrowser
webbrowser.open(path.resolve().as_uri())
print("Opened")
