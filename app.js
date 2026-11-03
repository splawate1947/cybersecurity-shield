/**
 * AutoShield-EV: Autonomous Electric Vehicle Cybersecurity Operations & Simulation Suite
 * Conforming to UNECE WP.29 R155/R156 & ISO/SAE 21434 Cybersecurity Engineering
 */

// ============================================================================
// 1. Global State
// ============================================================================
const state = {
  activeTab: 'cockpit',
  adsMode: 'AUTOPILOT (L3+)',
  speed: 72, // km/h
  batterySoC: 78, // %
  batteryTemp: 31.8, // °C
  secocRate: 99.98, // %
  busLoad: 42.4, // %
  postureScore: 96,
  autoMitigate: true,
  mrmTriggered: false,
  gatewayIsolated: false,
  radarFallback: false,
  hvDisconnected: false,
  
  // Threat Scenarios
  threats: [
    {
      id: 'attack-sign-patch',
      name: 'Adversarial Optical Patch on Speed Limit Sign',
      layer: 'Perception (Camera / Vision DNN)',
      sev: 'high',
      active: false,
      desc: 'Adversarial perturbation sticker on 40 km/h sign causes ResNet classifier to mispredict 100 km/h, risking severe overspeed.',
      impact: 'Spurious acceleration request; potential collision in urban zone.',
      countermeasure: 'Spatial Gradient Entropy Filter & HD Map speed-limit cross-check.'
    },
    {
      id: 'attack-phantom-laser',
      name: 'Phantom Obstacle Optical Injection (Laser Blinding)',
      layer: 'Perception (Cameras / LiDAR)',
      sev: 'critical',
      active: false,
      desc: 'High-power modulated laser beams project synthetic obstacle signatures into front CMOS sensor, inducing false detection.',
      impact: 'Triggers dangerous Phantom Braking (-1.2g deceleration on open highway).',
      countermeasure: 'Radar-LiDAR Spatial Plausibility Arbiter (rejection of zero-radar returns).'
    },
    {
      id: 'attack-can-steering',
      name: 'CAN-FD Bus Frame Injection: Steering Angle Override',
      layer: 'In-Vehicle Network (CAN-CHASSIS 0x0C4)',
      sev: 'critical',
      active: false,
      desc: 'Compromised gateway sends unauthenticated steering torque frames (0x0C4) requesting +35° abrupt lane departure.',
      impact: 'Physical steering deviation into oncoming traffic without driver initiation.',
      countermeasure: 'AUTOSAR SecOC freshness token validation and CMAC-AES128 drop.'
    },
    {
      id: 'attack-bms-overvoltage',
      name: 'BMS Fast-Charging Overvoltage Exploit',
      layer: 'EV Powertrain & BMS Controller',
      sev: 'critical',
      active: false,
      desc: 'Manipulates CAN-PT telemetry to report 3.80V when actual cell voltage reaches 4.38V, bypassing CC/CV cutoff.',
      impact: 'Lithium dendrite growth, internal separator rupture, and catastrophic thermal runaway.',
      countermeasure: 'Analog hardware voltage clamps + pyrotechnic isolation trip.'
    },
    {
      id: 'attack-iso-15118-mitm',
      name: 'ISO 15118 EVSE Man-in-the-Middle & Surge Attack',
      layer: 'V2G Charging Interface (PLC / HomePlug GreenPHY)',
      sev: 'high',
      active: false,
      desc: 'Malicious charging pile injects forged SECC certificate and commands abrupt 350kW current pulses to strain grid and inverter.',
      impact: 'Damage to on-board DC-DC converter and electrical distribution infrastructure.',
      countermeasure: 'Strict OEM Root-CA certificate pinning & mTLS TLS 1.3 handshake verification.'
    },
    {
      id: 'attack-gnss-spoof',
      name: 'GNSS / GPS L1/L5 Coordinate Spoofing',
      layer: 'Localization & V2X RF Stack',
      sev: 'high',
      active: false,
      desc: 'RF signal simulator transmits higher-power spoofed GPS ephemeris, shifting perceived vehicle location by 120m.',
      impact: 'Navigation trajectory desynchronization and incorrect geofence trigger.',
      countermeasure: 'Multi-constellation RTK carrier-phase tracking + IMU dead reckoning correlation.'
    },
    {
      id: 'attack-ota-tamper',
      name: 'Rogue Telematics OTA Firmware Injection',
      layer: 'Cloud & Telematics Control Unit (TCU)',
      sev: 'critical',
      active: false,
      desc: 'Stolen supplier API key used to push unauthorized firmware binary to braking gateway without OEM private key signature.',
      impact: 'Permanent actuator compromise and loss of safety interlocks.',
      countermeasure: 'Uptane / The Update Framework (TUF) threshold signature enforcement.'
    },
    {
      id: 'attack-sonar-jam',
      name: 'Ultrasonic Acoustic Jamming (Blind-Spot Blindness)',
      layer: 'Near-Field USS Sensors (40 kHz)',
      sev: 'high',
      active: false,
      desc: 'Piezoelectric emitter blasts ultrasonic noise resonant at 40 kHz, suppressing echo returns from pedestrians and low barriers.',
      impact: 'Blind-spot detection failure during lane change and parking maneuvers.',
      countermeasure: 'Frequency-hopping chirps & 360° surround camera optical flow backup.'
    }
  ],

  // In-Vehicle CAN-FD Frames Buffer
  canFrames: [],
  canPaused: false,
  defendedCount: 0,

  // Sensor Fusion Objects
  detectedObjects: [
    { id: 'OBJ-101', class: 'Lead Vehicle (Sedan)', camConf: '98.5%', radarDist: '48.2m', lidarPts: 1420, status: 'VERIFIED', action: 'Adaptive Cruise Follow' },
    { id: 'OBJ-102', class: 'Right Lane Vehicle (SUV)', camConf: '94.2%', radarDist: '32.1m', lidarPts: 890, status: 'VERIFIED', action: 'Blind Spot Track' },
    { id: 'OBJ-103', class: 'Speed Limit Sign (40 km/h)', camConf: '96.1%', radarDist: 'N/A', lidarPts: 180, status: 'VERIFIED', action: 'Speed Limit 40 km/h' }
  ],

  // 16 Battery Cells (Nominal 3.85V)
  cells: Array(16).fill(0).map((_, i) => ({ id: `C${i + 1}`, v: 3.85, temp: 31.5 })),

  // Audit Log Entries
  auditLogs: []
};

// ============================================================================
// 2. Initialization & Event Handlers
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initAttackConsole();
  initHUDCanvas();
  initTopologyCanvas();
  initCANSniffer();
  initBMSView();
  initAuditLogs();
  initButtons();

  // Background Telemetry Simulation Loop (100ms)
  setInterval(simulateTelemetry, 250);
  // CAN Bus Feed Generator Loop (150ms)
  setInterval(generateCANStream, 180);
});

// Navigation Tabs
function initNavigation() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-tab');
      switchTab(target);
    });
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.nav-tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
  });
  document.querySelectorAll('.tab-pane').forEach(p => {
    p.classList.toggle('active', p.id === `pane-${tabId}`);
  });

  if (tabId === 'cockpit') renderHUD();
  if (tabId === 'topology') renderTopology();
}

// ============================================================================
// 3. Attack Injector & Active Defense Logic
// ============================================================================
function initAttackConsole() {
  const container = document.getElementById('attack-cards-container');
  if (!container) return;

  container.innerHTML = state.threats.map(t => `
    <div class="attack-item-card ${t.active ? 'active-attack' : ''}" id="card-${t.id}">
      <div class="attack-header">
        <div class="attack-title">
          <span class="sev-badge ${t.sev}">${t.sev.toUpperCase()}</span>
          <strong>${t.name}</strong>
        </div>
        <span class="status-tag ${t.active ? 'status-spoofed' : 'status-secure'}" id="tag-${t.id}">
          ${t.active ? 'ATTACKING' : 'IDLE'}
        </span>
      </div>
      <p class="attack-desc">${t.desc}</p>
      <div class="attack-meta">
        <span class="target-layer">🎯 Target: ${t.layer}</span>
        <div class="attack-actions">
          <button class="btn btn-sm ${t.active ? 'btn-danger' : 'btn-warning'}" onclick="toggleAttack('${t.id}')">
            ${t.active ? 'Stop Injection' : 'Inject Attack'}
          </button>
          <button class="btn btn-sm btn-outline" onclick="mitigateAttack('${t.id}')">
            Deploy Countermeasure
          </button>
        </div>
      </div>
    </div>
  `).join('');

  updateThreatCounts();
}

window.toggleAttack = function(attackId) {
  const attack = state.threats.find(t => t.id === attackId);
  if (!attack) return;

  attack.active = !attack.active;
  
  if (attack.active) {
    addAuditLog('WARNING', attack.layer, `[RED TEAM INJECTION] ${attack.name} triggered.`, generateHash(attack.name));
    
    // Automatic AI Mitigation trigger if enabled
    if (state.autoMitigate) {
      setTimeout(() => {
        if (attack.active) {
          mitigateAttack(attackId, true);
        }
      }, 1200);
    }
  } else {
    addAuditLog('INFO', attack.layer, `Attack injection ceased: ${attack.name}`, generateHash(attack.name));
  }

  evaluateSystemState();
  initAttackConsole();
};

window.mitigateAttack = function(attackId, wasAuto = false) {
  const attack = state.threats.find(t => t.id === attackId);
  if (!attack) return;

  attack.active = false;
  state.defendedCount++;

  addAuditLog(
    'SEC_ALERT', 
    attack.layer, 
    `${wasAuto ? '[AUTONOMOUS IDS/IPS]' : '[MANUAL OPERATOR]'} Mitigated: ${attack.countermeasure}`, 
    generateHash(attack.countermeasure)
  );

  evaluateSystemState();
  initAttackConsole();
};

function evaluateSystemState() {
  const activeAttacks = state.threats.filter(t => t.active);
  const activeCount = activeAttacks.length;

  // Calculate Posture Score
  let score = 96;
  activeAttacks.forEach(a => {
    score -= (a.sev === 'critical' ? 22 : 12);
  });
  state.postureScore = Math.max(12, score);

  // Update Badges & Ribbon
  const postureBar = document.getElementById('posture-bar');
  const postureScoreEl = document.getElementById('posture-score');
  if (postureBar && postureScoreEl) {
    postureBar.style.width = `${state.postureScore}%`;
    postureScoreEl.textContent = `${state.postureScore}%`;
    if (state.postureScore < 60) {
      postureBar.style.background = 'var(--accent-danger)';
    } else if (state.postureScore < 85) {
      postureBar.style.background = 'var(--accent-warning)';
    } else {
      postureBar.style.background = 'var(--accent-green)';
    }
  }

  // Update active threats badge
  const threatBadge = document.getElementById('active-threats-badge');
  const threatPill = document.getElementById('active-threat-count-pill');
  if (threatBadge) {
    threatBadge.textContent = `${activeCount} THREAT${activeCount === 1 ? '' : 'S'} ACTIVE`;
  }
  if (threatPill) {
    threatPill.style.display = activeCount > 0 ? 'flex' : 'none';
  }

  // Check for critical impact on HUD
  const hudBanner = document.getElementById('hud-alert-banner');
  const hudAlertText = document.getElementById('hud-alert-text');
  
  if (activeAttacks.some(t => t.id === 'attack-phantom-laser')) {
    hudBanner?.classList.remove('hidden');
    if (hudAlertText) hudAlertText.textContent = 'CRITICAL: CAMERA DETECTS PHANTOM OBSTACLE (UNCONFIRMED BY 4D RADAR) - FILTERED';
    document.getElementById('sensor-front-cam')?.querySelector('.status-tag')?.classList.replace('status-secure', 'status-spoofed');
  } else if (activeAttacks.some(t => t.id === 'attack-sign-patch')) {
    hudBanner?.classList.remove('hidden');
    if (hudAlertText) hudAlertText.textContent = 'WARNING: ADVERSARIAL PERTURBATION DETECTED ON SPEED SIGN - HIGH SPATIAL ENTROPY';
  } else {
    hudBanner?.classList.add('hidden');
    document.getElementById('sensor-front-cam')?.querySelector('.status-tag')?.classList.replace('status-spoofed', 'status-secure');
  }

  // Handle BMS Overvoltage
  const isBmsAttack = activeAttacks.some(t => t.id === 'attack-bms-overvoltage');
  if (isBmsAttack) {
    state.batteryTemp = 58.4;
    state.cells[3].v = 4.38;
    state.cells[3].temp = 59.2;
    document.getElementById('bms-pack-status-badge')?.classList.replace('ok', 'danger');
    if (document.getElementById('bms-pack-status-badge')) {
      document.getElementById('bms-pack-status-badge').textContent = 'OVERVOLTAGE DETECTED - CONTACTORS ARMED';
    }
  } else {
    state.batteryTemp = 31.8;
    state.cells[3].v = 3.86;
    state.cells[3].temp = 32.1;
    document.getElementById('bms-pack-status-badge')?.classList.replace('danger', 'ok');
    if (document.getElementById('bms-pack-status-badge')) {
      document.getElementById('bms-pack-status-badge').textContent = 'BALANCED & MONITORED';
    }
  }

  updateThreatCounts();
  updateFusionTable();
}

function updateThreatCounts() {
  const activeCount = state.threats.filter(t => t.active).length;
  const defendedEl = document.getElementById('defended-attacks-count');
  const activeEl = document.getElementById('active-incidents-count');
  const sidebarBadge = document.getElementById('sidebar-threat-badge');
  
  if (defendedEl) defendedEl.textContent = state.defendedCount;
  if (activeEl) activeEl.textContent = activeCount;
  if (sidebarBadge) sidebarBadge.textContent = activeCount > 0 ? activeCount : '8';
}

// ============================================================================
// 4. Autonomous Perception HUD Canvas (60 FPS)
// ============================================================================
let hudCanvas, hudCtx;
let roadOffset = 0;

function initHUDCanvas() {
  hudCanvas = document.getElementById('canvas-hud');
  if (!hudCanvas) return;
  hudCtx = hudCanvas.getContext('2d');
  requestAnimationFrame(renderHUDLoop);
}

function renderHUDLoop() {
  if (state.activeTab === 'cockpit') {
    renderHUD();
  }
  requestAnimationFrame(renderHUDLoop);
}

function renderHUD() {
  if (!hudCtx || !hudCanvas) return;
  const w = hudCanvas.width;
  const h = hudCanvas.height;

  // Clear background
  hudCtx.fillStyle = '#060a12';
  hudCtx.fillRect(0, 0, w, h);

  // Road Perspective & Vanishing Point
  const vpX = w / 2;
  const vpY = 140;

  roadOffset = (roadOffset + (state.speed * 0.08)) % 40;

  // Draw Sky / Horizon Grid
  hudCtx.strokeStyle = 'rgba(0, 119, 254, 0.12)';
  hudCtx.lineWidth = 1;
  for (let y = 30; y < vpY; y += 20) {
    hudCtx.beginPath();
    hudCtx.moveTo(0, y);
    hudCtx.lineTo(w, y);
    hudCtx.stroke();
  }

  // Draw Road Surface
  hudCtx.fillStyle = '#09101d';
  hudCtx.beginPath();
  hudCtx.moveTo(vpX - 60, vpY);
  hudCtx.lineTo(vpX + 60, vpY);
  hudCtx.lineTo(w - 80, h);
  hudCtx.lineTo(80, h);
  hudCtx.closePath();
  hudCtx.fill();

  // Lane Boundaries (Cyan / Blue Neon)
  hudCtx.strokeStyle = 'rgba(0, 229, 255, 0.8)';
  hudCtx.lineWidth = 3;
  hudCtx.shadowColor = 'rgba(0, 229, 255, 0.6)';
  hudCtx.shadowBlur = 10;

  // Left Lane
  hudCtx.beginPath();
  hudCtx.moveTo(vpX - 60, vpY);
  hudCtx.lineTo(80, h);
  hudCtx.stroke();

  // Right Lane
  hudCtx.beginPath();
  hudCtx.moveTo(vpX + 60, vpY);
  hudCtx.lineTo(w - 80, h);
  hudCtx.stroke();

  // Dashed Center Lanes (Animated Forward Motion)
  hudCtx.shadowBlur = 4;
  hudCtx.strokeStyle = 'rgba(255, 255, 255, 0.6)';
  hudCtx.lineWidth = 2;

  const leftLaneCenterStartX = vpX - 25;
  const leftLaneCenterEndX = w / 2 - 130;
  const rightLaneCenterStartX = vpX + 25;
  const rightLaneCenterEndX = w / 2 + 130;

  for (let i = roadOffset; i < h - vpY; i += 40) {
    const progress = i / (h - vpY);
    const currY = vpY + (progress * (h - vpY));
    const leftX = vpX - (60 * (1 - progress)) - ((w / 2 - 80) * progress * 0.45);
    const rightX = vpX + (60 * (1 - progress)) + ((w / 2 - 80) * progress * 0.45);

    // Left divider dash
    hudCtx.beginPath();
    hudCtx.moveTo(leftX, currY);
    hudCtx.lineTo(leftX - (progress * 10), currY + 14);
    hudCtx.stroke();

    // Right divider dash
    hudCtx.beginPath();
    hudCtx.moveTo(rightX, currY);
    hudCtx.lineTo(rightX + (progress * 10), currY + 14);
    hudCtx.stroke();
  }

  hudCtx.shadowBlur = 0;

  // Sensor Coverage Cones (LiDAR & Radar)
  const showLidar = document.getElementById('toggle-lidar-cloud')?.checked;
  const showRadar = document.getElementById('toggle-radar-tracks')?.checked;

  if (showRadar) {
    // 4D Imaging Radar Fan Arc
    hudCtx.fillStyle = 'rgba(0, 240, 118, 0.05)';
    hudCtx.beginPath();
    hudCtx.moveTo(w / 2, h - 20);
    hudCtx.arc(w / 2, h - 20, 360, -Math.PI * 0.8, -Math.PI * 0.2);
    hudCtx.closePath();
    hudCtx.fill();
    hudCtx.strokeStyle = 'rgba(0, 240, 118, 0.25)';
    hudCtx.stroke();
  }

  if (showLidar) {
    // LiDAR Raycast Points
    hudCtx.fillStyle = 'rgba(0, 229, 255, 0.6)';
    for (let p = 0; p < 35; p++) {
      const rx = (Math.sin(p * 1.5 + roadOffset * 0.05) * 220) + (w / 2);
      const ry = 220 + (p * 7);
      hudCtx.fillRect(rx, ry, 2, 2);
    }
  }

  // Draw Lead Vehicle (Actual Car on Road)
  drawDetectedCar(w / 2, 260, 110, 65, 'Lead Vehicle [48m]', '98.5%', false);

  // Check if Phantom Obstacle Attack is Active
  const phantomAttack = state.threats.find(t => t.id === 'attack-phantom-laser' && t.active);
  if (phantomAttack) {
    drawDetectedCar(w / 2 + 100, 310, 130, 80, 'SPOOFED PHANTOM [Laser]', '0% (RADAR DROP)', true);
  }

  // Draw Ego Vehicle Hood at Bottom Center
  drawEgoHood(w / 2, h);

  // Speed Limit Sign with Adversarial Detection
  drawSpeedSign(w - 180, 160);
}

function drawDetectedCar(x, y, width, height, label, conf, isThreat) {
  hudCtx.save();
  hudCtx.translate(x - width / 2, y);

  // 3D Bounding Box
  hudCtx.strokeStyle = isThreat ? 'var(--accent-danger)' : 'var(--accent-cyan)';
  hudCtx.lineWidth = 2;
  hudCtx.strokeRect(0, 0, width, height);

  // Corner Accents
  hudCtx.fillStyle = isThreat ? '#ff3366' : '#00e5ff';
  const cSize = 6;
  hudCtx.fillRect(0, 0, cSize, 2);
  hudCtx.fillRect(0, 0, 2, cSize);
  hudCtx.fillRect(width - cSize, 0, cSize, 2);
  hudCtx.fillRect(width - 2, 0, 2, cSize);

  // Ground Distance Marker Line
  hudCtx.strokeStyle = isThreat ? 'rgba(255, 51, 102, 0.4)' : 'rgba(0, 229, 255, 0.4)';
  hudCtx.setLineDash([4, 4]);
  hudCtx.beginPath();
  hudCtx.moveTo(width / 2, height);
  hudCtx.lineTo(width / 2, height + 25);
  hudCtx.stroke();
  hudCtx.setLineDash([]);

  // Label Card
  hudCtx.fillStyle = 'rgba(10, 14, 23, 0.85)';
  hudCtx.fillRect(0, -22, width, 18);
  hudCtx.font = '10px "JetBrains Mono", monospace';
  hudCtx.fillStyle = isThreat ? '#ff3366' : '#00f076';
  hudCtx.fillText(`${label}`, 4, -8);

  hudCtx.restore();
}

function drawEgoHood(cx, cy) {
  hudCtx.save();
  hudCtx.fillStyle = '#0f172a';
  hudCtx.strokeStyle = 'rgba(0, 229, 255, 0.3)';
  hudCtx.lineWidth = 2;

  hudCtx.beginPath();
  hudCtx.moveTo(cx - 160, cy);
  hudCtx.quadraticCurveTo(cx, cy - 60, cx + 160, cy);
  hudCtx.lineTo(cx + 200, cy);
  hudCtx.lineTo(cx - 200, cy);
  hudCtx.closePath();
  hudCtx.fill();
  hudCtx.stroke();

  // Center Cockpit Crosshair
  hudCtx.strokeStyle = 'rgba(0, 240, 118, 0.6)';
  hudCtx.beginPath();
  hudCtx.moveTo(cx - 12, cy - 70);
  hudCtx.lineTo(cx + 12, cy - 70);
  hudCtx.moveTo(cx, cy - 82);
  hudCtx.lineTo(cx, cy - 58);
  hudCtx.stroke();

  hudCtx.restore();
}

function drawSpeedSign(x, y) {
  const isPatched = state.threats.find(t => t.id === 'attack-sign-patch' && t.active);

  hudCtx.save();
  hudCtx.translate(x, y);

  // Sign Pole
  hudCtx.fillStyle = '#475569';
  hudCtx.fillRect(22, 50, 6, 80);

  // Circular Sign
  hudCtx.beginPath();
  hudCtx.arc(25, 25, 28, 0, Math.PI * 2);
  hudCtx.fillStyle = '#f8fafc';
  hudCtx.fill();
  hudCtx.lineWidth = 6;
  hudCtx.strokeStyle = isPatched ? '#ff3366' : '#dc2626';
  hudCtx.stroke();

  // Sign Text (40 vs 100)
  hudCtx.fillStyle = '#0f172a';
  hudCtx.font = 'bold 18px "Outfit", sans-serif';
  hudCtx.textAlign = 'center';
  hudCtx.fillText(isPatched ? '100' : '40', 25, 31);

  if (isPatched) {
    // Adversarial Patch Sticker
    hudCtx.fillStyle = '#ffb703';
    hudCtx.fillRect(12, 10, 8, 8);
    hudCtx.fillStyle = '#ff3366';
    hudCtx.fillRect(28, 28, 6, 6);

    // Bounding Box
    hudCtx.strokeStyle = '#ff3366';
    hudCtx.lineWidth = 1;
    hudCtx.strokeRect(-10, -10, 70, 70);
    hudCtx.font = '9px "JetBrains Mono", monospace';
    hudCtx.fillStyle = '#ff3366';
    hudCtx.fillText('ADV-PATCH DETECTED', 25, -16);
  }

  hudCtx.restore();
}

// ============================================================================
// 5. In-Vehicle ECU Topology Canvas
// ============================================================================
let topoCanvas, topoCtx;
const ecus = [
  { id: 'CGW', name: 'Central Gateway (CGW)', x: 510, y: 150, domain: 'GATEWAY', status: 'secure' },
  { id: 'ADAS', name: 'Autopilot Domain (ADAS)', x: 260, y: 80, domain: 'COMPUTE', status: 'secure' },
  { id: 'TCU', name: 'Telematics / V2X (TCU)', x: 760, y: 80, domain: 'CONNECTIVITY', status: 'secure' },
  { id: 'EPS', name: 'Electronic Power Steering', x: 200, y: 320, domain: 'CHASSIS', status: 'secure' },
  { id: 'ESC', name: 'Brakes & Stability (iBooster)', x: 400, y: 320, domain: 'CHASSIS', status: 'secure' },
  { id: 'BMS', name: 'Battery Management (BMS)', x: 620, y: 320, domain: 'POWERTRAIN', status: 'secure' },
  { id: 'INV', name: 'Electric Inverter & Motor', x: 820, y: 320, domain: 'POWERTRAIN', status: 'secure' },
  { id: 'IVI', name: 'Infotainment (Android Auto)', x: 510, y: 440, domain: 'MEDIA', status: 'secure' }
];

function initTopologyCanvas() {
  topoCanvas = document.getElementById('canvas-topology');
  if (!topoCanvas) return;
  topoCtx = topoCanvas.getContext('2d');
  renderTopology();
}

function renderTopology() {
  if (!topoCtx || !topoCanvas) return;
  const w = topoCanvas.width;
  const h = topoCanvas.height;

  topoCtx.fillStyle = '#080d18';
  topoCtx.fillRect(0, 0, w, h);

  const cgw = ecus.find(e => e.id === 'CGW');

  // Check which attacks affect which ECUs
  const steeringAttack = state.threats.find(t => t.id === 'attack-can-steering' && t.active);
  const bmsAttack = state.threats.find(t => t.id === 'attack-bms-overvoltage' && t.active);
  const otaAttack = state.threats.find(t => t.id === 'attack-ota-tamper' && t.active);

  // Draw Bus Connections
  ecus.forEach(e => {
    if (e.id === 'CGW') return;
    
    topoCtx.beginPath();
    topoCtx.moveTo(cgw.x, cgw.y);
    topoCtx.lineTo(e.x, e.y);

    let isLinkCompromised = false;
    if (e.id === 'EPS' && steeringAttack) isLinkCompromised = true;
    if (e.id === 'BMS' && bmsAttack) isLinkCompromised = true;
    if (e.id === 'TCU' && otaAttack) isLinkCompromised = true;

    topoCtx.lineWidth = isLinkCompromised ? 3 : 2;
    topoCtx.strokeStyle = isLinkCompromised ? 'rgba(255, 51, 102, 0.8)' : 'rgba(0, 229, 255, 0.3)';
    topoCtx.stroke();

    // Animated data burst packet
    const t = (Date.now() * 0.002) % 1;
    const px = cgw.x + (e.x - cgw.x) * t;
    const py = cgw.y + (e.y - cgw.y) * t;

    topoCtx.fillStyle = isLinkCompromised ? '#ff3366' : '#00f076';
    topoCtx.beginPath();
    topoCtx.arc(px, py, 4, 0, Math.PI * 2);
    topoCtx.fill();
  });

  // Draw ECU Nodes
  ecus.forEach(e => {
    let nodeStatus = 'secure';
    if (e.id === 'EPS' && steeringAttack) nodeStatus = 'targeted';
    if (e.id === 'BMS' && bmsAttack) nodeStatus = 'targeted';
    if (e.id === 'TCU' && otaAttack) nodeStatus = 'targeted';
    if (state.gatewayIsolated && (e.id === 'IVI' || e.id === 'TCU')) nodeStatus = 'isolated';

    // Outer Circle / Box
    const boxW = 140;
    const boxH = 54;
    const bx = e.x - boxW / 2;
    const by = e.y - boxH / 2;

    topoCtx.fillStyle = nodeStatus === 'targeted' ? 'rgba(255, 51, 102, 0.15)' : '#101726';
    topoCtx.fillRect(bx, by, boxW, boxH);

    topoCtx.strokeStyle = nodeStatus === 'targeted' ? '#ff3366' : (nodeStatus === 'isolated' ? '#ffb703' : '#22324f');
    topoCtx.lineWidth = 2;
    topoCtx.strokeRect(bx, by, boxW, boxH);

    // Label
    topoCtx.fillStyle = '#f0f4fc';
    topoCtx.font = 'bold 11px "Outfit", sans-serif';
    topoCtx.textAlign = 'center';
    topoCtx.fillText(e.id, e.x, e.y - 6);

    topoCtx.font = '9px "JetBrains Mono", monospace';
    topoCtx.fillStyle = nodeStatus === 'targeted' ? '#ff3366' : '#8ba0c2';
    topoCtx.fillText(nodeStatus.toUpperCase(), e.x, e.y + 12);
  });
}

// ============================================================================
// 6. Real-Time CAN-FD & SecOC Packet Sniffer
// ============================================================================
const standardFrames = [
  { id: '0x0A2', name: 'ADAS_Trajectory_Cmd', bus: 'CAN-ADAS', dlc: 32, secoc: true },
  { id: '0x0C4', name: 'EPS_SteeringTorque_Req', bus: 'CAN-CHASSIS', dlc: 16, secoc: true },
  { id: '0x120', name: 'ESC_WheelPulse_Front', bus: 'CAN-CHASSIS', dlc: 8, secoc: true },
  { id: '0x214', name: 'BMS_HV_CurrentLimits', bus: 'CAN-PT', dlc: 16, secoc: true },
  { id: '0x280', name: 'INV_MotorSpeedTorque', bus: 'CAN-PT', dlc: 16, secoc: true },
  { id: '0x3F0', name: 'TCU_V2X_SafetyBeacon', bus: 'CAN-ADAS', dlc: 48, secoc: true }
];

let freshnessCounter = 409210;

function initCANSniffer() {
  const pauseBtn = document.getElementById('btn-pause-can');
  const clearBtn = document.getElementById('btn-clear-can');
  const injectBtn = document.getElementById('btn-inject-frame');

  pauseBtn?.addEventListener('click', () => {
    state.canPaused = !state.canPaused;
    pauseBtn.textContent = state.canPaused ? 'Resume Stream' : 'Pause Stream';
  });

  clearBtn?.addEventListener('click', () => {
    state.canFrames = [];
    renderCANTable();
  });

  injectBtn?.addEventListener('click', () => {
    const bus = document.getElementById('inject-bus-select')?.value || 'CAN-CHASSIS';
    const id = document.getElementById('inject-id-input')?.value || '0x0C4';
    const payload = document.getElementById('inject-payload-input')?.value || 'FF 00 24 1A';

    // Injected frames default to INVALID SecOC (simulating untrusted injected node)
    injectRawCANFrame(bus, id, 'ROUGE_MANUAL_INJECT', payload, false);
  });
}

function generateCANStream() {
  if (state.canPaused) return;

  freshnessCounter += 1;
  const template = standardFrames[Math.floor(Math.random() * standardFrames.length)];

  // Check if steering attack is ongoing
  const steeringAttack = state.threats.find(t => t.id === 'attack-can-steering' && t.active);
  let isValid = true;
  let payload = generateRandomHex(template.dlc > 16 ? 8 : template.dlc);

  if (steeringAttack && template.id === '0x0C4') {
    payload = 'FF 3F 00 00 A2 44 91 CC';
    isValid = false; // Spoofed frame fails CMAC verification
  }

  const frame = {
    time: new Date().toISOString().substring(11, 23),
    bus: template.bus,
    id: template.id,
    name: template.name,
    dlc: template.dlc,
    payload: payload,
    freshness: freshnessCounter,
    mac: isValid ? '0x' + generateRandomHex(4).toUpperCase() : 'INVALID_MAC',
    valid: isValid
  };

  state.canFrames.unshift(frame);
  if (state.canFrames.length > 40) state.canFrames.pop();

  if (state.activeTab === 'bus-monitor') {
    renderCANTable();
  }
}

function injectRawCANFrame(bus, id, name, payload, isValid) {
  freshnessCounter++;
  const frame = {
    time: new Date().toISOString().substring(11, 23),
    bus: bus,
    id: id,
    name: name,
    dlc: payload.split(' ').length,
    payload: payload,
    freshness: freshnessCounter,
    mac: isValid ? '0x' + generateRandomHex(4).toUpperCase() : 'UNVERIFIED',
    valid: isValid
  };

  state.canFrames.unshift(frame);
  addAuditLog('WARNING', bus, `Manual CAN injection detected on ID ${id} (${payload})`, generateHash(payload));
  renderCANTable();
}

function renderCANTable() {
  const tbody = document.getElementById('can-table-body');
  if (!tbody) return;

  const filter = document.getElementById('can-filter-input')?.value?.toUpperCase() || '';

  const filtered = state.canFrames.filter(f => 
    f.id.includes(filter) || f.bus.includes(filter) || f.name.toUpperCase().includes(filter)
  );

  tbody.innerHTML = filtered.slice(0, 18).map(f => `
    <tr>
      <td>${f.time}</td>
      <td><span class="badge badge-sm badge-accent">${f.bus}</span></td>
      <td><strong>${f.id}</strong></td>
      <td>${f.name}</td>
      <td>${f.dlc}</td>
      <td><code>${f.payload}</code></td>
      <td>#${f.freshness}</td>
      <td class="${f.valid ? 'val-good' : 'val-bad'}">${f.mac}</td>
      <td>
        <span class="status-tag ${f.valid ? 'status-secure' : 'status-spoofed'}">
          ${f.valid ? 'SecOC PASS' : 'SecOC REJECT'}
        </span>
      </td>
    </tr>
  `).join('');
}

function generateRandomHex(bytes) {
  const chars = '0123456789ABCDEF';
  let out = '';
  for (let i = 0; i < bytes * 2; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
    if (i % 2 === 1 && i < (bytes * 2 - 1)) out += ' ';
  }
  return out;
}

// ============================================================================
// 7. BMS & Battery Security View
// ============================================================================
function initBMSView() {
  const container = document.getElementById('bms-cells-container');
  if (!container) return;

  container.innerHTML = state.cells.map(c => `
    <div class="cell-box" id="cell-${c.id}">
      <span class="cell-id">${c.id}</span>
      <span class="cell-v">${c.v.toFixed(2)}V</span>
    </div>
  `).join('');
}

function updateBMSView() {
  const tempEl = document.getElementById('bms-pack-temp');
  if (tempEl) tempEl.textContent = `${state.batteryTemp.toFixed(1)}°C`;

  state.cells.forEach(c => {
    const el = document.getElementById(`cell-${c.id}`);
    if (el) {
      el.className = `cell-box ${c.v > 4.25 ? 'overvoltage' : ''}`;
      el.querySelector('.cell-v').textContent = `${c.v.toFixed(2)}V`;
    }
  });
}

// ============================================================================
// 8. Perception Fusion Arbiter Table
// ============================================================================
function updateFusionTable() {
  const tbody = document.getElementById('fusion-table-body');
  if (!tbody) return;

  const phantomAttack = state.threats.find(t => t.id === 'attack-phantom-laser' && t.active);
  const signAttack = state.threats.find(t => t.id === 'attack-sign-patch' && t.active);

  const objects = [
    { id: 'OBJ-101', class: 'Lead Vehicle (Sedan)', camConf: '98.5%', radarDist: '48.2m', lidarPts: 1420, status: 'VERIFIED', action: 'Adaptive Cruise Follow' },
    { id: 'OBJ-102', class: 'Right Lane Vehicle (SUV)', camConf: '94.2%', radarDist: '32.1m', lidarPts: 890, status: 'VERIFIED', action: 'Blind Spot Track' },
    { 
      id: 'OBJ-103', 
      class: signAttack ? 'Speed Sign [Perturbed 100km/h]' : 'Speed Limit Sign (40 km/h)', 
      camConf: signAttack ? '52.1% (Entropy Alert)' : '96.1%', 
      radarDist: 'N/A', 
      lidarPts: 180, 
      status: signAttack ? 'ANOMALOUS (MAP OVERRIDE)' : 'VERIFIED', 
      action: signAttack ? 'Enforce Map Speed (40km/h)' : 'Speed Limit 40 km/h' 
    }
  ];

  if (phantomAttack) {
    objects.unshift({
      id: 'OBJ-999 (SPOOFED)',
      class: 'Phantom Obstacle [Laser]',
      camConf: '91.4%',
      radarDist: 'NO RETURN (0m)',
      lidarPts: 12,
      status: 'REJECTED BY ARBITER',
      action: 'Suppress Phantom Braking'
    });
  }

  tbody.innerHTML = objects.map(o => `
    <tr>
      <td><strong>${o.id}</strong></td>
      <td>${o.class}</td>
      <td>${o.camConf}</td>
      <td>${o.radarDist}</td>
      <td>${o.lidarPts}</td>
      <td><span class="status-tag ${o.status.includes('REJECTED') || o.status.includes('ANOMALOUS') ? 'status-spoofed' : 'status-secure'}">${o.status}</span></td>
      <td><strong>${o.action}</strong></td>
    </tr>
  `).join('');
}

// ============================================================================
// 9. Immutable Audit Logs & Telemetry
// ============================================================================
function initAuditLogs() {
  addAuditLog('INFO', 'HSM_BOOT', 'Infineon AURIX TC397 Root-of-Trust authenticated with ASIL-D secure boot.', generateHash('BOOT'));
  addAuditLog('INFO', 'AUTOSAR_SecOC', 'SecOC freshness monotonic counters synchronized across CAN-FD gateways.', generateHash('SYNC'));
  addAuditLog('INFO', 'ISO_15118', 'Plug & Charge OEM certificate root chain validated successfully.', generateHash('PKI'));
}

function addAuditLog(sev, subsys, desc, hash) {
  const log = {
    time: new Date().toISOString().replace('T', ' ').substring(0, 19),
    sev: sev,
    subsys: subsys,
    desc: desc,
    hash: hash
  };

  state.auditLogs.unshift(log);
  if (state.auditLogs.length > 50) state.auditLogs.pop();

  const tbody = document.getElementById('log-table-body');
  if (tbody) {
    tbody.innerHTML = state.auditLogs.map(l => `
      <tr>
        <td>${l.time}</td>
        <td><span class="sev-badge ${l.sev === 'WARNING' || l.sev === 'SEC_ALERT' ? 'critical' : 'high'}">${l.sev}</span></td>
        <td><strong>${l.subsys}</strong></td>
        <td>${l.desc}</td>
        <td><code>${l.hash}</code></td>
      </tr>
    `).join('');
  }
}

function generateHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return '0x' + Math.abs(hash).toString(16).padStart(8, '0') + '...';
}

// ============================================================================
// 10. Buttons & Actions
// ============================================================================
function initButtons() {
  // Minimal Risk Maneuver (MRM Safe Stop)
  document.getElementById('btn-mrm-trigger')?.addEventListener('click', () => {
    state.mrmTriggered = true;
    state.adsMode = 'EMERGENCY MRM SAFE STOP';
    state.speed = 0;
    
    const badge = document.getElementById('ads-mode-badge');
    if (badge) {
      badge.textContent = state.adsMode;
      badge.classList.replace('highlight', 'danger');
    }

    addAuditLog('SEC_ALERT', 'ACTUATOR_SAFETY', 'Minimal Risk Maneuver executed: Vehicle brought to safe standstill on shoulder.', generateHash('MRM'));
    alert('🛑 MINIMAL RISK MANEUVER (MRM) EXECUTED:\n\nVehicle has transitioned to Fail-Operational safe state:\n1. Hazard flashers activated.\n2. Inverter torque ramped down to 0 Nm.\n3. Friction brakes modulated to halt vehicle.\n4. High-voltage pyrotechnic fuse safe-state engaged.');
  });

  // Reset All Attacks
  document.getElementById('btn-reset-all-attacks')?.addEventListener('click', () => {
    state.threats.forEach(t => t.active = false);
    evaluateSystemState();
    initAttackConsole();
    addAuditLog('INFO', 'SIMULATOR', 'All active red team attacks terminated.', generateHash('RESET'));
  });

  // Rotate Cryptographic Keys
  document.getElementById('btn-rotate-keys')?.addEventListener('click', () => {
    freshnessCounter += 1000;
    addAuditLog('INFO', 'HSM_CRYPTO', 'Session keys rotated via ECDH ephemeral key exchange.', generateHash('ROTATE'));
    alert('🔐 Root-of-Trust HSM Keys Successfully Rotated!\nNew AES-256-GCM symmetric session keys distributed to all cluster ECUs.');
  });

  // Direct Countermeasure Overrides
  document.getElementById('btn-isolate-gateway')?.addEventListener('click', () => {
    state.gatewayIsolated = !state.gatewayIsolated;
    addAuditLog('WARNING', 'FIREWALL', `IVI/Telematics Gateway ${state.gatewayIsolated ? 'ISOLATED' : 'RECONNECTED'}.`, generateHash('ISOLATE'));
    alert(`Central Gateway Firewall: Telematics and Infotainment subnets are now ${state.gatewayIsolated ? 'AIR-GAPPED' : 'RECONNECTED'}.`);
    renderTopology();
  });

  document.getElementById('btn-force-sensor-fallback')?.addEventListener('click', () => {
    state.radarFallback = !state.radarFallback;
    addAuditLog('WARNING', 'PERCEPTION', `Perception forced to ${state.radarFallback ? 'RADAR/LIDAR ONLY' : 'FULL TRISENSOR'}.`, generateHash('FALLBACK'));
    alert(`Sensor Fusion Arbiter: Camera optical feed ${state.radarFallback ? 'BYPASSED' : 'RESTORED'}. Operating on Radar + LiDAR distance geometry.`);
  });

  document.getElementById('btn-cut-dc-charging')?.addEventListener('click', () => {
    state.hvDisconnected = true;
    addAuditLog('SEC_ALERT', 'BMS_HV', 'High-voltage main contactors forcefully open.', generateHash('HV_CUT'));
    alert('⚡ Emergency HV Disconnect:\nMain pyrotechnic contactors opened in 2ms. Traction battery isolated from inverter and DC fast charging port.');
  });

  // Test Malicious EVSE Handshake
  document.getElementById('btn-test-malicious-evse')?.addEventListener('click', () => {
    addAuditLog('SEC_ALERT', 'ISO_15118', 'Rogue EVSE attempted power curve injection: Certificate revoked by OEM OCSP.', generateHash('EVSE_MITM'));
    alert('⚠️ Rogue Charging Station Detected!\n\nISO 15118 Handshake Result:\n- Station Certificate: UNTRUSTED_ROOT_CA\n- Requested Current: 500A Surge (Exceeds Max Negotiated 250A)\n- Action: Connection terminated before closing HV contactors.');
  });

  // Auto-mitigate switch
  document.getElementById('toggle-auto-mitigate')?.addEventListener('change', (e) => {
    state.autoMitigate = e.target.checked;
    addAuditLog('INFO', 'AI_ENGINE', `Autonomous IDS/IPS mitigation set to: ${state.autoMitigate ? 'ENABLED' : 'DISABLED'}`, generateHash('AUTOMIT'));
  });

  // Export audit logs
  document.getElementById('btn-export-logs')?.addEventListener('click', () => {
    const csvContent = "data:text/csv;charset=utf-8," 
      + "Timestamp,Severity,Subsystem,Event,Hash\n"
      + state.auditLogs.map(e => `"${e.time}","${e.sev}","${e.subsys}","${e.desc}","${e.hash}"`).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `autoshield_audit_log_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });
}

// Background Telemetry Simulation
function simulateTelemetry() {
  if (state.speed > 0 && !state.mrmTriggered) {
    // Natural jitter
    state.speed = Math.max(65, Math.min(80, state.speed + (Math.random() - 0.5) * 1.5));
    document.getElementById('telemetry-speed').textContent = `${state.speed.toFixed(0)} km/h`;
  }

  // Jitter busload
  state.busLoad = Math.max(38, Math.min(52, state.busLoad + (Math.random() - 0.5) * 2));
  document.getElementById('telemetry-busload').textContent = `${state.busLoad.toFixed(1)}%`;

  document.getElementById('telemetry-battery').textContent = `${state.batterySoC}% • ${state.batteryTemp.toFixed(1)}°C`;

  updateBMSView();
}

