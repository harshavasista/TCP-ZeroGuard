const API_BASE = "https://tcp-zeroguard.onrender.com";
const ANALYSIS_URL = `${API_BASE}/api/analysis`;
const START_CAPTURE_URL = `${API_BASE}/api/start-capture`;
let ANALYSIS = null;

/* ============================================================
   LOAD EXISTING ANALYSIS
   ============================================================ */


  
async function loadAnalysis() {
  try {
    const response = await fetch(ANALYSIS_URL, {
      cache: "no-store"
    });

    // Backend is reachable, but there is no saved analysis yet.
    if (response.status === 404) {
      ANALYSIS = null;
      updateBackendStatus(true);
      clearAnalysisView(
        "No completed analysis is available. Run a capture to begin.",
        "No analysis"
      );

      console.log("Backend connected. No analysis available yet.");
      return false;
    }

    if (!response.ok) {
      throw new Error(`FastAPI returned HTTP ${response.status}`);
    }

    const data = await response.json();

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("The analysis response was not a valid JSON object.");
    }

    ANALYSIS = normalizeAnalysis(data);

    updateBackendStatus(true);
    console.log("Analysis loaded from FastAPI:", ANALYSIS);

    return true;
  } catch (error) {
    console.error("Unable to load analysis:", error);
    updateBackendStatus(false);
    clearAnalysisView(
      "Unable to retrieve analysis from the backend.",
      "Connection error"
    );
    showBackendError(error);
    return false;
  }
}


/* ============================================================
   RUN AUTOMATIC CAPTURE AND ANALYSIS THROUGH FASTAPI
   ============================================================ */

async function runAnalysis(pauseSeconds) {
  try {
    const url = pauseSeconds
      ? `${START_CAPTURE_URL}?pause_seconds=${encodeURIComponent(pauseSeconds)}`
      : START_CAPTURE_URL;
    const response = await fetch(url, {
      method: "POST",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json"
      }
    });

    let result;
    try {
      result = await response.json();
    } catch {
      throw new Error("The server returned invalid JSON. Check the backend logs.");
    }

    if (!response.ok) {
      let message = "Capture and analysis failed.";

      if (result && result.detail) {
        message =
          typeof result.detail === "string"
            ? result.detail
            : result.detail.message ||
              JSON.stringify(result.detail);
      }

      throw new Error(message);
    }

    if (!result || !result.analysis || typeof result.analysis !== "object") {
      throw new Error(
        "FastAPI did not return analysis data."
      );
    }

    ANALYSIS = normalizeAnalysis(result.analysis);
    updateBackendStatus(true);

    console.log("Fresh analysis received:", ANALYSIS);

    return {
      success: true,
      output: result.analyzer_output || ""
    };
  } catch (error) {
    console.error("Automatic capture and analysis failed:", error);
    updateBackendStatus(false);

    return {
      success: false,
      error
    };
  }
}

/* ============================================================
   NORMALIZE BACKEND DATA
   ============================================================ */

function normalizeAnalysis(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Analysis data is missing or malformed.");
  }
  const sender = data.connection?.sender || {};
  const receiver = data.connection?.receiver || {};
  const capture = data.capture || {};
  const events = data.events || {};
  const metrics = data.metrics || {};
  const state = data.state || {};

  const connection = {
    sender: `${sender.ip || "Unknown"}:${sender.port || "?"}`,
    receiver: `${receiver.ip || "Unknown"}:${receiver.port || "?"}`,
    protocol: "TCP",
    currentlyStalled: Boolean(state.currently_stalled)
  };

  const pcap = {
    file: "tcp_zero_window.pcapng",
    totalPackets: capture.total_packets || 0,
    tcpPackets: capture.tcp_packets || 0,
    analyzer: "TCP-ZeroGuard",
    status: "Completed",
    output: "analysis.json"
  };

  const normalizedMetrics = {
    zeroWindowPackets: events.zero_window_packets || 0,
    stallEpisodes: events.stall_episodes || 0,
    confirmedProbes: events.confirmed_probes || 0,
    probeResponses: events.probe_responses || 0,
    recoveryEpisodes: events.recovery_episodes || 0,
    totalStallDuration: Number(
      metrics.total_stall_duration_sec || 0
    ),
    maximumStallDuration: Number(
      metrics.maximum_stall_duration_sec || 0
    ),
    averageStallDuration: Number(
      metrics.average_stall_duration_sec || 0
    )
  };

  const backendTimeline = Array.isArray(data.timeline)
    ? data.timeline
    : [];

  const formatEventDuration = value => {
    if (!Number.isFinite(value)) {
      return undefined;
    }

    const decimals = Math.abs(value) < 0.001 ? 6 : 3;
    return `${value.toFixed(decimals)} s`;
  };

  const timeline = backendTimeline.filter(event => event && typeof event === "object").map(event => {
    let type = "alert";
    let label = event.event || "Unknown event";

    switch (event.event) {
      case "ZERO_WINDOW_START":
        type = "alert";
        label = "Zero window";
        break;

      case "ZERO_WINDOW_PROBE":
        type = "probe";
        label = "Zero window probe";
        break;

      case "PROBE_RESPONSE":
        type = "response";
        label = "Probe response";
        break;

      case "WINDOW_REOPENED":
        type = "ok";
        label = "Window reopened";
        break;

      default:
        type = "alert";
        label = event.event || "Unknown event";
    }

    const eventTiming = (() => {
      let timingValue;
      let timingLabel;

      switch (event.event) {
        case "ZERO_WINDOW_START":
        case "WINDOW_REOPENED":
          timingValue = event.stall_duration;
          timingLabel = "Stall";
          break;
        case "ZERO_WINDOW_PROBE":
          timingValue = event.probe_interval_sec;
          timingLabel = "Probe interval";
          break;
        case "PROBE_RESPONSE":
          timingValue = event.probe_response_latency_sec;
          timingLabel = "Response time";
          break;
        default:
          timingValue = undefined;
          timingLabel = "Timing";
      }

      if (
        (event.event === "ZERO_WINDOW_START" || event.event === "WINDOW_REOPENED") &&
        !Number.isFinite(timingValue) &&
        Number.isFinite(event.start_timestamp_sec) &&
        Number.isFinite(event.recovery_timestamp_sec)
      ) {
        timingValue = event.recovery_timestamp_sec - event.start_timestamp_sec;
      }

      return {
        value: Number.isFinite(timingValue) && timingValue >= 0
          ? formatEventDuration(timingValue)
          : event.event === "ZERO_WINDOW_START" && state.currently_stalled
            ? "Ongoing"
            : undefined,
        label: timingLabel
      };
    })();

    return {
      packet: event.packet,
      eventCode: event.event,
      type,
      label,
      window: event.window,
      ack: event.ack,
      seq: event.seq,
      payload: Number.isFinite(event.payload_length)
        ? `${event.payload_length} byte${event.payload_length === 1 ? "" : "s"}`
        : event.payload,
      duration: eventTiming.value,
      durationLabel: eventTiming.label
    };
  });

  // The analyzer does not provide a separate flap classification. Keep this
  // collection empty instead of inferring events from packet-number thresholds.
  const flaps = [];

  let final = {
    packet: 0,
    type: "alert",
    label: "No final event",
    detail: ""
  };

  if (backendTimeline.length > 0) {
    const last = backendTimeline[backendTimeline.length - 1];
    const reopened = last.event === "WINDOW_REOPENED";

    final = {
      packet: last.packet,
      type: reopened ? "ok" : "alert",
      label: reopened
        ? "Window reopened"
        : "Zero window (ongoing)",
      window: last.window,
      seq: last.seq,
      ack: last.ack,
      payload: Number.isFinite(last.payload_length)
        ? `${last.payload_length} byte${last.payload_length === 1 ? "" : "s"}`
        : undefined,
      duration: Number.isFinite(last.stall_duration)
        ? `${String(last.stall_duration)}s`
        : undefined,
      detail: reopened
        ? "The capture ended after the receive window reopened."
        : "The capture ended while the connection was still in a zero-window state."
    };
  }

  const stallEpisodeDurations = [];

  backendTimeline.forEach(event => {
    if (event.event !== "WINDOW_REOPENED") {
      return;
    }

    // Prefer the paired PCAP timestamps. Keep the existing analyzer duration
    // as a compatibility fallback for analysis files generated earlier.
    const duration =
      Number.isFinite(event.start_timestamp_sec) &&
      Number.isFinite(event.recovery_timestamp_sec)
        ? event.recovery_timestamp_sec - event.start_timestamp_sec
        : event.stall_duration;

    if (Number.isFinite(duration) && duration >= 0) {
      stallEpisodeDurations.push(duration);
    }
  });

  return {
    connection,
    pcap,
    metrics: normalizedMetrics,
    timeline,
    flaps,
    final,
    stallEpisodeDurations,
    state: {
      stallDetected: Boolean(state.stall_detected),
      recoveryDetected: Boolean(state.recovery_detected),
      currentlyStalled: Boolean(state.currently_stalled)
    }
  };
}

/* ============================================================
   BACKEND STATUS
   ============================================================ */

function updateBackendStatus(connected) {
  const captureStatus = document.querySelector(".capture-status");
  const captureDot = document.querySelector(".capture-pill .dot");

  if (captureStatus) {
    captureStatus.textContent = connected
      ? "Analysis ready"
      : "Backend unavailable";
  }

  if (captureDot) {
    captureDot.classList.toggle("dot-ok", connected);
    captureDot.classList.toggle("dot-alert", !connected);
  }

  const statusText = document.querySelector(".foot-text");
  const statusDot = document.querySelector(".foot-status .dot");

  if (statusText) {
    statusText.textContent = connected
      ? "Backend connected"
      : "Backend unavailable";
  }

  if (statusDot) {
    statusDot.classList.remove("dot-ok");

    if (connected) {
      statusDot.classList.add("dot-ok");
    }
  }

  const settingsValue = document.querySelector(".settings-mono");

  if (settingsValue) {
    settingsValue.textContent = connected
      ? "127.0.0.1:8000"
      : "not connected";
  }
}

/* ============================================================
   BACKEND ERROR
   ============================================================ */

function showBackendError(error) {
  const heroState = document.getElementById("hero-state");
  const heroBadge = document.getElementById("hero-badge");

  if (heroState) {
    heroState.textContent = "Backend unavailable";
  }

  if (heroBadge) {
    heroBadge.innerHTML = `
      <span class="pulse-dot"></span>
      OFFLINE
    `;
  }

  console.error("TCP-ZeroGuard backend error:", error);
}

function clearAnalysisView(message, status = "No analysis") {
  ANALYSIS = null;
  tableRows = [];
  activeFilter = "all";
  searchTerm = "";
  currentPage = 1;

  [
    "metric-grid",
    "timeline-list",
    "timeline-legend",
    "stall-stats",
    "stall-chart",
    "event-filters",
    "packet-table-body",
    "pcap-grid"
  ].forEach(id => {
    const element = document.getElementById(id);
    if (element) element.replaceChildren();
  });

  const state = document.getElementById("hero-state");
  const description = document.getElementById("hero-description");
  const badge = document.getElementById("hero-badge");
  const gauge = document.getElementById("gauge-level");
  const gaugeValue = document.getElementById("gauge-value");
  const packetSearch = document.getElementById("packet-search");
  const tableCount = document.getElementById("table-count");
  const pager = document.getElementById("pager-label");
  const captureStatus = document.querySelector(".capture-status");
  const captureDot = document.querySelector(".capture-pill .dot");

  if (state) state.textContent = "No current analysis";
  if (description) description.textContent = message;
  if (badge) badge.textContent = "NO DATA";
  if (gauge) {
    gauge.style.width = "0%";
    gauge.style.background = "";
  }
  if (gaugeValue) gaugeValue.textContent = "—";
  if (packetSearch) packetSearch.value = "";
  if (tableCount) tableCount.textContent = "0 rows";
  if (pager) pager.textContent = "Page 0 of 0";
  if (captureStatus) captureStatus.textContent = status;
  if (captureDot) {
    captureDot.classList.remove("dot-ok");
    captureDot.classList.add("dot-alert");
  }

  document.querySelectorAll(".channel-node-addr").forEach(element => {
    element.textContent = "—";
  });

  ["pager-prev", "pager-next"].forEach(id => {
    const button = document.getElementById(id);
    if (button) button.disabled = true;
  });
}

/* ============================================================
   ICONS
   ============================================================ */

const ICONS = {
  buffer: `
    <svg viewBox="0 0 16 16" fill="none">
      <rect x="2" y="2" width="12" height="12"
        rx="1.5" stroke="currentColor" stroke-width="1.4"/>
      <path d="M2 10.5h12" stroke="currentColor"
        stroke-width="1.4" stroke-dasharray="1.6 1.6"/>
    </svg>`,

  clock: `
    <svg viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8.4" r="5.4"
        stroke="currentColor" stroke-width="1.4"/>
      <path d="M8 5.4v3l2 1.3" stroke="currentColor"
        stroke-width="1.4" stroke-linecap="round"/>
      <path d="M6 1.8h4" stroke="currentColor"
        stroke-width="1.4" stroke-linecap="round"/>
    </svg>`,

  ping: `
    <svg viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="1.6" fill="currentColor"/>
      <circle cx="8" cy="8" r="4.2"
        stroke="currentColor" stroke-width="1.3" opacity=".6"/>
      <circle cx="8" cy="8" r="6.6"
        stroke="currentColor" stroke-width="1.1" opacity=".3"/>
    </svg>`,

  check: `
    <svg viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="6"
        stroke="currentColor" stroke-width="1.4"/>
      <path d="M5.3 8.2l1.8 1.8 3.6-4"
        stroke="currentColor" stroke-width="1.4"
        stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,

  refresh: `
    <svg viewBox="0 0 16 16" fill="none">
      <path d="M13 8a5 5 0 1 1-1.6-3.7"
        stroke="currentColor" stroke-width="1.4"
        stroke-linecap="round"/>
      <path d="M13 2.6V5.4H10.2"
        stroke="currentColor" stroke-width="1.4"
        stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,

  hourglass: `
    <svg viewBox="0 0 16 16" fill="none">
      <path d="M4 2h8M4 14h8" stroke="currentColor"
        stroke-width="1.4" stroke-linecap="round"/>
      <path d="M4.6 2c0 2.6 1.4 4.2 3.4 4.9
        C5.9 7.6 4.6 9.3 4.6 14
        M11.4 2c0 2.6-1.4 4.2-3.4 4.9
        2.1.7 3.4 2.4 3.4 6"
        stroke="currentColor" stroke-width="1.3"
        stroke-linejoin="round"/>
    </svg>`
};

const TONE_LABEL = {
  alert: "Zero window",
  probe: "Probe",
  response: "Response",
  ok: "Reopened / recovery"
};

/* ============================================================
   METRIC CARDS
   ============================================================ */

function renderMetrics() {
  const m = ANALYSIS.metrics;
  const element = document.getElementById("metric-grid");
  if (!element) return;

  const cards = [
    {
      icon: "buffer",
      tone: "alert",
      value: m.zeroWindowPackets,
      label: "Zero window packets",
      sub: "Receiver advertised window = 0"
    },
    {
      icon: "clock",
      tone: "alert",
      value: m.stallEpisodes,
      label: "Stall episodes",
      sub: "Distinct halt periods detected"
    },
    {
      icon: "ping",
      tone: "probe",
      value: m.confirmedProbes,
      label: "Zero window probes",
      sub: "1-byte keep-alive probes sent"
    },
    {
      icon: "check",
      tone: "response",
      value: m.probeResponses,
      label: "Probe responses",
      sub: "Receiver replies to probes"
    },
    {
      icon: "refresh",
      tone: "ok",
      value: m.recoveryEpisodes,
      label: "Recovery episodes",
      sub: "Window reopened after stall"
    },
    {
      icon: "hourglass",
      tone: "alert",
      value: m.maximumStallDuration.toFixed(3) + "s",
      label: "Maximum stall",
      sub: "Longest single stall duration"
    }
  ];

  element.innerHTML =
    cards.map(card => `
      <div class="metric-card">
        <div class="metric-card-top">
          <div class="metric-icon"
            style="color:var(--${card.tone})">
            ${ICONS[card.icon]}
          </div>
        </div>
        <div class="metric-value">${card.value}</div>
        <div class="metric-label">${card.label}</div>
        <div class="metric-sub">${card.sub}</div>
      </div>
    `).join("");
}

/* ============================================================
   TCP CASCADE
   ============================================================ */

function renderCascade(containerId, steps) {
  const element = document.getElementById(containerId);

  if (!element) {
    return;
  }

  element.innerHTML = steps.map((step, index) => `
    ${index > 0
      ? '<div class="cascade-connector"></div>'
      : ''}
    <div class="cascade-step t-${step.tone}">
      <div class="step-mark">${index + 1}</div>
      <span>${step.label}</span>
    </div>
  `).join("");
}

function renderCascades() {
  renderCascade("cascade-flow", [
    { label: "Receiver buffer full", tone: "alert" },
    { label: "Zero window advertised", tone: "alert" },
    { label: "Sender stops normal transmission", tone: "alert" },
    { label: "Zero window probe sent", tone: "probe" },
    { label: "Probe response received", tone: "response" },
    { label: "Window reopens", tone: "ok" }
  ]);

  const firstPacket = ANALYSIS.timeline.length
    ? ANALYSIS.timeline[0].packet
    : "—";

  renderCascade("cascade-recovery", [
    {
      label: `Stall detected — packet ${firstPacket}`,
      tone: "alert"
    },
    { label: "Zero window advertised", tone: "alert" },
    {
      label: `${ANALYSIS.metrics.confirmedProbes} probes sent`,
      tone: "probe"
    },
    {
      label: `${ANALYSIS.metrics.probeResponses} responses received`,
      tone: "response"
    },
    { label: "Window reopened — 4096 bytes", tone: "ok" }
  ]);

  // Update recovery time (longest stall) and current state
  const maxStall = ANALYSIS.metrics.maximumStallDuration || 0;
  const isStalled = ANALYSIS.state?.currentlyStalled || false;

  const recoveryTimeEl = document.getElementById("recovery-time-value");
  if (recoveryTimeEl) {
    recoveryTimeEl.textContent = maxStall.toFixed(3) + "s";
  }

  const stateChipEl = document.querySelector(".recovery-state .state-chip");
  const stateLabelEl = document.querySelector(".recovery-state .foot-label");
  if (stateChipEl) {
    stateChipEl.textContent = isStalled ? "Zero window" : "Window open";
    stateChipEl.className = "state-chip " + (isStalled ? "state-chip-alert" : "state-chip-ok");
  }
  if (stateLabelEl) {
    stateLabelEl.textContent = "Current state at end of capture";
  }
}

/* ============================================================
   EVENT LEGEND
   ============================================================ */

function renderLegend() {
  const items = [
    { tone: "alert", label: "Zero window" },
    { tone: "probe", label: "Probe" },
    { tone: "response", label: "Probe response" },
    { tone: "ok", label: "Reopened / recovery" }
  ];

  const element = document.getElementById("timeline-legend");

  if (!element) {
    return;
  }

  element.innerHTML = items.map(item => `
    <div class="legend-item">
      <span class="legend-swatch dot-${item.tone}-fill"></span>
      ${item.label}
    </div>
  `).join("");
}

/* ============================================================
   TIMELINE
   ============================================================ */

function buildFullEventList() {
  const main = ANALYSIS.timeline.map(event => ({
    ...event
  }));

  const flaps = [];

  ANALYSIS.flaps.forEach(([start, end], index) => {
    flaps.push({
      packet: start,
      type: "alert",
      label: "Zero window start",
      window: 0,
      detail: `Brief buffer flap #${index + 1}.`
    });

    flaps.push({
      packet: end,
      type: "ok",
      label: "Window reopened",
      window: 4096,
      detail: `Buffer cleared quickly — short flap #${index + 1}.`
    });
  });

  return {
    main,
    flaps,
    final: ANALYSIS.final
  };
}

function timelineRowHTML(event) {
  const metadata = [];

  if (event.window !== undefined) {
    metadata.push(`WIN ${event.window}`);
  }

  if (event.seq) {
    metadata.push(`SEQ ${event.seq}`);
  }

  if (event.ack) {
    metadata.push(`ACK ${event.ack}`);
  }

  if (event.payload) {
    metadata.push(event.payload);
  }

  if (event.duration) {
    metadata.push(event.duration);
  }

  return `
    <div
      class="timeline-item"
      data-packet="${event.packet}"
    >
      <div
        class="timeline-node dot-${event.type}-fill"
      ></div>

      <div class="timeline-row">
        <div class="timeline-main">
          <span class="timeline-pkt">
            #${event.packet}
          </span>

          <span class="timeline-tag tag-${event.type}">
            ${TONE_LABEL[event.type]}
          </span>

          <span class="timeline-label">
            ${event.label}
          </span>
        </div>

        <span class="timeline-meta">
          ${metadata.join(" · ")}
        </span>
      </div>

      ${
        event.detail
          ? `
            <div class="timeline-detail">
              ${event.detail}
            </div>
          `
          : ""
      }
    </div>
  `;
}


function renderTimeline() {
  const {
    main,
    flaps,
    final
  } = buildFullEventList();

  let html = main.map(timelineRowHTML).join("");

  if (flaps.length) {
    html += `
      <div class="timeline-divider">
        Recurring buffer flaps
      </div>
    `;
    html += flaps.map(timelineRowHTML).join("");
  }

  html += `
    <div class="timeline-divider">
      Capture end
    </div>
  `;

  html += timelineRowHTML(final);

  const element = document.getElementById("timeline-list");

  if (!element) {
    return;
  }

  element.innerHTML = html;

  document.querySelectorAll(".timeline-item").forEach(item => {
    const detail = item.querySelector(".timeline-detail");

    if (!detail) {
      return;
    }

    item.querySelector(".timeline-row").addEventListener("click", () => {
      item.classList.toggle("expanded");
    });
  });
}

/* ============================================================
   STALL STATISTICS
   ============================================================ */

function renderStallStats() {
  const m = ANALYSIS.metrics;

  const stats = [
    {
      value: m.totalStallDuration.toFixed(3) + "s",
      label: "Total completed stall duration"
    },
    {
      value: m.maximumStallDuration.toFixed(3) + "s",
      label: "Maximum completed stall"
    },
    {
      value: m.averageStallDuration.toFixed(3) + "s",
      label: "Average completed stall"
    },
    {
      value: m.stallEpisodes,
      label: "Stall episodes"
    },
    {
      value: m.recoveryEpisodes,
      label: "Recovery episodes"
    }
  ];

  const element = document.getElementById("stall-stats");

  if (!element) {
    return;
  }

  element.innerHTML = stats.map(stat => `
    <div class="stat-card">
      <div class="stat-value">
        ${stat.value}
      </div>
      <div class="stat-label">
        ${stat.label}
      </div>
    </div>
  `).join("");
}

/* ============================================================
   STALL CHART
   ============================================================ */

function renderStallChart() {
  const durations = ANALYSIS.stallEpisodeDurations;
  const element = document.getElementById("stall-chart");

  if (!element) {
    return;
  }

  if (!durations || durations.length === 0) {
    element.innerHTML = `
      <div class="cell-empty" style="padding:24px;">
        No measured stall durations
        available in the analysis.
      </div>
    `;
    return;
  }

  element.title = ANALYSIS.state.currentlyStalled
    ? "Chart and duration statistics include completed stalls only. The current stall has no recovery timestamp and is excluded."
    : "Chart and duration statistics include completed stalls only.";

  const positiveDurations = durations.filter(duration => duration > 0);
  const minPositive = positiveDurations.length
    ? Math.min(...positiveDurations)
    : 0;
  const maxPositive = positiveDurations.length
    ? Math.max(...positiveDurations)
    : 0;
  const scaleMin = minPositive > 0
    ? 10 ** Math.floor(Math.log10(minPositive))
    : 0;
  const scaleMax = maxPositive > 0
    ? 10 ** Math.ceil(Math.log10(maxPositive))
    : 0;
  const logMin = scaleMin > 0 ? Math.log10(scaleMin) : 0;
  const logMax = scaleMax > scaleMin ? Math.log10(scaleMax) : logMin;

  // Keep the explanation as a full-width banner inside the chart's card.
  const panel = element.closest(".panel");
  document.querySelectorAll(".chart-scale-note").forEach(note => {
    if (panel && !panel.contains(note)) {
      note.remove();
    }
  });

  if (panel) {
    let scaleNote = panel.querySelector(".chart-scale-note");
    if (!scaleNote) {
      scaleNote = document.createElement("div");
      scaleNote.className = "chart-scale-note";
    }
    element.before(scaleNote);
    scaleNote.textContent =
      `Logarithmic bar scale (base 10), ${String(scaleMin)} s to ${String(scaleMax)} s. Equal vertical steps represent equal duration ratios. Labels show rounded values; hover over a bar for its full precision.`;
  }

  element.innerHTML = durations.map((duration, index) => {
    let height = 0;
    if (duration > 0) {
      height = logMax === logMin
        ? 100
        : ((Math.log10(duration) - logMin) / (logMax - logMin)) * 100;
    }

    return `
    <div class="chart-col">
      <span class="chart-val">
        ${Number(duration).toLocaleString("en-US", {
          useGrouping: false,
          maximumSignificantDigits: 5
        })} s
      </span>
      <div class="chart-bar-wrap">
        <div
          class="chart-bar ${duration === maxPositive ? "is-max" : ""}"
          data-height="${height}"
          title="${String(Number(duration))} seconds"
          aria-label="Episode ${index + 1}: ${String(Number(duration))} seconds"
        ></div>
      </div>
      <span class="chart-label">
        ${index + 1}
      </span>
    </div>
  `;
  }).join("");

  requestAnimationFrame(() => {
    element.querySelectorAll(".chart-bar").forEach(bar => {
      bar.style.height = `${bar.dataset.height}%`;
    });
  });
}

/* ============================================================
   PACKET TABLE
   ============================================================ */

let tableRows = [];
let activeFilter = "all";
let searchTerm = "";
let currentPage = 1;
const PAGE_SIZE = 8;

function buildTableRows() {
  return ANALYSIS.timeline
    .map((event, sourceOrder) => ({ event, sourceOrder }))
    .sort((a, b) =>
      Number(a.event.packet) - Number(b.event.packet) ||
      a.sourceOrder - b.sourceOrder
    )
    .map(item => item.event);
}

function renderFilterChips() {
  const filters = [
    {
      id: "all",
      label: "All events"
    },
    {
      id: "zero_window",
      label: "Zero window"
    },
    {
      id: "probe",
      label: "Probes"
    },
    {
      id: "response",
      label: "Responses"
    },
    {
      id: "reopened",
      label: "Reopened"
    }
  ];

  const element = document.getElementById("event-filters");

  if (!element) {
    return;
  }

  element.innerHTML = filters.map(filter => `
    <button
      class="filter-chip ${filter.id === activeFilter ? "active" : ""}"
      data-filter="${filter.id}"
    >
      ${filter.label}
    </button>
  `).join("");

  document.querySelectorAll(".filter-chip").forEach(button => {
    button.addEventListener("click", () => {
      activeFilter = button.dataset.filter;
      currentPage = 1;
      renderFilterChips();
      renderTable();
    });
  });
}

function normalizeEventIdentifier(value) {
  return String(value ?? "")
    .toLowerCase()
    .replace(/[\s_-]+/g, "");
}

function eventMatchesFilter(row, filter) {
  const eventType = normalizeEventIdentifier(row.eventCode || row.label);

  switch (filter) {
    case "zero_window":
      return eventType === "zerowindowstart" || eventType === "zerowindow";
    case "probe":
      return eventType === "zerowindowprobe";
    case "response":
      return eventType === "proberesponse";
    case "reopened":
      return eventType === "windowreopened";
    case "all":
    default:
      return true;
  }
}

function renderTable() {
  let rows = tableRows;

  if (activeFilter !== "all") {
    rows = rows.filter(row => eventMatchesFilter(row, activeFilter));
  }

  if (searchTerm) {
    const query = searchTerm.toLowerCase();

    rows = rows.filter(row =>
      String(row.packet).includes(query) ||
      String(row.seq ?? "").toLowerCase().includes(query) ||
      String(row.ack ?? "").toLowerCase().includes(query) ||
      String(row.payload ?? "").toLowerCase().includes(query) ||
      String(row.duration ?? "").toLowerCase().includes(query) ||
      String(row.durationLabel ?? "").toLowerCase().includes(query) ||
      String(row.eventCode ?? "").toLowerCase().includes(query) ||
      String(row.label).toLowerCase().includes(query)
    );
  }

  const totalPages = Math.max(
    1,
    Math.ceil(rows.length / PAGE_SIZE)
  );

  currentPage = Math.min(currentPage, totalPages);

  const pageRows = rows.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  const tableBody = document.getElementById("packet-table-body");

  if (!tableBody) {
    return;
  }

  tableBody.innerHTML = pageRows.map(row => `
    <tr>
      <td class="cell-pkt">
        ${row.packet}
      </td>
      <td>
        <span class="timeline-tag tag-${row.type}">
          ${row.label}
        </span>
      </td>
      <td>
        ${
          row.window !== undefined
            ? row.window
            : `<span class="cell-empty">—</span>`
        }
      </td>
      <td>
        ${
          row.seq ??
          `<span class="cell-empty">—</span>`
        }
      </td>
      <td>
        ${
          row.ack ??
          `<span class="cell-empty">—</span>`
        }
      </td>
      <td>
        ${
          row.payload ??
          `<span class="cell-empty">—</span>`
        }
      </td>
      <td>
        ${
          row.duration
            ? `<span title="${row.durationLabel} based on PCAP timestamps">${row.durationLabel === "Stall" ? "Stall" : row.durationLabel}: ${row.duration}</span>`
            : `<span class="cell-empty">—</span>`
        }
      </td>
    </tr>
  `).join("") || `
    <tr>
      <td
        colspan="7"
        class="cell-empty"
        style="text-align:center;padding:24px;"
      >
        No packets match this search.
      </td>
    </tr>
  `;

  const count = document.getElementById("table-count");

  if (count) {
    count.textContent =
      `${rows.length} row${rows.length === 1 ? "" : "s"}`;
  }

  const pager = document.getElementById("pager-label");

  if (pager) {
    pager.textContent = `Page ${currentPage} of ${totalPages}`;
  }

  const previous = document.getElementById("pager-prev");
  const next = document.getElementById("pager-next");

  if (previous) {
    previous.disabled = currentPage <= 1;
  }

  if (next) {
    next.disabled = currentPage >= totalPages;
  }
}

function initTableControls() {
  const search = document.getElementById("packet-search");

  if (search) {
    search.addEventListener("input", event => {
      searchTerm = event.target.value.trim();
      currentPage = 1;
      renderTable();
    });
  }

  const previous = document.getElementById("pager-prev");

  if (previous) {
    previous.addEventListener("click", () => {
      currentPage--;
      renderTable();
    });
  }

  const next = document.getElementById("pager-next");

  if (next) {
    next.addEventListener("click", () => {
      currentPage++;
      renderTable();
    });
  }
}
/* ============================================================
   PCAP PAGE
   ============================================================ */

function renderPcap() {
  const p = ANALYSIS.pcap;

  const items = [
    {
      label: "File",
      value: p.file
    },
    {
      label: "Total packets",
      value: p.totalPackets
    },
    {
      label: "TCP packets",
      value: p.tcpPackets
    },
    {
      label: "Analyzer",
      value: p.analyzer
    },
    {
      label: "Analysis",
      value: p.status
    },
    {
      label: "Output",
      value: p.output
    }
  ];

  const element = document.getElementById("pcap-grid");

  if (!element) {
    return;
  }

  element.innerHTML = items.map(item => `
    <div class="pcap-item">
      <div class="pcap-item-label">
        ${item.label}
      </div>
      <div class="pcap-item-value">
        ${item.value}
      </div>
    </div>
  `).join("");
}

/* ============================================================
   UPDATE HERO
   ============================================================ */

function renderHero() {
  const stalled = ANALYSIS.state.currentlyStalled;

  const state = document.getElementById("hero-state");
  const description = document.getElementById("hero-description");
  const badge = document.getElementById("hero-badge");

  if (state) {
    state.textContent = stalled
      ? "Currently stalled"
      : "Window available";
  }

  if (description) {
    description.textContent = stalled
      ? "Receiver advertised a zero TCP receive window. The sender has halted normal segment transmission and is holding unacknowledged data."
      : "The receiver has available buffer space and can accept incoming TCP data. Normal data transmission can continue.";
  }

  if (badge) {
    badge.innerHTML = `
      <span class="pulse-ring"></span>
      <span class="pulse-dot"></span>
      ${stalled ? "STALLED" : "ACTIVE"}
    `;
  }

  const sender = document.querySelector(
    ".channel-node:not(.channel-node-right) .channel-node-addr"
  );

  const receiver = document.querySelector(
    ".channel-node-right .channel-node-addr"
  );

  if (sender) {
    sender.textContent = ANALYSIS.connection.sender;
  }

  if (receiver) {
    receiver.textContent = ANALYSIS.connection.receiver;
  }

  const level = document.getElementById("gauge-level");
  const value = document.getElementById("gauge-value");

  if (level && value) {
    const windowValue = stalled ? 0 : 4096;

    level.style.width = stalled ? "0%" : "100%";
    level.style.background = stalled ? "var(--alert)" : "";
    value.textContent = windowValue;
  }
}

/* ============================================================
   NAVIGATION
   ============================================================ */

const PAGE_META = {
  dashboard: {
    title: "Dashboard",
    sub: "TCP receive-window monitoring"
  },
  connection: {
    title: "TCP Connection",
    sub: "Sender / receiver flow-control state"
  },
  timeline: {
    title: "Event Timeline",
    sub: "Chronological packet-level events"
  },
  stall: {
    title: "Stall Analysis",
    sub: "Duration and frequency of receive-window stalls"
  },
  packets: {
    title: "Packet Events",
    sub: "Full packet-level event log"
  },
  pcap: {
    title: "PCAP Analysis",
    sub: "Capture file and analyzer output"
  },
  settings: {
    title: "Settings",
    sub: "Analyzer configuration"
  }
};

function initNav() {
  document.querySelectorAll(".nav-item").forEach(button => {
    button.addEventListener("click", () => {
      const page = button.dataset.page;

      document.querySelectorAll(".nav-item").forEach(item => {
        item.classList.remove("active");
      });

      button.classList.add("active");

      document.querySelectorAll(".page").forEach(section => {
        section.classList.remove("active");
      });

      const target = document.getElementById(`page-${page}`);

      if (target) {
        target.classList.add("active");
      }

      const title = document.getElementById("page-title");
      const subtitle = document.getElementById("page-subtitle");

      if (title && PAGE_META[page]) {
        title.textContent = PAGE_META[page].title;
      }

      if (subtitle && PAGE_META[page]) {
        subtitle.textContent = PAGE_META[page].sub;
      }

      window.scrollTo(0, 0);
    });
  });
}

/* ============================================================
   ANALYZE BUTTON — AUTOMATIC CAPTURE
   ============================================================ */

function initAnalyzeButton() {
  const button = document.getElementById("analyze-btn");
  const pauseSelect = document.getElementById("pause-select");

  if (!button) {
    return;
  }

  button.addEventListener("click", async () => {
    if (button.disabled || button.classList.contains("is-running")) {
      return;
    }

    const original = button.innerHTML;
    const pauseSeconds = pauseSelect ? pauseSelect.value : "";

    clearAnalysisView(
      "A fresh capture is running. Results will appear when it completes.",
      "Capturing..."
    );

    button.classList.add("is-running");
    button.disabled = true;

    button.innerHTML = `
      <svg
        width="15"
        height="15"
        viewBox="0 0 16 16"
        fill="none"
      >
        <circle
          cx="8"
          cy="8"
          r="6"
          stroke="currentColor"
          stroke-width="1.6"
          stroke-dasharray="28"
          stroke-dashoffset="10"
        />
      </svg>
      Capturing & analyzing…
    `;

    try {
      console.log(
        "Starting TCP-ZeroGuard automatic capture and analysis..."
      );

      const result = await runAnalysis(pauseSeconds);

      if (result.success) {
        console.log(
          "Automatic capture and analysis completed."
        );

        renderAll();
      } else {
        clearAnalysisView(
          "The latest capture failed. No previous results are being shown.",
          "Capture failed"
        );
        showAnalysisError(result.error);
      }
    } catch (error) {
      console.error("Capture and analysis failed:", error);

      clearAnalysisView(
        "The latest capture failed. No previous results are being shown.",
        "Capture failed"
      );

      showAnalysisError(error);
    } finally {
      button.classList.remove("is-running");
      button.disabled = false;
      button.innerHTML = original;
    }
  });
}

function showAnalysisError(error) {
  const message = error?.message || "Unknown error";
  console.error("Capture and analysis failed:", error);
  window.alert(`Capture and analysis failed.\n\n${message}`);
}

/* ============================================================
   TOOLTIPS
   ============================================================ */

function initTooltips() {
  const tooltip = document.getElementById("tooltip");

  if (!tooltip) {
    return;
  }

  const descriptions = {
    alert:
      "Zero window: receiver's advertised window has dropped to 0 bytes.",
    probe:
      "Zero window probe: sender sends a probe to check whether the receiver window has reopened.",
    response:
      "Probe response: receiver acknowledges the zero-window probe.",
    ok:
      "Window reopened: receiver has available buffer space again."
  };

  document.addEventListener("mouseover", event => {
    const tag = event.target.closest?.("[class*='tag-']");

    if (!tag) {
      return;
    }

    const type = [
      "alert",
      "probe",
      "response",
      "ok"
    ].find(value => tag.classList.contains(`tag-${value}`));

    if (!type) {
      return;
    }

    tooltip.textContent = descriptions[type];
    tooltip.classList.add("visible");
  });

  document.addEventListener("mousemove", event => {
    tooltip.style.left = `${event.clientX + 14}px`;
    tooltip.style.top = `${event.clientY + 14}px`;
  });

  document.addEventListener("mouseout", event => {
    if (event.target.closest?.("[class*='tag-']")) {
      tooltip.classList.remove("visible");
    }
  });
}

/* ============================================================
   RENDER EVERYTHING
   ============================================================ */

function renderAll() {
  if (!ANALYSIS) {
    return;
  }

  renderHero();
  renderMetrics();
  renderCascades();
  renderLegend();
  renderTimeline();
  renderStallStats();
  renderStallChart();
  renderPcap();

  tableRows = buildTableRows();
  activeFilter = "all";
  searchTerm = "";
  currentPage = 1;

  const search = document.getElementById("packet-search");
  if (search) {
    search.value = "";
  }

  renderFilterChips();
  renderTable();
}

/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener("DOMContentLoaded", async () => {
  console.log("Starting TCP-ZeroGuard frontend...");

  // Bind page controls before the network request so the UI remains usable
  // when the backend is initially unavailable.
  initTableControls();
  initNav();
  initAnalyzeButton();
  initTooltips();

  if (await loadAnalysis()) {
    renderAll();
  }

  console.log("TCP-ZeroGuard frontend ready.");
});
