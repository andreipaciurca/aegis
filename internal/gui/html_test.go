package gui

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestEmbeddedJavaScriptParses(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not available for JavaScript syntax validation")
	}

	script := embeddedScript(t)
	cmd := exec.Command("node", "--check")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded GUI JavaScript does not parse: %v\n%s", err, out)
	}
}

func TestEmbeddedJavaScriptInitializesDashboard(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not available for JavaScript runtime validation")
	}

	quotedScript, err := json.Marshal(embeddedScript(t))
	if err != nil {
		t.Fatalf("quote embedded script: %v", err)
	}
	runner := `
const vm = require('vm');
const script = ` + string(quotedScript) + `;

class Element {
  constructor(id) {
    this.id = id;
    this.textContent = '';
    this._innerHTML = '';
    this.style = {};
    this.dataset = {};
    this.className = '';
    this.classList = { toggle: (name, on) => {
      this.active = !!on;
      this.className = on ? name : '';
    }};
  }
  set innerHTML(value) { this._innerHTML = String(value); }
  get innerHTML() { return this._innerHTML; }
}

const elements = new Map();
const ids = [
  'year','nav','syncDot','syncOut','startupOut','cards','scoreNum',
  'scoreLabel','scoreWhy','healthWhy','detailsOut','path','scanOut',
  'shieldOut','networkOut','firewallOut','auditOut','checkupOut','aiOut',
  'historyOut','note','headerUpdateBtn'
];
for (const id of ids) elements.set(id, new Element(id));
elements.get('path').value = '';
elements.get('note').value = '';

const views = ['dashboard','scan','shield','network','firewall','audit','checkup','ai','history','details']
  .map((name) => {
    const el = new Element('view-' + name);
    el.dataset.view = name;
    return el;
  });

const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element(id));
    return elements.get(id);
  },
  querySelectorAll(selector) {
    if (selector === '.view') return views;
    if (selector === '.ic[data-ic]') return [];
    if (selector === 'nav button') return [];
    return [];
  },
  querySelector(selector) {
    if (selector === '.view.active') return views.find((v) => v.active) || null;
    return null;
  }
};

const status = {
  health_score: 92,
  health: 'Excellent',
  health_summary: 'Local posture score.',
  health_good: ['Firewall is active'],
  health_issues: [],
  firewall: { enabled: true, backend: 'test firewall' },
  signature_hashes: 1045,
  signature_rules: 10,
  signature_age: '1m0s',
  network_flagged: 0,
  network_total: 12,
  persistence_suspicious: 0,
  persistence_total: 3,
  ransom_alerts: [],
  canaries: 2
};
const startup = {
  running: false,
  report: {
    signature_added: 0,
    signature_total: 1045,
    aegis: { latest: '1.6.2', update: false },
    llama: { tag: 'b10069', release_url: 'https://example.invalid/llama' }
  }
};

const sandbox = {
  document,
  navigator: { clipboard: { writeText: async () => {} } },
  fetch: async (path) => ({
    ok: true,
    json: async () => path === '/api/startup' ? startup : status,
    text: async () => ''
  }),
  setInterval: () => 1,
  clearInterval: () => {},
  setTimeout: () => 1,
  confirm: () => true,
  window: { close: () => {} },
  console
};

(async () => {
  vm.runInNewContext(script, sandbox, { timeout: 1000 });
  for (let i = 0; i < 8; i++) await Promise.resolve();
  const nav = elements.get('nav').innerHTML;
  const cards = elements.get('cards').innerHTML;
  const sync = elements.get('syncOut').textContent;
  if (!nav.includes('Dashboard') || !nav.includes('History')) {
    throw new Error('navigation did not initialize: ' + nav);
  }
  if (!cards.includes('Firewall') || !cards.includes('Ransom Shield')) {
    throw new Error('dashboard cards did not render: ' + cards);
  }
  if (!sync.includes('synced')) {
    throw new Error('sync status was not updated: ' + sync);
  }
})().catch((err) => {
  console.error(err && err.stack || err);
  process.exit(1);
});
`
	cmd := exec.Command("node")
	cmd.Stdin = strings.NewReader(runner)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded GUI JavaScript did not initialize dashboard: %v\n%s", err, out)
	}
}

func TestEmbeddedJavaScriptShowsRestartRequiredAfterInstall(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not available for JavaScript runtime validation")
	}

	quotedScript, err := json.Marshal(embeddedScript(t))
	if err != nil {
		t.Fatalf("quote embedded script: %v", err)
	}
	runner := `
const vm = require('vm');
const script = ` + string(quotedScript) + `;

class Element {
  constructor(id) {
    this.id = id;
    this.textContent = '';
    this._innerHTML = '';
    this.style = {};
    this.dataset = {};
    this.className = '';
    this.classList = { toggle: (name, on) => {
      this.active = !!on;
      this.className = on ? name : '';
    }};
  }
  set innerHTML(value) { this._innerHTML = String(value); }
  get innerHTML() { return this._innerHTML; }
}

const elements = new Map();
const ids = [
  'year','nav','syncDot','syncOut','startupOut','cards','scoreNum',
  'scoreLabel','scoreWhy','healthWhy','detailsOut','path','scanOut',
  'shieldOut','networkOut','firewallOut','auditOut','checkupOut','aiOut',
  'historyOut','note','headerUpdateBtn'
];
for (const id of ids) elements.set(id, new Element(id));
elements.get('path').value = '';
elements.get('note').value = '';

const views = ['dashboard','scan','shield','network','firewall','audit','checkup','ai','history','details']
  .map((name) => {
    const el = new Element('view-' + name);
    el.dataset.view = name;
    return el;
  });

const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element(id));
    return elements.get(id);
  },
  querySelectorAll(selector) {
    if (selector === '.view') return views;
    if (selector === '.ic[data-ic]') return [];
    if (selector === 'nav button') return [];
    return [];
  },
  querySelector(selector) {
    if (selector === '.view.active') return views.find((v) => v.active) || null;
    return null;
  }
};

const status = {
  health_score: 100,
  health: 'Excellent',
  health_summary: 'Local posture score.',
  health_good: ['Firewall is active'],
  health_issues: [],
  firewall: { enabled: true, backend: 'test firewall' },
  signature_hashes: 1067,
  signature_rules: 10,
  signature_age: '1m0s',
  network_flagged: 0,
  network_total: 12,
  persistence_suspicious: 0,
  persistence_total: 3,
  ransom_alerts: [],
  canaries: 2
};
const startup = {
  running: false,
  report: {
    signature_added: 0,
    signature_total: 1067,
    aegis: { latest: '1.7.2', update: true, release_url: 'https://example.invalid/aegis' },
    llama: { tag: 'b10069', release_url: 'https://example.invalid/llama' }
  },
  install: { installed: true, version: '1.7.2', binary_path: '/tmp/aegis' }
};

const sandbox = {
  document,
  navigator: { clipboard: { writeText: async () => {} } },
  fetch: async (path) => ({
    ok: true,
    json: async () => path === '/api/startup' ? startup : status,
    text: async () => ''
  }),
  setInterval: () => 1,
  clearInterval: () => {},
  setTimeout: () => 1,
  confirm: () => true,
  window: { close: () => {} },
  console
};

(async () => {
  vm.runInNewContext(script, sandbox, { timeout: 1000 });
  for (let i = 0; i < 8; i++) await Promise.resolve();
  const banner = elements.get('startupOut').innerHTML;
  if (!banner.includes('Aegis 1.7.2 installed') || !banner.includes('restart required')) {
    throw new Error('startup banner did not show restart-required install state: ' + banner);
  }
  if (banner.includes('Aegis 1.7.2 available')) {
    throw new Error('startup banner still says available after install: ' + banner);
  }
})().catch((err) => {
  console.error(err && err.stack || err);
  process.exit(1);
});
`
	cmd := exec.Command("node")
	cmd.Stdin = strings.NewReader(runner)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded GUI JavaScript did not show restart-required state: %v\n%s", err, out)
	}
}

func TestEmbeddedGUIHasExpectedShellContracts(t *testing.T) {
	required := []string{
		`id="cards"`,
		`id="syncOut"`,
		`id="startupOut"`,
		`data-view="dashboard"`,
		`data-view="history"`,
		`onclick="updateSigs()"`,
		`onclick="quitApp()"`,
		`/api/startup`,
		`/api/status`,
		`/api/update`,
		`/api/ai/install`,
		`/api/ai/chat`,
		`/api/ai/advice`,
		`onclick="aiInstall()"`,
		`id="chatPrompt"`,
		`id="chatSendBtn"`,
	}
	for _, want := range required {
		if !strings.Contains(indexHTML, want) {
			t.Fatalf("indexHTML missing GUI contract %q", want)
		}
	}
}

func embeddedScript(t *testing.T) string {
	t.Helper()
	start := strings.Index(indexHTML, "<script>")
	end := strings.LastIndex(indexHTML, "</script>")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("indexHTML should contain one executable script block")
	}
	return strings.TrimSpace(indexHTML[start+len("<script>") : end])
}
