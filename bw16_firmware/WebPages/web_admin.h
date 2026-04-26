#ifndef WEB_ADMIN_H
#define WEB_ADMIN_H

// Tabbed Web UI: Home + Custom SSID Beacon + Handshake Capture
const char WEB_ADMIN_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BW16 Web UI</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:Arial,Helvetica,sans-serif;background:#f5f6f8;color:#222;padding:16px}
    .shell{max-width:800px;margin:0 auto;background:#fff;border:1px solid #e8e8e8;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.06);overflow:hidden}
    .brand{padding:16px 18px;border-bottom:1px solid #eee;background:linear-gradient(180deg,#4caf50,#45a049);color:#fff}
    .brand h1{font-size:18px;margin:0}
    .tabs{display:flex;gap:0;border-bottom:1px solid #eee;background:#fafafa}
    .tab{flex:1;text-align:center;padding:12px 10px;cursor:pointer;font-weight:600;color:#555}
    .tab.active{background:#fff;border-bottom:2px solid #4caf50;color:#2e7d32}
    .page{display:none;padding:16px}
    .page.active{display:block}
    h2{font-size:16px;margin-bottom:8px;color:#333;display:flex;flex-wrap:nowrap;justify-content:center}
    p{margin:8px 0;color:#555;line-height:1.5}
    .card{border:1px solid #eee;border-radius:8px;padding:12px;background:#fafafa}
    #HomeCard{display:flex;justify-content:center;flex-wrap:wrap}
    label{display:block;color:#000;font-size:14px;margin-top:6px}
    input[type=text]{width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:6px}
    .row{margin-top:8px;text-align:center}
    .btn{padding:10px 14px;border:0;border-radius:6px;color:#fff;cursor:pointer;margin-right:8px;display:inline-block}
    .btn-danger{background:#f44336}
    .btn-warning{background:#ff9800}
    .status{margin-top:10px;padding:10px;border-radius:6px;background:#e8f5e9;border:1px solid #4caf50;color:#2e7d32;text-align:center}
    .muted{color:#777;font-size:12px;margin-top:8px}
    .radio-row{text-align:center;margin: 20px;}
    .radio-row>label{display:inline-block;margin-right:12px}
    .muted{text-align:center}
    #mode-help,#mode-help:visited{color:orange}
    footer{padding:12px;text-align:center;color:#999;border-top:1px solid #eee;font-size:12px}
    @media screen and (max-width: 800px) {#ap-select{max-width: 300px;}}
    /* Start-capture loading spinner */
    .spinner{display:none;width:16px;height:16px;border:2px solid #ccc;border-top-color:#4caf50;border-radius:50%;animation:spin 0.8s linear infinite;margin-left:8px;vertical-align:middle}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
  <script>
    function $(id){return document.getElementById(id)}
    function setActive(idx){
      const tabs=document.querySelectorAll('.tab');
      const pages=document.querySelectorAll('.page');
      tabs.forEach((t,i)=>t.classList.toggle('active', i===idx));
      pages.forEach((p,i)=>p.classList.toggle('active', i===idx));
    }
    function show(msg,type){
      const d=document.createElement('div');
      d.textContent=msg; d.className='toast';
      d.style.cssText='position:fixed;left:50%;top:16px;transform:translateX(-50%);background:'+(type==='success'?'#4caf50':'#f44336')+';color:#fff;padding:8px 12px;border-radius:6px;box-shadow:0 4px 10px rgba(0,0,0,.2);z-index:9999;';
      document.body.appendChild(d); setTimeout(()=>d.remove(),2000);
    }
    function refresh(){
      try{ fetch('/status').then(()=>{}).catch(()=>{});}catch(e){}
    }
    function startCustom(){
      const ssid=$('ssid').value.trim(); if(!ssid){show('InputSSID');return}
      if(!confirm('OKAttackRequest，Turn Off。StopWeb UIEndAttack')) return;
      const band=document.querySelector('input[name="band"]:checked').value;
      const body='ssid='+encodeURIComponent(ssid)+'&band='+encodeURIComponent(band);
      try { fetch('/custom-beacon',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}); } catch(e) {}
      show('StartAttack，DisconnectConnect！');
    }
    function stopAll(){
      fetch('/stop',{method:'POST'}).then(r=>r.json()).then(()=>{ show('Stopped','success'); })
        .catch(()=>show('RequestFailed'))
    }
    function startScan(){
      if(!confirm('ShortTurn OffAPScan，DisconnectConnect，DoneRestore。YesNoResume？')) return;
      $('scan-status').textContent = 'Scan...';
      fetch('/handshake/scan',{method:'POST'})
        .then(()=>{ pollScanStatus(); })
        .catch(()=>show('ScanStartFailed'))
    }
    function pollScanStatus(){
      fetch('/handshake/scan-status').then(r=>r.json()).then(st=>{
        if(st.done){ loadOptions(); $('scan-status').textContent = 'Done'; }
        else setTimeout(pollScanStatus, 1500);
      }).catch(()=>setTimeout(pollScanStatus, 2000));
    }
    function loadOptions(){
      fetch('/handshake/options').then(r=>r.text()).then(html=>{
        const sel=$('ap-select');
        sel.innerHTML = html;
        if(sel.options && sel.options.length>0){ sel.selectedIndex = 0; }
      });
    }
    function selectNetwork(bssid){
      fetch('/handshake/select?bssid='+encodeURIComponent(bssid),{method:'POST'}).then(()=>{
        show('SelectNetwork','success');
        document.getElementById('selected-network').style.display = 'block';
      }).catch(()=>show('SelectFailed'))
    }
    function startHandshake(){
      const sel=$('ap-select');
      const bssid = sel && sel.value ? sel.value.trim() : '';
      if(!bssid){ show('SelectTargetAP'); return; }
      const modeEl = document.querySelector('input[name="capmode"]:checked');
      const mode = modeEl ? modeEl.value : 'active';

      // UsageDescConfirmDialog
      const confirmMsg = '⬇UsageDesc⬇\n\n' +
        'StartPacketWeb UIDisconnectConnect，PacketBW16-Kit LED，PacketDoneLED，ConnectWeb UIDownloadHandshake。\n\n' +
        '⚠Note：RestartDeviceWeb UIHandshake，Save！\n\nPacketMedium，StopPacketRSTRestartDevice' +
        'YesNoConfirmStartPacket？';

      if(!confirm(confirmMsg)) return;

      const body = 'bssid='+encodeURIComponent(bssid);
      // SpinnerButton，PacketStart
      const spinner = $('start-loading');
      const startBtn = event && event.target && event.target.closest('button') ? event.target.closest('button') : null;
      if (spinner) spinner.style.display = 'inline-block';
      if (startBtn) startBtn.disabled = true;
      fetch('/handshake/select',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body})
        .then(()=>{
          const body2 = 'mode='+encodeURIComponent(mode);
          return fetch('/handshake/capture',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body: body2});
        })
        .then(()=>{
          show('StartPacket','success');
          document.getElementById('handshake-status').style.display = 'block';
          if (spinner) spinner.style.display = 'none';
          if (startBtn) startBtn.disabled = false;
          setTimeout(checkHandshakeStatus, 1500);
        })
        .catch(()=>{ if (spinner) spinner.style.display = 'none'; if (startBtn) startBtn.disabled = false; show('StartFailed'); })
    }
    function stopHandshake(){
      fetch('/handshake/stop',{method:'POST'}).then(()=>{
        show('StoppedPacket','success');
        document.getElementById('handshake-status').style.display = 'none';
      }).catch(()=>show('StopFailed'))
    }
    function checkHandshakeStatus(){
      fetch('/handshake/status').then(r=>r.json()).then(data=>{
        const hs = $('handshake-status');
        const dl = $('pcap-download');
        const saved = $('saved-section');
        const savedInfo = $('saved-info');
        const savedEmpty = $('saved-empty');
        const savedCounts = $('saved-counts');
        const savedTime = $('saved-time');
        if(data.justCaptured){
          alert('Handshake！');
          // ClearjustCapturedStatus（Delete）
          location.reload();
          return;
        }
        if(data.captured){ hs.style.display='none'; dl.style.display='block'; }
        else if(data.running){ hs.style.display='block'; dl.style.display='none'; setTimeout(checkHandshakeStatus, 2000); }
        else { hs.style.display='none'; dl.style.display='none'; }
        // UpdateSave
        if(data.pcapSize && data.pcapSize>0){
          saved.style.display='block'; savedEmpty.style.display='none'; savedInfo.style.display='block';
          savedCounts.textContent = 'Handshake Count: '+data.hsCount+'/4, Management Frames: '+data.mgmtCount+'/10';
          savedTime.textContent = 'Time(ms): '+data.ts;
        } else {
          saved.style.display='block'; savedInfo.style.display='none'; savedEmpty.style.display='block';
        }
      }).catch(()=>{})
    }
    function deleteSaved(){
      if(!confirm('OKDeleteSaveHandshakeStatsData？')) return;
      fetch('/handshake/delete',{method:'POST'}).then(()=>{ show('Delete','success'); location.reload(); })
        .catch(()=>show('DeleteFailed'))
    }
    function downloadPcap(){
      const a=document.createElement('a');
      a.href='/handshake/download';
      a.download='capture.pcap';
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
    function showModeHelp(){
      alert('ModePacketJamConnect，HandshakeValid99%。\n\nModePacketSendDeauthFrameJamConnect，HandshakeErrorManageFrameFrameHandshakeValid，TestInvalidPacket\n\nHeightModePacketSendManageFrameTimePausePacketDeauthFrameJamConnectResumePacket，PacketValid>90%，SuccessHeightInvalidPacket。Detect，HandshakeWait\n\nUsage：\nMode，（StartHandshake）HeightModeMode，Handshake99%ValidUsageMode。\n\nSmallHint：\nJam，ModeHeightModeDeauthSTASendManageFrame，DeviceValid\n\nHandshakeValid：\n1.Handshake Count4/4，0/42/4Frame，YesLengthTimeTimeout，ClassHandshakeInvalid，Packet\n2.StartPacketHintPacketDoneYesManageFrame，Handshake Count4/4HandshakeInvalid，Packet，PacketMode\nHintPacketDoneHandshake：InvalidPacket，Packet。');
    }
    document.addEventListener('DOMContentLoaded', ()=>{
      setActive(0);
      refresh(); setInterval(refresh,2000);
      // List，Scan，ConnectDisconnect
      loadOptions();
      // InitSaveStatus
      checkHandshakeStatus();
    });
  </script>
</head>
<body>
  <div class="shell">
    <div class="brand"><h1>😽 BW16 Tools · Web UI</h1></div>
    <div class="tabs">
      <div class="tab active" onclick="setActive(0)">/Desc</div>
      <div class="tab" onclick="setActive(1)">BeaconFrameAttack</div>
      <div class="tab" onclick="setActive(2)">Packet</div>
    </div>
    <div class="page active" id="page-home">
      <h2>📌 AboutProj</h2>
      <div class="card" id="HomeCard">
        <p>github.com/FlyingIceyyds/Bw16-Tools</p>
        <p>GPL-3.0，CodeModify</p>
      </div>
      <h2 style="margin-top:14px;">📑 Web UIDesc</h2>
      <div class="status">VersionWeb UIPacketOLEDMenu，</div>
    </div>
    <div class="page" id="page-beacon">
      <h2>📡  SSID BeaconFrameAttack</h2>
      <div class="card">
        <label style="text-align:center;">🖋️ SSID </label>
        <input id="ssid" type="text" placeholder="InputBroadcast SSID">
        <label style="margin-top:8px;text-align:center;">🌐 Packet</label>
        <div class="radio-row">
          <label><input type="radio" name="band" value="mixed" checked> (2.4G+5G)</label>
          <label><input type="radio" name="band" value="2g"> 2.4G</label>
          <label><input type="radio" name="band" value="5g"> 5G</label>
        </div>
        <div class="row">
          <button class="btn btn-danger" onclick="startCustom()">Start</button>
          <button class="btn btn-warning" onclick="stopAll()">Stop</button>
        </div>
        <div class="muted">Web UIUsed，Attack。UsageOLEDMenu</div>
      </div>
    </div>
    <div class="page" id="page-handshake">
      <h2>🔐 WPA/WPA2 Packet</h2>
      <div class="card">
        <p style="text-align:center;">WPA/WPA2 4-wayHandshake</p>
        <p style="color:red;text-align:center;">V2.2VersionUsageOLEDMenuPacket！</p>
        <div class="row" style="gap:8px; align-items:center; justify-content:center; margin-top:8px;">
          <select id="ap-select" style="min-width:80%; padding:8px;">
            <option value="">Loading...List...</option>
          </select><br />
          <span id="scan-status" class="muted">Loading...</span>
        </div>
        <div class="row" style="margin-top: 12px;">
          <div class="radio-row" style="margin-bottom:10px;">
            <label><input type="radio" name="capmode" value="active" checked> Mode</label>
            <label><input type="radio" name="capmode" value="passive"> Mode</label>
            <label><input type="radio" name="capmode" value="efficient"> HeightMode</label><br />
            <a id="mode-help" href="javascript:void(0)" onclick="showModeHelp()" style="margin-left:8px;line-height:50px;">ViewModeDesc</a>
          </div>
          <button class="btn btn-danger" onclick="startHandshake(event)">StartPacket</button><span id="start-loading" class="spinner"></span>
          <button class="btn btn-warning" onclick="stopHandshake()">StopPacket</button>
          <button class="btn" style="background:#607d8b" onclick="startScan()">Scan</button>
        </div>
        <div id="handshake-status" style="margin-top: 16px; display: none;">
          <div class="status">PacketMedium，Wait...</div>
        </div>
        <div id="pcap-download" style="margin-top: 16px; display: none;">
          <div class="status">Handshake！</div>
        </div>
        <div id="saved-section" class="card" style="margin-top:12px; display:none;">
          <div id="saved-empty" class="muted" style="display:none;color:#f44336;">SaveHandshake，StartPacket</div>
          <div id="saved-info" style="display:none;">
            <div id="saved-counts" class="status" style="margin-bottom:8px;"></div>
            <div id="saved-time" class="muted" style="margin-bottom:8px;"></div>
            <div class="row">
              <button class="btn btn-danger" onclick="downloadPcap()">DownloadPCAPFile</button>
              <button class="btn btn-warning" onclick="deleteSaved()">Delete</button>
            </div>
          </div>
        </div>
        <div class="muted">Warning：Security，</div>
      </div>
    </div>
    <footer>© 2025 Bw16-Tools</footer>
  </div>
</body>
</html>
)rawliteral";

#endif
