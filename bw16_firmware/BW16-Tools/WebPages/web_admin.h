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
      const ssid=$('ssid').value.trim(); if(!ssid){show('请输入SSID');return}
      if(!confirm('点击确定将提交攻击请求，同时会关闭当前接入点。停止Web UI可结束攻击')) return;
      const band=document.querySelector('input[name="band"]:checked').value;
      const body='ssid='+encodeURIComponent(ssid)+'&band='+encodeURIComponent(band);
      try { fetch('/custom-beacon',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}); } catch(e) {}
      show('已开始攻击，将断开此接入点连接！');
    }
    function stopAll(){
      fetch('/stop',{method:'POST'}).then(r=>r.json()).then(()=>{ show('已停止','success'); })
        .catch(()=>show('请求失败'))
    }
    function startScan(){
      if(!confirm('将短暂关闭AP进行扫描，期间会断开连接，完成后会自动恢复。是否继续？')) return;
      $('scan-status').textContent = '正在扫描...';
      fetch('/handshake/scan',{method:'POST'})
        .then(()=>{ pollScanStatus(); })
        .catch(()=>show('扫描启动失败'))
    }
    function pollScanStatus(){
      fetch('/handshake/scan-status').then(r=>r.json()).then(st=>{
        if(st.done){ loadOptions(); $('scan-status').textContent = '已完成'; }
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
        show('已选择网络','success');
        document.getElementById('selected-network').style.display = 'block';
      }).catch(()=>show('选择失败'))
    }
    function startHandshake(){
      const sel=$('ap-select');
      const bssid = sel && sel.value ? sel.value.trim() : '';
      if(!bssid){ show('请先选择一个目标AP'); return; }
      const modeEl = document.querySelector('input[name="capmode"]:checked');
      const mode = modeEl ? modeEl.value : 'active';

      // 显示使用说明确认对话框
      const confirmMsg = '⬇使用说明⬇\n\n' +
        '启动抓包后Web UI可能会断开连接，抓包时BW16-Kit LED熄灭，抓包完成后绿色LED重新亮起，可重新连接并访问Web UI下载握手包。\n\n' +
        '⚠注意：重启设备或Web UI将丢失已抓到的握手包，请及时保存！\n\n抓包过程无法中断，停止抓包请直接按下RST重启设备' +
        '是否确认开始抓包？';

      if(!confirm(confirmMsg)) return;

      const body = 'bssid='+encodeURIComponent(bssid);
      // 显示加载动画并临时禁用按钮，直到抓包真正开始
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
          show('开始抓包','success');
          document.getElementById('handshake-status').style.display = 'block';
          if (spinner) spinner.style.display = 'none';
          if (startBtn) startBtn.disabled = false;
          setTimeout(checkHandshakeStatus, 1500);
        })
        .catch(()=>{ if (spinner) spinner.style.display = 'none'; if (startBtn) startBtn.disabled = false; show('启动失败'); })
    }
    function stopHandshake(){
      fetch('/handshake/stop',{method:'POST'}).then(()=>{
        show('已停止抓包','success');
        document.getElementById('handshake-status').style.display = 'none';
      }).catch(()=>show('停止失败'))
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
          alert('已抓取到握手包！');
          // 清除justCaptured标志由后端在下一次状态查询后自然消失（或删除时消失）
          location.reload();
          return;
        }
        if(data.captured){ hs.style.display='none'; dl.style.display='block'; }
        else if(data.running){ hs.style.display='block'; dl.style.display='none'; setTimeout(checkHandshakeStatus, 2000); }
        else { hs.style.display='none'; dl.style.display='none'; }
        // 更新保存区
        if(data.pcapSize && data.pcapSize>0){
          saved.style.display='block'; savedEmpty.style.display='none'; savedInfo.style.display='block';
          savedCounts.textContent = 'Handshake Count: '+data.hsCount+'/4, Management Frames: '+data.mgmtCount+'/10';
          savedTime.textContent = '抓取时间(ms): '+data.ts;
        } else {
          saved.style.display='block'; savedInfo.style.display='none'; savedEmpty.style.display='block';
        }
      }).catch(()=>{})
    }
    function deleteSaved(){
      if(!confirm('确定删除已保存的握手包及统计数据？')) return;
      fetch('/handshake/delete',{method:'POST'}).then(()=>{ show('已删除','success'); location.reload(); })
        .catch(()=>show('删除失败'))
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
      alert('被动模式仅抓包不干扰连接，抓取速度较慢但抓到的握手包有效率为99%。\n\n主动模式在抓包同时发送解除认证帧干扰连接，可以更快抓取握手包但可能会将错误的管理帧当成握手帧导致握手包不完全有效，经测试部分环境可能会抓到无效包\n\n高效模式在抓包时不会发送管理帧但每隔一段时间会暂停抓包突发解除认证帧干扰连接随后继续抓包，抓包有效率>90%，成功率较高同时很少会抓到无效包。但由于更保守的检测逻辑，部分环境下可能抓不到握手包或要等待很久\n\n使用建议：\n优先尝试主动模式，如果出现误判（启动后固定一秒左右抓到握手包）则尝试高效模式或被动模式，如果需要确保抓到的握手包99%有效则使用被动模式。\n\n小提示：\n为了降低干扰，主动模式和高效模式的解除认证采用先STA学习后针对性发送管理帧，通常对移动端设备会更有效\n\n握手包有效性判断：\n1.Handshake Count应为4/4，如果为0/4或2/4等则表示没有抓到完整握手帧，可能是长时间未抓到触发了超时机制，通常此类握手包无效，请重新抓包\n2.如果启动抓包后一秒左右就提示抓包完成可能是管理帧过滤没有生效，即便Handshake Count为4/4此握手包也有可能无效，建议重新抓包，如果多次复现请尝试更换抓包模式\n提示抓包完成但没有抓到握手包：抓到了无效包被自动过滤了，请重新抓包。');
    }
    document.addEventListener('DOMContentLoaded', ()=>{
      setActive(0);
      refresh(); setInterval(refresh,2000);
      // 仅加载现有列表，不自动触发扫描，避免刚连接即断开
      loadOptions();
      // 初始化保存区与状态轮询
      checkHandshakeStatus();
    });
  </script>
</head>
<body>
  <div class="shell">
    <div class="brand"><h1>😽 BW16 Tools · Web UI</h1></div>
    <div class="tabs">
      <div class="tab active" onclick="setActive(0)">首页/说明</div>
      <div class="tab" onclick="setActive(1)">信标帧攻击</div>
      <div class="tab" onclick="setActive(2)">握手抓包</div>
    </div>
    <div class="page active" id="page-home">
      <h2>📌 关于本项目</h2>
      <div class="card" id="HomeCard">
        <p>github.com/FlyingIceyyds/Bw16-Tools</p>
        <p>采用GPL-3.0协议开源，请勿倒卖源代码或修改后闭源售卖</p>
      </div>
      <h2 style="margin-top:14px;">📑 Web UI说明</h2>
      <div class="status">当前版本Web UI仅包含OLED菜单无法操作的功能，不添加重复功能</div>
    </div>
    <div class="page" id="page-beacon">
      <h2>📡 自定义 SSID 信标帧攻击</h2>
      <div class="card">
        <label style="text-align:center;">🖋️ SSID 名称</label>
        <input id="ssid" type="text" placeholder="输入要广播的 SSID">
        <label style="margin-top:8px;text-align:center;">🌐 发包频段</label>
        <div class="radio-row">
          <label><input type="radio" name="band" value="mixed" checked> 混合(2.4G+5G)</label>
          <label><input type="radio" name="band" value="2g"> 2.4G</label>
          <label><input type="radio" name="band" value="5g"> 5G</label>
        </div>
        <div class="row">
          <button class="btn btn-danger" onclick="startCustom()">开始</button>
          <button class="btn btn-warning" onclick="stopAll()">停止</button>
        </div>
        <div class="muted">Web UI会占用部分资源，可能影响攻击效率。如非必要建议使用OLED菜单</div>
      </div>
    </div>
    <div class="page" id="page-handshake">
      <h2>🔐 WPA/WPA2 握手抓包</h2>
      <div class="card">
        <p style="text-align:center;">此功能可以捕获WPA/WPA2 4-way握手包</p>
        <p style="color:red;text-align:center;">V2.2版本后建议使用OLED菜单的快速抓包功能！</p>
        <div class="row" style="gap:8px; align-items:center; justify-content:center; margin-top:8px;">
          <select id="ap-select" style="min-width:80%; padding:8px;">
            <option value="">正在加载列表...</option>
          </select><br />
          <span id="scan-status" class="muted">加载中</span>
        </div>
        <div class="row" style="margin-top: 12px;">
          <div class="radio-row" style="margin-bottom:10px;">
            <label><input type="radio" name="capmode" value="active" checked> 主动模式</label>
            <label><input type="radio" name="capmode" value="passive"> 被动模式</label>
            <label><input type="radio" name="capmode" value="efficient"> 高效模式</label><br />
            <a id="mode-help" href="javascript:void(0)" onclick="showModeHelp()" style="margin-left:8px;line-height:50px;">点击查看模式说明</a>
          </div>
          <button class="btn btn-danger" onclick="startHandshake(event)">开始抓包</button><span id="start-loading" class="spinner"></span>
          <button class="btn btn-warning" onclick="stopHandshake()">停止抓包</button>
          <button class="btn" style="background:#607d8b" onclick="startScan()">重新扫描</button>
        </div>
        <div id="handshake-status" style="margin-top: 16px; display: none;">
          <div class="status">正在抓包中，请等待...</div>
        </div>
        <div id="pcap-download" style="margin-top: 16px; display: none;">
          <div class="status">握手包已捕获！</div>
        </div>
        <div id="saved-section" class="card" style="margin-top:12px; display:none;">
          <div id="saved-empty" class="muted" style="display:none;color:#f44336;">暂无已保存的握手包，请开始抓包</div>
          <div id="saved-info" style="display:none;">
            <div id="saved-counts" class="status" style="margin-bottom:8px;"></div>
            <div id="saved-time" class="muted" style="margin-bottom:8px;"></div>
            <div class="row">
              <button class="btn btn-danger" onclick="downloadPcap()">下载PCAP文件</button>
              <button class="btn btn-warning" onclick="deleteSaved()">删除</button>
            </div>
          </div>
        </div>
        <div class="muted">警告：此功能仅用于安全研究和教育目的，请勿用于非法用途</div>
      </div>
    </div>
    <footer>© 2025 Bw16-Tools</footer>
  </div>
</body>
</html>
)rawliteral";

#endif
