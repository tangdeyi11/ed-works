import { connect } from 'cloudflare:sockets';

// ============================
// 全局变量声明（精简版）
// ============================
let userID = '';          // 用户 UUID
let userIDLow;            // UUID 小写形式
let 动态UUID = userID;     // 动态生成 UUID 用

let proxyIP = '';          // 全局 proxyIP
let proxyIPs;              // 可能的 proxyIP 列表

const expire = 4102329600; // 订阅过期时间（2099-12-31）

// 地址相关数组
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];

// CSV/订阅相关设置
let DLS = 8;               // 默认下载限制
let remarkIndex = 1;       // CSV 备注所在列偏移
let FileName = atob('ZWRnZXR1bm5lbA=='); // 默认文件名 base64 解码
let BotToken;              // TG Bot Token

// 安全/全局开关
let SCV = 'true';          // 是否允许不安全链接
let allowInsecure = '&allowInsecure=1';
let noTLS = 'false';       // 是否强制不使用 TLS
let 请求CF反代IP = 'false'; // 是否请求 CF 反代 IP

// ============================
// Export default 入口
// ============================
export default {
    async fetch(request, env, ctx) {
        try {
            // ------------------------
            // 获取 UA
            // ------------------------
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();

            // ------------------------
            // 解析 UUID
            // ------------------------
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;

            // 如果有 KEY/TOKEN 或 UUID 无效，则生成动态 UUID
            if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
                动态UUID = env.KEY || env.TOKEN || userID;
                const userIDs = await 生成动态UUID(动态UUID);
                userID = userIDs[0];
                userIDLow = userIDs[1];
            } else {
                动态UUID = userID;
            }

            if (!userID) {
                // UUID 未设置时返回错误
                return new Response('请设置你的UUID变量，或尝试重试部署，检查变量是否生效？', {
                    status: 404,
                    headers: { "Content-Type": "text/plain;charset=utf-8" }
                });
            }

            // ------------------------
            // 生成伪 ID 和 HostName（用于订阅校验）
            // ------------------------
            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);

            const fakeUserIDMD5 = await MD5MD5(`${userID}${timestamp}`);
            const fakeUserID = [
                fakeUserIDMD5.slice(0, 8),
                fakeUserIDMD5.slice(8, 12),
                fakeUserIDMD5.slice(12, 16),
                fakeUserIDMD5.slice(16, 20),
                fakeUserIDMD5.slice(20)
            ].join('-');

            const fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(13, 19)}`;

            // ------------------------
            // proxyIP 解析（非 WebSocket 分支）
            // ------------------------
            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = proxyIP ? await 整理(proxyIP) : [];
            proxyIP = proxyIPs.length > 0 
                ? proxyIPs[Math.floor(Math.random() * proxyIPs.length)].toLowerCase()
                : (request.cf?.colo || 'sg') + '.dtcs520.com';
            
            // 请求 CF 反代 IP
            请求CF反代IP = env.RPROXYIP || (!proxyIP ? 'true' : 'false');

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);

            // ------------------------
            // HTTP 普通请求分支
            // ------------------------
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                if (env.ADD) addresses = await 整理(env.ADD);
                if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
                if (env.ADDNOTLS) addressesnotls = await 整理(env.ADDNOTLS);
                if (env.ADDNOTLSAPI) addressesnotlsapi = await 整理(env.ADDNOTLSAPI);
                if (env.ADDCSV) addressescsv = await 整理(env.ADDCSV);

                DLS = Number(env.DLS) || DLS;
                remarkIndex = Number(env.CSVREMARK) || remarkIndex;
                BotToken = env.TGTOKEN || BotToken;
                FileName = env.SUBNAME || FileName;

                let sub = env.SUB || '';
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') {
                    sub = url.searchParams.get('sub').toLowerCase();
                }

                if (url.searchParams.has('notls')) noTLS = 'true';

                SCV = env.SCV || SCV;
                if (!SCV || SCV == '0' || SCV == 'false') allowInsecure = '';
                else SCV = 'true';

                const 路径 = url.pathname.toLowerCase();

                // ------------------------
                // 路径处理：主页
                // ------------------------
                if (路径 == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else return new Response(await nginx(), {
                        status: 200,
                        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
                    });

                // ------------------------
                // 路径处理：伪订阅
                // ------------------------
                } else if (路径 == `/${fakeUserID}`) {
                    const fakeConfig = await getVLXXXConfig(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', url);
                    return new Response(`${fakeConfig}`, { status: 200 });

                // ------------------------
                // 路径处理：config.json 请求
                // ------------------------
                } else if ((url.pathname == `/${动态UUID}/config.json` || 路径 == `/${userID}/config.json`) 
                    && url.searchParams.get('token') === await MD5MD5(fakeUserID + UA)) {

                    return await config_Json(userID, request.headers.get('Host'), sub, UA, 请求CF反代IP, url, fakeUserID, fakeHostName, env);

                // ------------------------
                // 路径处理：订阅下载
                // ------------------------
                } else if (url.pathname == `/${动态UUID}` || 路径 == `/${userID}`) {

                    await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'),
                        `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);

                    const vlxxxConfig = await getVLXXXConfig(userID, request.headers.get('Host'), sub, UA, url);

                    const now = Date.now();
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);

                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);

                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;

                    if (userAgent.includes('mozilla')) {
                        return new Response(vlxxxConfig, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                                "Cache-Control": "no-store",
                            }
                        });
                    } else {
                        return new Response(vlxxxConfig, {
                            status: 200,
                            headers: {
                                "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
                                "Profile-Update-Interval": "6",
                                "Profile-web-page-url": request.url.includes('?') ? request.url.split('?')[0] : request.url,
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            }
                        });
                    }

                } else {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else return new Response('Wrong UUID', { status: 404 });
                }

            // ------------------------
            // WebSocket 分支
            // 🔥 删除 SOCKS5 相关逻辑
            // ------------------------
            } else {
                /**
                 * 解析 proxyIP 的规则（局部变量，不直接受全局 proxyIP 影响）
                 * 规则：
                 *  1. 优先读取查询参数 ?proxyip=xxx 作为候选
                 *  2. 如果路径是 /proxyip=xxx 或 /proxyip.xxx，则以路径为准（并标记 matchedProxyPath）
                 *  3. 如果路径匹配不上前两条，则检查特定路径（sg/hk/jp/tw/us.dtcs520.com）
                 *  4. 如果前两条路径未匹配（matchedProxyPath === false），**强制覆盖**为默认值 'sg.dtcs520.com'
                 */
                {
                    // 先取 query 参数
                    let pickedProxyIP = url.searchParams.get('proxyip'); // query 参数优先,可能为 null 或 ''
                    let matchedProxyPath = false;          // 标记路径匹配是否成功
                    const path = url.pathname.toLowerCase();

                    // 路径匹配：/proxyip=xxx 或 /proxyip.xxx
                    if (/\/proxyip=/i.test(path)) {
                        pickedProxyIP = path.split('/proxyip=')[1] || '';
                        matchedProxyPath = true;
                    } else if (/\/proxyip\./i.test(path)) {
                        pickedProxyIP = `proxyip.${(path.split('/proxyip.')[1] || '')}`;
                        matchedProxyPath = true;
                    } else if (/sg.dtcs520.com/i.test(path)) {
                    // 特殊路径匹配,（不会影响 matchedProxyPath）
                        pickedProxyIP = 'sg.dtcs520.com';
                    } else if (/hk.dtcs520.com/i.test(path)) {
                        pickedProxyIP = 'hk.dtcs520.com';
                    } else if (/jp.dtcs520.com/i.test(path)) {
                        pickedProxyIP = 'jp.dtcs520.com';
					} else if (/tw.dtcs520.com/i.test(path)) {
                        pickedProxyIP = 'tw.dtcs520.com';
                    } else if (/us.dtcs520.com/i.test(path)) {
                        pickedProxyIP = 'us.dtcs520.com';
                    }

                    // 兜底逻辑：路径没匹配且 query 参数为空
                    if (!matchedProxyPath && (!pickedProxyIP || pickedProxyIP === '')) {
                        pickedProxyIP = 'sg.dtcs520.com';
                    }

                    // 最终把局部解析结果写回全局 proxyIP（写回全局变量）
                    proxyIP = pickedProxyIP;
                }

                // WebSocket 请求处理
                return handleWebSocket(request);
            }

        } catch (err) {
            // 捕获全局异常
            return new Response(err.toString());
        }
    },
};


/**
 * 这不是真正的 UUID 验证，而是一个简化的版本
 * @param {string} uuid 要验证的 UUID 字符串
 * @returns {boolean} 如果字符串匹配 UUID 格式则返回 true，否则返回 false
 */
function isValidUUID(uuid) {
    // 定义一个正则表达式来匹配 UUID 格式
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    // 使用正则表达式测试 UUID 字符串
    return uuidRegex.test(uuid);
}


//输入UUID后的页面
async function sendMessage(title, ip, body) {
    // noop or implement Telegram / webhook sending if desired
    try { console.log('sendMessage', title, ip, body); } catch (e) {}
  }

async function getVLXXXConfig(userId, host, subVal, ua, url) {
    // Minimal config generator stub. Replace with your real implementation.
    return `# VLXXX config\nuser:${userId}\nhost:${host}\nsub:${subVal}\nua:${ua}\n`;
  }

/**
 * 双重MD5哈希函数
 * 这个函数对输入文本进行两次MD5哈希，增强安全性
 * 第二次哈希使用第一次哈希结果的一部分作为输入
 * 
 * @param {string} text 要哈希的文本
 * @returns {Promise<string>} 双重哈希后的小写十六进制字符串
 */
async function MD5MD5(text) {
    const encoder = new TextEncoder();
    const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
    const firstPassArray = Array.from(new Uint8Array(firstPass));
    const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
    const secondPassArray = Array.from(new Uint8Array(secondPass));
    const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return secondHex.toLowerCase();
  }



async function 整理(内容) {
    // 将制表符、双引号、单引号和换行符都替换为逗号
    // 然后将连续的多个逗号替换为单个逗号
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');

    // 删除开头和结尾的逗号（如果有的话）
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

    // 使用逗号分割字符串，得到地址数组
    const 地址数组 = 替换后的内容.split(',');

    return 地址数组;
}


async function nginx() {
    const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
    return text;
}


/**
 * WebSocket 处理函数 (稳定版)
 * 功能：
 *   1. TCP/UDP 代理转发
 *   2. DNS over HTTPS
 *   3. WebSocket 输入流 → TCP/UDP 输出流
 *   4. 自动 fallback proxyIP
 *   5. UUID 校验
 *   6. 全局异常捕获，防止 POP 切换/区域切换导致 Worker 崩溃
 */
async function handleWebSocket(request) {
  // 创建 WebSocketPair，返回 client 给浏览器
  const [client, ws] = Object.values(new WebSocketPair());
  ws.accept();

  let remote = null;      // TCP 远端连接
  let udpWriter = null;   // UDP 写入器
  let isDNS = false;      // 是否 DNS 模式
  let closed = false;     // 是否已关闭
  let tcpWriter = null;   // ✅ 新增：TCP 写入器（全局复用）
  let writeQueue = Promise.resolve();  // ✅ 写入队列（防并发 write 导致异常）
  

  function safeWrite(writer, chunk) {
    if (!writer) return;

    writeQueue = writeQueue
      .then(() => writer.write(chunk))
      .catch(() => {});
  }
  

  // 清理函数，保证多次调用安全
  const cleanup = () => {
    if (closed) return;
    closed = true;
    try { tcpWriter?.releaseLock?.(); } catch {}
    try { remote?.close(); } catch {}
    try { ws?.close(); } catch {}
  };

  const decoder = new TextDecoder(); // 全局 TextDecoder，用于解析字符串地址

  // WebSocket → ReadableStream
  const inputStream = new ReadableStream({
    start(ctrl) {
      // 接收 WebSocket 消息
      ws.addEventListener('message', (e) => ctrl.enqueue(e.data));
      ws.addEventListener('close', cleanup);
      ws.addEventListener('error', () => {
        ctrl.error(new Error('WebSocket error'));
        cleanup();
      });

      // 支持早期 sec-websocket-protocol 中传输二进制
      const early = request.headers.get('sec-websocket-protocol');
      if (early) {
        try {
          const binary = Uint8Array.from(
            atob(early.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
          );
          ctrl.enqueue(binary.buffer);
        } catch {}
      }
    },
    cancel() {
      cleanup();
    }
  });

  // ===== 核心修改点：pipeTo 加全局 catch =====
  inputStream.pipeTo(new WritableStream({
    async write(data) {
      try {
        if (closed) return;

        // --- UDP DNS 模式直接写入 ---
        if (isDNS) return udpWriter?.write(data);

        // --- TCP 已连接直接写入 ---
        if (remote) {
          safeWrite(tcpWriter, data);
          return;
        }

        // 校验最小包长度
        if (data.byteLength < 24) return;

        // 验证 UUID
        const uuidBytes = new Uint8Array(data.slice(1, 17));
        const checkUUID = (uuid) => {
          const hex = uuid.replace(/-/g, '');
          for (let i = 0; i < 16; i++)
            if (uuidBytes[i] !== parseInt(hex.substr(i*2,2),16)) return false;
          return true;
        };
        if (!checkUUID(userID) && !(userIDLow && checkUUID(userIDLow))) return;

        const view = new DataView(data);
        const version = view.getUint8(0);
        const optLen = view.getUint8(17);
        const cmd = view.getUint8(18 + optLen);
        if (![1,2].includes(cmd)) return;

        // 解析端口和地址类型
        let pos = 19 + optLen;
        const port = view.getUint16(pos);
        const type = view.getUint8(pos+2);
        pos += 3;

        let addr = '';
        if (type===1) { // IPv4
          addr = `${view.getUint8(pos)}.${view.getUint8(pos+1)}.${view.getUint8(pos+2)}.${view.getUint8(pos+3)}`;
          pos +=4;
        } else if (type===2) { // 域名
          const len = view.getUint8(pos++);
          addr = decoder.decode(data.slice(pos,pos+len));
          pos += len;
        } else if (type===3) { // IPv6
          const ipv6 = [];
          for (let i=0;i<8;i++,pos+=2)
            ipv6.push(view.getUint16(pos).toString(16));
          addr = ipv6.join(':');
        } else return;

        const header = new Uint8Array([version,0]);
        const payload = data.slice(pos);

        // ===== UDP DNS =====
        if(cmd===2 && port===53){
          isDNS=true;
          const { readable, writable } = new TransformStream({
            transform(chunk, ctrl){
              let i=0;
              while(i<chunk.byteLength){
                const len = new DataView(chunk.slice(i,i+2)).getUint16(0);
                ctrl.enqueue(chunk.slice(i+2,i+2+len));
                i+=2+len;
              }
            }
          });

          readable.pipeTo(new WritableStream({
            async write(query){
              try {
                const resp = await fetch('https://dns.google/dns-query', {
                  method:'POST',
                  headers:{'content-type':'application/dns-message'},
                  body: query
                });
                const buf = await resp.arrayBuffer();
                const result = new Uint8Array(buf);

                if (ws.readyState === 1) {
                  try {
                    ws.send(new Uint8Array([
                      ...header,
                      result.length >> 8,
                      result.length & 0xff,
                      ...result
                    ]));
                  } catch {}
                }
              } catch(e){
                console.error('DNS error', e.message);
              }
            },
            close: cleanup,
            abort: cleanup
          })).catch(() => {});

          udpWriter = writable.getWriter();
          try { await udpWriter.write(payload); } catch {}
          return;
        }

        // ===== TCP 连接 =====
        try {
          let remoteConn = connect({ hostname: addr, port });
          await remoteConn.opened;
          remote = remoteConn;
          tcpWriter = remote.writable.getWriter();
        } catch (e1) {
          // 主连接失败，fallback proxyIP
          try {
            const remoteConn2 = connect({ hostname: proxyIP, port });
            await remoteConn2.opened;
            remote = remoteConn2;
            tcpWriter = remote.writable.getWriter();
          } catch (err) {
            console.error('TCP connect failed', addr, port, err.message);
            cleanup();
            return;
          }
        }

        safeWrite(tcpWriter, payload);

        // TCP → WebSocket
        let sent=false;
        remote.readable.pipeTo(new WritableStream({
          write(chunk){
            if(ws.readyState===1){
              try{
                ws.send(sent?chunk:new Uint8Array([...header,...new Uint8Array(chunk)]));
                sent=true;
              }catch{}
            }
          },
          close:cleanup,
          abort:cleanup
        })).catch(() => {});

      } catch(err){
        console.error('inputStream write error', err.message);
        cleanup();
      }
    },
    close: cleanup,
    abort: cleanup
  })).catch(err=>{
    console.error('pipeTo global error', err.message);
    cleanup();
  });

  return new Response(null,{status:101,webSocket:client});
}
