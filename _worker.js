import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIP = '';
//let sub = '';
let subConverter = atob('U3ViQXBpLkNtbGlVc3NzUy5OZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let enableSocks = false;
let enableHttp = false;
let noTLS = 'false';
const expire = 4102329600;//2099-12-31
let proxyIPs;
let socks5s;
let go2Socks5s = [
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*.loadshare.org',
];
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;//CSV备注所在列偏移量
let FileName = atob('ZWRnZXR1bm5lbA==');
let BotToken;
let ChatID;
let proxyhosts = [];
let proxyhostsURL;
let 请求CF反代IP = 'false';
const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let 有效时间 = 30;
let 更新时间 = 3;
let userIDLow;
let userIDTime = "";
let proxyIPPool = [];
let path = '/?ed=2560';
let 动态UUID = userID;
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
let SCV = 'true';
let allowInsecure = '&allowInsecure=1';



export default {
    async fetch(request, env, ctx) {
        try {
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;
            if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
                动态UUID = env.KEY || env.TOKEN || userID;
                有效时间 = Number(env.TIME) || 有效时间;
                更新时间 = Number(env.UPTIME) || 更新时间;
                const userIDs = await 生成动态UUID(动态UUID);
                userID = userIDs[0];
                userIDLow = userIDs[1];
            } else 动态UUID = userID;

            if (!userID) {
                return new Response('请设置你的UUID变量，或尝试重试部署，检查变量是否生效？', {
                    status: 404,
                    headers: {
                        "Content-Type": "text/plain;charset=utf-8",
                    }
                });
            }
            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);
            const fakeUserIDMD5 = await 双重哈希(`${userID}${timestamp}`);
            const fakeUserID = [
                fakeUserIDMD5.slice(0, 8),
                fakeUserIDMD5.slice(8, 12),
                fakeUserIDMD5.slice(12, 16),
                fakeUserIDMD5.slice(16, 20),
                fakeUserIDMD5.slice(20)
            ].join('-');

            const fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(13, 19)}`;

            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = await 整理(proxyIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
            proxyIP = proxyIP ? proxyIP.toLowerCase() : request.cf.colo + '.PrOXYip.CMLiussss.NeT';
            socks5Address = env.HTTP || env.SOCKS5 || socks5Address;
            socks5s = await 整理(socks5Address);
            socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
            enableHttp = env.HTTP ? true : socks5Address.toLowerCase().includes('http://');
            socks5Address = socks5Address.split('//')[1] || socks5Address;
            if (env.GO2SOCKS5) go2Socks5s = await 整理(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await 整理(env.CFPORTS);
            if (env.BAN) banHosts = await 整理(env.BAN);
            if (socks5Address) {
                try {
                    socks5AddressParser(socks5Address);
                    请求CF反代IP = env.RPROXYIP || 'false';
                    enableSocks = true;
                } catch (err) {
                    let e = err;
                    console.log(e.toString());
                    请求CF反代IP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
                    enableSocks = false;
                }
            } else {
                请求CF反代IP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
            }

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                if (env.ADD) addresses = await 整理(env.ADD);
                if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
                if (env.ADDNOTLS) addressesnotls = await 整理(env.ADDNOTLS);
                if (env.ADDNOTLSAPI) addressesnotlsapi = await 整理(env.ADDNOTLSAPI);
                if (env.ADDCSV) addressescsv = await 整理(env.ADDCSV);
                DLS = Number(env.DLS) || DLS;
                remarkIndex = Number(env.CSVREMARK) || remarkIndex;
                BotToken = env.TGTOKEN || BotToken;
                ChatID = env.TGID || ChatID;
                FileName = env.SUBNAME || FileName;
                subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
                if (subEmoji == '0') subEmoji = 'false';
                if (env.LINK) link = await 整理(env.LINK);
                let sub = env.SUB || '';
                subConverter = env.SUBAPI || subConverter;
                if (subConverter.includes("http://")) {
                    subConverter = subConverter.split("//")[1];
                    subProtocol = 'http';
                } else {
                    subConverter = subConverter.split("//")[1] || subConverter;
                }
                subConfig = env.SUBCONFIG || subConfig;
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub').toLowerCase();
                if (url.searchParams.has('notls')) noTLS = 'true';



                SCV = env.SCV || SCV;
                if (!SCV || SCV == '0' || SCV == 'false') allowInsecure = '';
                else SCV = 'true';
                const 路径 = url.pathname.toLowerCase();
                if (路径 == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response(await nginx(), {
                        status: 200,
                        headers: {
                            'Content-Type': 'text/html; charset=UTF-8',
                        },
                    });
                } else if (路径 == `/${fakeUserID}`) {
                    const fakeConfig = await 生成配置信息(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', 请求CF反代IP, url, fakeUserID, fakeHostName, env);
                    return new Response(`${fakeConfig}`, { status: 200 });
                } else if ((url.pathname == `/${动态UUID}/config.json` || 路径 == `/${userID}/config.json`) && url.searchParams.get('token') === await 双重哈希(fakeUserID + UA)) {
                    return await config_Json(userID, request.headers.get('Host'), sub, UA, 请求CF反代IP, url, fakeUserID, fakeHostName, env);
                } else if (url.pathname == `/${动态UUID}/edit` || 路径 == `/${userID}/edit`) {
                    return await KV(request, env);
                } else if (url.pathname == `/${动态UUID}/bestip` || 路径 == `/${userID}/bestip`) {
                    return await bestIP(request, env);
                } else if (url.pathname == `/${动态UUID}` || 路径 == `/${userID}`) {
                    await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
                    const vlxxxConfig = await 生成配置信息(userID, request.headers.get('Host'), sub, UA, 请求CF反代IP, url, fakeUserID, fakeHostName, env);
                    const now = Date.now();
                    //const timestamp = Math.floor(now / 1000);
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;
                    if ((env.CF_EMAIL && env.CF_APIKEY) || (env.CF_ID && env.CF_APITOKEN)) {
                        const usage = await getUsage(env.CF_ID, env.CF_EMAIL, env.CF_APIKEY, env.CF_APITOKEN, env.CF_ALL);
                        pagesSum = usage[1];
                        workersSum = usage[2];
                        total = env.CF_ALL ? Number(env.CF_ALL) : (1024 * 100); // 100K
                    }
                    if (userAgent && userAgent.includes('mozilla')) {
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
                                //"Content-Type": "text/plain;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Profile-web-page-url": request.url.includes('?') ? request.url.split('?')[0] : request.url,
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            }
                        });
                    }
                } else {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response('Wrong UUID', { status: 404 });
                }
            } else {
                socks5Address = url.searchParams.get('socks5') || url.searchParams.get('http') || socks5Address;
                enableHttp = url.searchParams.get('http') ? true : enableHttp;
                go2Socks5s = url.searchParams.has('globalproxy') ? ['all in'] : go2Socks5s;

                if (url.pathname.toLowerCase().includes('/socks5=')) socks5Address = url.pathname.split('5=')[1];
                else if (url.pathname.toLowerCase().includes('/socks://') || url.pathname.toLowerCase().includes('/socks5://') || url.pathname.toLowerCase().includes('/http://')) {
                    enableHttp = url.pathname.includes('http://');
                    socks5Address = url.pathname.split('://')[1].split('#')[0];
                    if (socks5Address.includes('@')) {
                        const lastAtIndex = socks5Address.lastIndexOf('@');
                        let userPassword = socks5Address.substring(0, lastAtIndex).replaceAll('%3D', '=');
                        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                        socks5Address = `${userPassword}@${socks5Address.substring(lastAtIndex + 1)}`;
                    }
                    go2Socks5s = ['all in'];//开启全局SOCKS5
                }

                if (socks5Address) {
                    try {
                        socks5AddressParser(socks5Address);
                        enableSocks = true;
                    } catch (err) {
                        let e = err;
                        console.log(e.toString());
                        enableSocks = false;
                    }
                } else {
                    enableSocks = false;
                }

                /**
                * 解析 proxyIP 的规则（局部变量，不直接受全局 proxyIP 影响）
                * 规则：
                *  1. 优先读取查询参数 ?proxyip=xxx 作为候选
                *  2. 如果路径是 /proxyip=xxx 或 /proxyip.xxx，则以路径为准（并标记 matchedProxyPath）
                *  3. 如果路径匹配不上前两条，则检查特定路径（sg/hk/jp/us.dtcs520.com）
                *  4. 如果前两条路径未匹配（matchedProxyPath === false），**强制覆盖**为默认值 'sg.dtcs520.com'
                */
                {
                // 使用局部变量避免受到上层全局变量的干扰
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

                      return handleWebSocket(request);
                  }
              } catch (err) {
                  let e = err;
                  return new Response(e.toString());
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






/**
 * 双重MD5哈希函数
 * 这个函数对输入文本进行两次MD5哈希，增强安全性
 * 第二次哈希使用第一次哈希结果的一部分作为输入
 * 
 * @param {string} 文本 要哈希的文本
 * @returns {Promise<string>} 双重哈希后的小写十六进制字符串
 */
async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();

    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    return 第二次十六进制.toLowerCase();
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


//////////////////////////////////////////////////////////////////////
// WebSocket 处理函数（简化版，保留 UDP DNS）
//////////////////////////////////////////////////////////////////////
async function handleWebSocket(request) {
  const [client, ws] = Object.values(new WebSocketPair());
  ws.accept();

  let remote = null,
      udpWriter = null,
      isDNS = false;

  new ReadableStream({
      start(ctrl) {
          ws.addEventListener('message', e => ctrl.enqueue(e.data));
          ws.addEventListener('close', () => {
              remote?.close();
              ctrl.close();
          });
          ws.addEventListener('error', () => {
              remote?.close();
              ctrl.error();
          });

          const early = request.headers.get('sec-websocket-protocol');
          if (early) {
              try {
                  ctrl.enqueue(Uint8Array.from(
                      atob(early.replace(/-/g, '+').replace(/_/g, '/')),
                      c => c.charCodeAt(0)
                  ).buffer);
              } catch { }
          }
      }
  }).pipeTo(new WritableStream({
      async write(data) {
          // UDP DNS 数据优先处理
          if (isDNS) return udpWriter?.write(data);

          // 如果 TCP 已连接，直接转发数据
          if (remote) {
              const w = remote.writable.getWriter();
              await w.write(data);
              w.releaseLock();
              return;
          }

          if (data.byteLength < 24) return;

          // UUID 验证
          const uuidBytes = new Uint8Array(data.slice(1, 17));
          const checkUUID = (uuid) => {
              const hex = uuid.replace(/-/g, '');
              for (let i = 0; i < 16; i++) {
                  if (uuidBytes[i] !== parseInt(hex.substr(i * 2, 2), 16)) return false;
              }
              return true;
          };
          if (!checkUUID(userID) && !(userIDLow && checkUUID(userIDLow))) return;

          const view = new DataView(data);
          const version = view.getUint8(0);
          const optLen = view.getUint8(17);
          const cmd = view.getUint8(18 + optLen);
          if (cmd !== 1 && cmd !== 2) return;

          let pos = 19 + optLen;
          const port = view.getUint16(pos);
          const type = view.getUint8(pos + 2);
          pos += 3;

          let addr = '';
          if (type === 1) {
              addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
              pos += 4;
          } else if (type === 2) {
              const len = view.getUint8(pos++);
              addr = new TextDecoder().decode(data.slice(pos, pos + len));
              pos += len;
          } else if (type === 3) {
              const ipv6 = [];
              for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos).toString(16));
              addr = ipv6.join(':');
          } else return;

          if (banHosts.includes(addr)) throw new Error(`黑名单关闭 TCP 出站连接 ${addr}`);

          const header = new Uint8Array([version, 0]);
          const payload = data.slice(pos);

          // UDP DNS 处理
          if (cmd === 2) {
              if (port !== 53) return;
              isDNS = true;
              let sent = false;
              const { readable, writable } = new TransformStream({
                  transform(chunk, ctrl) {
                      for (let i = 0; i < chunk.byteLength;) {
                          const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
                          ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
                          i += 2 + len;
                      }
                  }
              });

              readable.pipeTo(new WritableStream({
                  async write(query) {
                      try {
                          const resp = await fetch('https://1.1.1.1/dns-query', {
                              method: 'POST',
                              headers: { 'content-type': 'application/dns-message' },
                              body: query
                          });
                          if (ws.readyState === 1) {
                              const result = new Uint8Array(await resp.arrayBuffer());
                              ws.send(new Uint8Array([...(sent ? [] : header),
                                  result.length >> 8, result.length & 0xff, ...result
                              ]));
                              sent = true;
                          }
                      } catch { }
                  }
              }));
              udpWriter = writable.getWriter();
              return udpWriter.write(payload);
          }

          // TCP 连接（首次直连 + fallback）
          let sock = null;
          try {
              sock = connect({ hostname: addr, port });
              await sock.opened;
          } catch {
              // 如果直连失败，用 proxyIP 重试
              try {
                  sock = connect({ hostname: proxyIP, port: port }); // 硬编码测试
                  await sock.opened;
              } catch (err) {
                  // 两次都失败，直接返回错误（不再连接默认地址）
                  return { hasError: true, message: `connect failed: ${err.message}` };
              }
          }

          remote = sock;
          const w = sock.writable.getWriter();
          await w.write(payload);
          w.releaseLock();

          let sent = false;
          sock.readable.pipeTo(new WritableStream({
              write(chunk) {
                  if (ws.readyState === 1) {
                      ws.send(sent ? chunk : new Uint8Array([...header, ...new Uint8Array(chunk)]));
                      sent = true;
                  }
              },
              close: () => ws.readyState === 1 && ws.close(),
              abort: () => ws.readyState === 1 && ws.close()
          })).catch(() => { });
      }
  })).catch(() => { });

  return new Response(null, { status: 101, webSocket: client });
}
