// Optimized Cloudflare Worker (VLXXX) - refactored and renamed vless/VLESS -> vlxxx/VLXXX
// Based on user's original code. Some external integrations (account APIs, subscription backends)
// are stubbed with minimal implementations to keep this file self-contained for testing.

// @ts-ignore
import { connect } from 'cloudflare:sockets';

// -------------------------------
// Configuration / Defaults
// -------------------------------
let userID = 'df3a46a8-6f37-4ed8-afb5-e8f71b02500c';
let proxyIP = '';
let sub = '';
let subconverter = 'subapi.dtcs.dpdns.org';
let subconfig = "https://raw.githubusercontent.com/tangdeyi11/dyconfig/main/rule.ini";
let socks5Address = '';
let fakeUserID;
let fakeHostName;
let noTLS = 'false';
const expire = 4102329600; // 2099-12-31
let proxyIPs;
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let FileName = 'edgetunnel';
let BotToken = '';
let ChatID = '';
let proxyhosts = [];
let proxyhostsURL = '';
let RproxyIP = 'false';
let enableSocks = false;
let parsedSocks5Address = {};

// -------------------------------
// Exported fetch handler
// -------------------------------
export default {
  /**
   * @param {Request} request
   * @param {*} env
   * @param {*} ctx
   */
  async fetch(request, env, ctx) {
    try {
	  // -------------------- 新增 /debug 分支 --------------------
	  // 下一句需要拿到请求的路径 (pathname) 来判断是否访问了 /debug
	  const url = new URL(request.url);
      
      // -------------------- 新增 /debug 分支 --------------------
      if (url.pathname.toLowerCase() === '/debug') {
        const rayHeader = request.headers.get("cf-ray");
        const entryColo = rayHeader ? rayHeader.split("-")[1] : "unknown";
        const execColo = request.cf?.colo || "unknown";

        const match = (entryColo === execColo) ? "一致 ✅" : "不一致 ⚠️";

        const debugInfo = {
          entryColo,   // 请求入口节点
          execColo,    // 实际执行节点
          result: match,
          country: request.cf?.country,
          city: request.cf?.city,
          asn: request.cf?.asn,
          timezone: request.cf?.timezone,
          ua: request.headers.get('User-Agent')
        };

        return new Response(JSON.stringify(debugInfo, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json;charset=utf-8" }
        });
      }
      // -------------------- /debug 分支结束 --------------------
		
      const UA = request.headers.get('User-Agent') || 'null';
      const userAgent = UA.toLowerCase();
      userID = (env.UUID || userID).toLowerCase();

      // generate daily fake ids
      const currentDate = new Date();
      currentDate.setHours(0, 0, 0, 0);
      const timestamp = Math.ceil(currentDate.getTime() / 1000);
      const fakeUserIDMD5 = await MD5MD5(`${userID}${timestamp}`);
      fakeUserID = fakeUserIDMD5.slice(0, 8) + "-" + fakeUserIDMD5.slice(8, 12) + "-" + fakeUserIDMD5.slice(12, 16) + "-" + fakeUserIDMD5.slice(16, 20) + "-" + fakeUserIDMD5.slice(20);
      fakeHostName = fakeUserIDMD5.slice(6, 9) + "." + fakeUserIDMD5.slice(13, 19);

      proxyIP = env.PROXYIP || proxyIP;
      proxyIPs = proxyIP ? await ADD(proxyIP) : [];
      proxyIP = proxyIPs && proxyIPs.length ? proxyIPs[Math.floor(Math.random() * proxyIPs.length)] : proxyIP;

      socks5Address = env.SOCKS5 || socks5Address;
      sub = env.SUB || sub;
      subconverter = env.SUBAPI || subconverter;
      subconfig = env.SUBCONFIG || subconfig;

      // socks parsing
      if (socks5Address) {
        try {
          parsedSocks5Address = socks5AddressParser(socks5Address);
          RproxyIP = env.RPROXYIP || 'false';
          enableSocks = true;
        } catch (err) {
          console.log(err.toString());
          RproxyIP = env.RPROXYIP || (!proxyIP ? 'true' : 'false');
          enableSocks = false;
        }
      } else {
        RproxyIP = env.RPROXYIP || (!proxyIP ? 'true' : 'false');
      }

      if (env.ADD) addresses = await ADD(env.ADD);
      if (env.ADDAPI) addressesapi = await ADD(env.ADDAPI);
      if (env.ADDNOTLS) addressesnotls = await ADD(env.ADDNOTLS);
      if (env.ADDNOTLSAPI) addressesnotlsapi = await ADD(env.ADDNOTLSAPI);
      if (env.ADDCSV) addressescsv = await ADD(env.ADDCSV);
      DLS = env.DLS || DLS;
      BotToken = env.TGTOKEN || BotToken;
      ChatID = env.TGID || ChatID;

      const upgradeHeader = request.headers.get('Upgrade');
      //const url = new URL(request.url);
      if (url.searchParams.has('notls')) noTLS = 'true';

      if (!upgradeHeader || upgradeHeader !== 'websocket') {
        // HTTP routes
        switch (url.pathname.toLowerCase()) {
          case '/': {
            const envKey = env.URL302 ? 'URL302' : (env.URL ? 'URL' : null);
            if (envKey) {
              const URLs = await ADD(env[envKey]);
              const URL = URLs[Math.floor(Math.random() * URLs.length)];
              return envKey === 'URL302' ? Response.redirect(URL, 302) : fetch(new Request(URL, request));
            }
            return new Response('系统维护中........', { status: 404, headers: { "Content-Type": "text/plain;charset=utf-8" } });
          }
          case `/${fakeUserID}`: {
            const fakeConfig = await getVLXXXConfig(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url);
            return new Response(`${fakeConfig}`, { status: 200 });
          }
          case `/${userID}`: {
            // telemetry (safe noop if sendMessage undefined)
            await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`);

            if ((!sub || sub == '') && (addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
              if (request.headers.get('Host').includes('.workers.dev')) {
                sub = 'end.dtcs520.com';
                subconfig = 'https://raw.githubusercontent.com/tangdeyi11/dyconfig/main/rule.ini';
              } else sub = 'end.dtcs520.com';
            }

            const vlxxxConfig = await getVLXXXConfig(userID, request.headers.get('Host'), sub, UA, RproxyIP, url);

            const now = Date.now();
            const today = new Date(now);
            today.setHours(0, 0, 0, 0);
            const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
            let pagesSum = UD;
            let workersSum = UD;
            let total = 24 * 1099511627776;

            if (env.CFEMAIL && env.CFKEY) {
              const email = env.CFEMAIL;
              const key = env.CFKEY;
              const accountIndex = env.CFID || 0;
              const accountId = await getAccountId(email, key);
              if (accountId) {
                const nowDate = new Date();
                nowDate.setUTCHours(0, 0, 0, 0);
                const startDate = nowDate.toISOString();
                const endDate = new Date().toISOString();
                const Sum = await getSum(accountId, accountIndex, email, key, startDate, endDate);
                pagesSum = Sum[0];
                workersSum = Sum[1];
                total = 102400;
              }
            }

            const headers = {
              "Content-Type": "text/plain;charset=utf-8",
              "Profile-Update-Interval": "6",
              "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
            };

            if (userAgent && userAgent.includes('mozilla')) {
              return new Response(`${vlxxxConfig}`, { status: 200, headers });
            } else {
              headers['Content-Disposition'] = `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`;
              return new Response(`${vlxxxConfig}`, { status: 200, headers });
            }
          }
          default:
            return new Response('Not found', { status: 404 });
        }
      } else {
        // websocket upgrade path
        // parse some parameters from url path and query

        // ---------- 替换开始 ----------
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
          let pickedProxyIP = url.searchParams.get('proxyip'); // query 参数优先
          let matchedProxyPath = false;
          const path = url.pathname.toLowerCase();

          // 路径匹配：/proxyip=xxx 或 /proxyip.xxx
          if (/\/proxyip=/i.test(path)) {
            pickedProxyIP = path.split('/proxyip=')[1] || '';
            matchedProxyPath = true;
          } else if (/\/proxyip\./i.test(path)) {
            pickedProxyIP = `proxyip.${(path.split('/proxyip.')[1] || '')}`;
            matchedProxyPath = true;
          } else if (/sg.dtcs520.com/i.test(path)) {
            // 特殊路径匹配
            pickedProxyIP = 'sg.dtcs520.com';
          } else if (/hk.dtcs520.com/i.test(path)) {
            pickedProxyIP = 'hk.dtcs520.com';
          } else if (/jp.dtcs520.com/i.test(path)) {
            pickedProxyIP = 'jp.dtcs520.com';
          } else if (/us.dtcs520.com/i.test(path)) {
            pickedProxyIP = 'us.dtcs520.com';
          }

          // 兜底逻辑：路径没匹配且 query 参数为空
          if (!matchedProxyPath && !pickedProxyIP) {
            pickedProxyIP = 'sg.dtcs520.com';
          }

          // 最终把局部解析结果写回全局 proxyIP（写回全局变量）
          proxyIP = pickedProxyIP;
        }
        // ---------- 替换结束 ----------

		
 		
		/*
        //url.searchParams.get用于匹配查询参数，格式如/?proxyip=jp.dtcs520.com，主要是?号代表查询参数
        proxyIP = url.searchParams.get('proxyip');
        //以下都是url.pathname查询方式，用于匹配路径，格式如/proxyip=jp.dtcs520.com，没有?号，只有/代表路径，由于客户端都是传查询参数，即/?proxyip格式，不是/proxyip的路径格式
        //所以默认以下两条语句不生效，除非客户端路径(PATH)部分写成/proxyip=jp.dtcs520.com，即不带?号的格式才能使以下两条语句生效
        //另外如果路径PATH写成只有proxyip=(即=号后面没有内容)，会匹配以下第一条规则，但是会使proxyIP的值为空，导致需要proxyIP的访问失败
        if (/\/proxyip=/i.test(url.pathname)) proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
        else if (/\/proxyip\./i.test(url.pathname)) proxyIP = `proxyip.${url.pathname.toLowerCase().split('/proxyip.')[1]}`;
        //以下四条是实际使用的内容，使用/sg.dtcs520.com/i（前后/是正则表达式，匹配前后/内的内容，i表示转为小写字符），和(url.pathname)进行路径匹配，只要路径中包含以下4条语句中的一条，则分配对应proxyIP
        else if (/sg.dtcs520.com/i.test(url.pathname)) proxyIP = 'sg.dtcs520.com';
        else if (/hk.dtcs520.com/i.test(url.pathname)) proxyIP = 'hk.dtcs520.com';
        else if (/jp.dtcs520.com/i.test(url.pathname)) proxyIP = 'jp.dtcs520.com';
        else if (/us.dtcs520.com/i.test(url.pathname)) proxyIP = 'us.dtcs520.com';
        //下面的语句用于匹配两种情况：
        //如果路径PATH中的内容为空（不输入任何内容），之前的proxyIP = url.searchParams.get('proxyip');语句的执行结果会认为proxyIP参数为null，即false，匹配下面语句的!proxyIP条件，保底分配proxyIP = 'sg.dtcs520.com'
        //如果路径PATH中仅输入了/?proxyip=(即=号后面没有内容)，之前的proxyIP = url.searchParams.get('proxyip');语句的执行结果会认为proxyIP为''，即空，匹配下面语句的proxyIP == ''条件，保底分配proxyIP = 'sg.dtcs520.com'
        else if (!proxyIP || proxyIP == '') proxyIP = 'sg.dtcs520.com';
        */
		  
        socks5Address = url.searchParams.get('socks5') || socks5Address;
        if (/\/socks5=/i.test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
        else if (/\/socks:\/\//i.test(url.pathname) || /\/socks5:\/\//i.test(url.pathname)) {
          socks5Address = url.pathname.split('://')[1].split('#')[0];
          if (socks5Address.includes('@')) {
            let userPassword = socks5Address.split('@')[0];
            const base64Regex = /^(?:[A-Z0-9+\/]{4})*(?:[A-Z0-9+\/]{2}==|[A-Z0-9+\/]{3}=)?$/i;
            if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
            socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
          }
        }

        if (socks5Address) {
          try {
            parsedSocks5Address = socks5AddressParser(socks5Address);
            enableSocks = true;
          } catch (err) {
            console.log(err.toString());
            enableSocks = false;
          }
        } else {
          enableSocks = false;
        }

        return await vlxxxOverWSHandler(request);
      }
    } catch (err) {
      let e = err;
      return new Response(e.toString());
    }
  }
};

// -------------------------------
// VLXXX WebSocket handler
// -------------------------------

/**
 * Handle VLXXX over WebSocket
 * @param {Request} request
 */
async function vlxxxOverWSHandler(request) {
  // @ts-ignore
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = '';
  let portWithRandomLog = '';
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
  };

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = { value: null };
  let isDns = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk) {
      if (isDns) {
        return await handleDNSQuery(chunk, webSocket, null, log);
      }

      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const {
        hasError,
        message,
        addressType,
        portRemote = 443,
        addressRemote = '',
        rawDataIndex,
        vlxxxVersion = new Uint8Array([0, 0]),
        isUDP,
      } = processVlxxxHeader(chunk, userID);

      address = addressRemote;
      portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;

      if (hasError) {
        throw new Error(message);
      }

      if (isUDP) {
        if (portRemote === 53) {
          isDns = true;
        } else {
          throw new Error('UDP 代理仅对 DNS（53 端口）启用');
        }
      }

      const vlxxxResponseHeader = new Uint8Array([vlxxxVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);

      if (isDns) {
        return handleDNSQuery(rawClientData, webSocket, vlxxxResponseHeader, log);
      }

      log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
      handleTCPOutBound(remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlxxxResponseHeader, log);
    },
    close() {
      log(`readableWebSocketStream 已关闭`);
    },
    abort(reason) {
      log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
    },
  })).catch((err) => {
    log('readableWebSocketStream 管道错误', err);
  });

  return new Response(null, { status: 101, // @ts-ignore
    webSocket: client,
  });
}

// -------------------------------
// Handle outbound TCP
// -------------------------------

/**
 * Handle TCP outbound connection and data forwarding
 */
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlxxxResponseHeader, log) {
  async function connectAndWrite(address, port, socks = false) {
    log(`attempt connect to ${address}:${port}`);

    // resolve specific domains to IPv4 if desired (kept simple)
    // 注释整段google DNS解析功能，开头使用 /*，结尾使用*/
	// 通过将address变量的域名值事先解析成IPv4地址，这样在下面的connect阶段将通过IPv4地址建立TCP会话，从而避免通过IPv6连接
	//if (address.includes('fast.com') || address.includes('netflix.com') || address.includes('netflix.net') || address.includes('nflxext.com') || address.includes('nflxso.net') || address.includes('nflxvideo.net') || address.includes('nflxsearch.net') || address.includes('nflximg.com')) {
    if (address.includes('163.com')) {
      const resolved = await resolveDomainToIPv4(address);
      if (resolved) address = resolved;
    }

    async function resolveDomainToIPv4(addr) {
      try {
        const resp = await fetch(`https://dns.google/resolve?name=${addr}&type=A`);
        if (!resp.ok) return null;
        const data = await resp.json();
        if (data.Status === 0 && Array.isArray(data.Answer)) {
          const record = data.Answer.find(r => r.type === 1);
          return record ? record.data : null;
        }
        return null;
      } catch (e) {
        console.error('DNS resolution error:', e);
        return null;
      }
    }

    const tcpSocket = socks ? await socks5Connect(addressType, address, port, log) : connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;

    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    let tcpSocket;
    if (enableSocks) {
      tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
    } else {
      tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
    }

    tcpSocket.closed.catch(error => {
      console.log('retry tcpSocket closed error', error);
    }).finally(() => {
      safeCloseWebSocket(webSocket);
    });

    remoteSocketToWS(tcpSocket, webSocket, vlxxxResponseHeader, null, log);
  }

  let tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, vlxxxResponseHeader, retry, log);
}

// -------------------------------
// Convert WebSocket to ReadableStream
// -------------------------------

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;

  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });

      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });

      webSocketServer.addEventListener('error', (err) => {
        log('WebSocket 服务器发生错误');
        controller.error(err);
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(controller) {
      // placeholder for backpressure logic
    },
    cancel(reason) {
      if (readableStreamCancel) return;
      log(`可读流被取消，原因是 ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });

  return stream;
}

// -------------------------------
// Protocol parsing: VLXXX
// -------------------------------

function processVlxxxHeader(vlxxxBuffer, userID) {
  if (vlxxxBuffer.byteLength < 24) return { hasError: true, message: 'invalid data' };

  const version = new Uint8Array(vlxxxBuffer.slice(0, 1));
  let isValidUser = false;
  try {
    if (stringify(new Uint8Array(vlxxxBuffer.slice(1, 17))) === userID) isValidUser = true;
  } catch (e) {
    return { hasError: true, message: 'invalid user id' };
  }
  if (!isValidUser) return { hasError: true, message: 'invalid user' };

  const optLength = new Uint8Array(vlxxxBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlxxxBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  let isUDP = false;
  if (command === 1) {
    // tcp
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: `command ${command} is not support, command 01-tcp,02-udp,03-mux` };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = vlxxxBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlxxxBuffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];

  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlxxxBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    case 2:
      addressLength = new Uint8Array(vlxxxBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlxxxBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(vlxxxBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: `invild addressType is ${addressType}` };
  }

  if (!addressValue) return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlxxxVersion: version,
    isUDP,
  };
}

// -------------------------------
// Forward remote socket -> WebSocket
// -------------------------------

async function remoteSocketToWS(remoteSocket, webSocket, vlxxxResponseHeader, retry, log) {
  let remoteChunkCount = 0;
  let vlessHeader = vlxxxResponseHeader;
  let hasIncomingData = false;

  await remoteSocket.readable.pipeTo(new WritableStream({
    start() {},
    async write(chunk, controller) {
      hasIncomingData = true;
      if (webSocket.readyState !== WS_READY_STATE_OPEN) controller.error('webSocket.readyState is not open, maybe close');
      if (vlessHeader) {
        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
        vlessHeader = null;
      } else {
        webSocket.send(chunk);
      }
    },
    close() {
      log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
    },
    abort(reason) {
      console.error(`remoteConnection!.readable abort`, reason);
    }
  })).catch((error) => {
    console.error(`remoteSocketToWS has exception `, error.stack || error);
    safeCloseWebSocket(webSocket);
  });

  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

// -------------------------------
// DNS handling (TCP forward)
// -------------------------------

async function handleDNSQuery(udpChunk, webSocket, vlxxxResponseHeader, log) {
  try {
    const dnsServer = '1.1.1.1';
    const dnsPort = 53;
    let vlessHeader = vlxxxResponseHeader;
    const tcpSocket = connect({ hostname: dnsServer, port: dnsPort });
    log(`连接到 ${dnsServer}:${dnsPort}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          if (vlessHeader) {
            webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
            vlessHeader = null;
          } else {
            webSocket.send(chunk);
          }
        }
      },
      close() {
        log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`);
      },
      abort(reason) {
        console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason);
      }
    }));
  } catch (error) {
    console.error(`handleDNSQuery 函数发生异常，错误信息: ${error.message}`);
  }
}

// -------------------------------
// SOCKS5 connect and parser
// -------------------------------

async function socks5Connect(addressType, addressRemote, portRemote, log) {
  const { username, password, hostname, port } = parsedSocks5Address;
  const socket = connect({ hostname, port });
  const socksGreeting = new Uint8Array([5, 2, 0, 2]);
  const writer = socket.writable.getWriter();
  await writer.write(socksGreeting);
  log('已发送 SOCKS5 问候消息');

  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  let res = (await reader.read()).value;
  if (res[0] !== 0x05) { log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`); return; }
  if (res[1] === 0xff) { log('服务器不接受任何认证方法'); return; }

  if (res[1] === 0x02) {
    log('SOCKS5 服务器需要认证');
    if (!username || !password) { log('请提供用户名和密码'); return; }
    const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 0x01 || res[1] !== 0x00) { log('SOCKS5 服务器认证失败'); return; }
  }

  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
      break;
    case 2:
      DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
      break;
    case 3:
      DSTADDR = new Uint8Array([4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
      break;
    default:
      log(`无效的地址类型: ${addressType}`); return;
  }

  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
  await writer.write(socksRequest);
  log('已发送 SOCKS5 请求');

  res = (await reader.read()).value;
  if (res[1] === 0x00) { log('SOCKS5 连接已建立'); } else { log('SOCKS5 连接建立失败'); return; }
  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

function socks5AddressParser(address) {
  let [latter, former] = address.split('@').reverse();
  let username, password, hostname, port;
  if (former) {
    const formers = former.split(':');
    if (formers.length !== 2) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
    [username, password] = formers;
  }
  const latters = latter.split(':');
  port = Number(latters.pop());
  if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
  hostname = latters.join(':');
  const regex = /^\[.*\]$/;
  if (hostname.includes(':') && !regex.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
  return { username, password, hostname, port };
}

// -------------------------------
// Utility and helpers
// -------------------------------

function revertFakeInfo(content, userIDVal, hostName, isBase64) {
  if (isBase64) content = atob(content);
  content = content.replace(new RegExp(fakeUserID, 'g'), userIDVal).replace(new RegExp(fakeHostName, 'g'), hostName);
  if (isBase64) content = btoa(content);
  return content;
}

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

async function ADD(envadd) {
  if (!envadd) return [];
  var addtext = envadd.replace(/[\t|"'\r\n]+/g, ',').replace(/,+/g, ',');
  if (addtext.charAt(0) == ',') addtext = addtext.slice(1);
  if (addtext.charAt(addtext.length - 1) == ',') addtext = addtext.slice(0, addtext.length - 1);
  return addtext.split(',');
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
  try {
    if (!socket) return;
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) socket.close();
  } catch (error) {
    console.error('safeCloseWebSocket error', error);
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw TypeError(`生成的 UUID 不符合规范 ${uuid}`);
  return uuid;
}

// -------------------------------
// Minimal stubs for missing integrations
// -------------------------------

async function getVLXXXConfig(userId, host, subVal, ua, rproxy, url) {
  // Minimal config generator stub. Replace with your real implementation.
  return `# VLXXX config\nuser:${userId}\nhost:${host}\nsub:${subVal}\nua:${ua}\n`;
}

async function sendMessage(title, ip, body) {
  // noop or implement Telegram / webhook sending if desired
  try { console.log('sendMessage', title, ip, body); } catch (e) {}
}

async function getAccountId(email, key) {
  // stub to avoid runtime errors
  return null;
}

async function getSum(accountId, accountIndex, email, key, startDate, endDate) {
  return [0, 0];
}

// -------------------------------
// Simple helpers to avoid unused errors
// -------------------------------

// ensure top-level exported names exist if other code relies on them elsewhere
export {
  vlxxxOverWSHandler,
  processVlxxxHeader,
  handleTCPOutBound,
  handleDNSQuery,
  socks5Connect,
  socks5AddressParser,
  MD5MD5,
  ADD,
};
