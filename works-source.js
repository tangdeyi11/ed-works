
// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:05 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'df3a46a8-6f37-4ed8-afb5-e8f71b01100c';

let proxyIP = '';// 小白勿动，该地址并不影响你的网速，这是给CF代理使用的。'cdn.xn--b6gac.eu.org, cdn-all.xn--b6gac.eu.org, workers.cloudflare.cyou'

let sub = '';// 留空则使用内置订阅
let subconverter = 'subapi.dtcs520.ggff.net';// clash订阅转换后端，目前使用CM的订阅转换功能subapi.cmliussss.net。也可以使用肥羊的订阅转换后端url.v1.mk，自带虚假uuid和host订阅。
//let subconfig = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Full_MultiMode.ini"; //订阅配置文件
let subconfig = "https://raw.githubusercontent.com/tangdeyi11/dyconfig/main/rule.ini";

// The user name and password do not contain special characters
// Setting the address will ignore proxyIP
// Example:  user:pass@host:port  or  host:port
let socks5Address = '';

if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

let parsedSocks5Address = {}; 
let enableSocks = false;

// 虚假uuid和hostname，用于发送给配置生成服务
let fakeUserID ;
let fakeHostName ;
let noTLS = 'false'; 
const expire = 4102329600;//2099-12-31
let proxyIPs;
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let FileName = 'edgetunnel';
let BotToken ='';
let ChatID =''; 
let proxyhosts = [];//本地代理域名池
let proxyhostsURL = '';//在线代理域名池URL
let RproxyIP = 'false';
export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			const UA = request.headers.get('User-Agent') || 'null';
			const userAgent = UA.toLowerCase();
			userID = (env.UUID || userID).toLowerCase();

			const currentDate = new Date();
			currentDate.setHours(0, 0, 0, 0); 
			const timestamp = Math.ceil(currentDate.getTime() / 1000);
			const fakeUserIDMD5 = await MD5MD5(`${userID}${timestamp}`);
			fakeUserID = fakeUserIDMD5.slice(0, 8) + "-" + fakeUserIDMD5.slice(8, 12) + "-" + fakeUserIDMD5.slice(12, 16) + "-" + fakeUserIDMD5.slice(16, 20) + "-" + fakeUserIDMD5.slice(20);
			fakeHostName = fakeUserIDMD5.slice(6, 9) + "." + fakeUserIDMD5.slice(13, 19);
			//console.log(`${fakeUserID}\n${fakeHostName}`); // 打印fakeID

			proxyIP = env.PROXYIP || proxyIP;
			proxyIPs = await ADD(proxyIP);
			proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			//console.log(proxyIP);
			socks5Address = env.SOCKS5 || socks5Address;
			sub = env.SUB || sub;
			subconverter = env.SUBAPI || subconverter;
			subconfig = env.SUBCONFIG || subconfig;
			if (socks5Address) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Address);
					RproxyIP = env.RPROXYIP || 'false';
					enableSocks = true;
				} catch (err) {
  					/** @type {Error} */ 
					let e = err;
					console.log(e.toString());
					RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
					enableSocks = false;
				}
			} else {
				RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
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
			const url = new URL(request.url);
			if (url.searchParams.has('notls')) noTLS = 'true';
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				// const url = new URL(request.url);
				switch (url.pathname.toLowerCase()) {
				case '/':
					const envKey = env.URL302 ? 'URL302' : (env.URL ? 'URL' : null);
					if (envKey) {
						const URLs = await ADD(env[envKey]);
						const URL = URLs[Math.floor(Math.random() * URLs.length)];
						return envKey === 'URL302' ? Response.redirect(URL, 302) : fetch(new Request(URL, request));
					}
				        return new Response('系统维护中........', { status: 404, headers: { "Content-Type": "text/plain;charset=utf-8" } });
					// return new Response(JSON.stringify(request.cf, null, 4), { status: 200 });
				case `/${fakeUserID}`:
					const fakeConfig = await getVLESSConfig(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url);
					return new Response(`${fakeConfig}`, { status: 200 });
				case `/${userID}`: {
					await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
					if ((!sub || sub == '') && (addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0){
						if (request.headers.get('Host').includes(".workers.dev")) {
							sub = 'end.dtcs520.com'; 
							subconfig = 'https://raw.githubusercontent.com/tangdeyi11/dyconfig/main/rule.ini';
						} else sub = 'end.dtcs520.com';
					} 
					const vlessConfig = await getVLESSConfig(userID, request.headers.get('Host'), sub, UA, RproxyIP, url);
					const now = Date.now();
					//const timestamp = Math.floor(now / 1000);
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime())/86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776 ;
					if (env.CFEMAIL && env.CFKEY){
						const email = env.CFEMAIL;
						const key = env.CFKEY;
						const accountIndex = env.CFID || 0;
						const accountId = await getAccountId(email, key);
						if (accountId){
							const now = new Date()
							now.setUTCHours(0, 0, 0, 0)
							const startDate = now.toISOString()
							const endDate = new Date().toISOString();
							const Sum = await getSum(accountId, accountIndex, email, key, startDate, endDate);
							pagesSum = Sum[0];
							workersSum = Sum[1];
							total = 102400 ;
						}
					}
					//console.log(`pagesSum: ${pagesSum}\nworkersSum: ${workersSum}\ntotal: ${total}`);
					if (userAgent && userAgent.includes('mozilla')){
						return new Response(`${vlessConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					} else {
						return new Response(`${vlessConfig}`, {
							status: 200,
							headers: {
								"Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					}
				}
				default:
					return new Response('Not found', { status: 404 });
				}
			} else {
				proxyIP = url.searchParams.get('proxyip') || proxyIP;
				if (new RegExp('/proxyip=', 'i').test(url.pathname)) proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
				else if (new RegExp('/proxyip.', 'i').test(url.pathname)) proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
				else if (new RegExp('sg.dtcs520.com', 'i').test(url.pathname)) proxyIP = 'sg.dtcs520.com';
				else if (new RegExp('hk.dtcs520.com', 'i').test(url.pathname)) proxyIP = 'hk.dtcs520.com';
				else if (new RegExp('jp.dtcs520.com', 'i').test(url.pathname)) proxyIP = 'jp.dtcs520.com';
				else if (new RegExp('us.dtcs520.com', 'i').test(url.pathname)) proxyIP = 'us.dtcs520.com';
				else if (!proxyIP || proxyIP == '') proxyIP = 'sg.dtcs520.com';
				
				
				socks5Address = url.searchParams.get('socks5') || socks5Address;
				if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
				else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname)) {
					socks5Address = url.pathname.split('://')[1].split('#')[0];
					if (socks5Address.includes('@')){
						let userPassword = socks5Address.split('@')[0];
						const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
						if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
						socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
					}
				}
				if (socks5Address) {
					try {
						parsedSocks5Address = socks5AddressParser(socks5Address);
						enableSocks = true;
					} catch (err) {
						/** @type {Error} */ 
						let e = err;
						console.log(e.toString());
						enableSocks = false;
					}
				} else {
					enableSocks = false;
				}
				return await vlessOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

/**
 * 处理 VLESS over WebSocket 的请求
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function vlessOverWSHandler(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	// 接受 WebSocket 连接
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	// 日志函数，用于记录连接信息
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	// 获取早期数据头部，可能包含了一些初始化数据
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	// 创建一个可读的 WebSocket 流，用于接收客户端数据
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	// 用于存储远程 Socket 的包装器
	let remoteSocketWapper = {
		value: null,
	};
	// 标记是否为 DNS 查询
	let isDns = false;

	// WebSocket 数据流向远程服务器的管道
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				// 如果是 DNS 查询，调用 DNS 处理函数
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				// 如果已有远程 Socket，直接写入数据
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			// 处理 VLESS 协议头部
			const {
				hasError,
				message,
				addressType,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processVlessHeader(chunk, userID);
			// 设置地址和端口信息，用于日志
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
			if (hasError) {
				// 如果有错误，抛出异常
				throw new Error(message);
				return;
			}
			// 如果是 UDP 且端口不是 DNS 端口（53），则关闭连接
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP 代理仅对 DNS（53 端口）启用');
					return;
				}
			}
			// 构建 VLESS 响应头部
			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			// 获取实际的客户端数据
			const rawClientData = chunk.slice(rawDataIndex);
			
			if (isDns) {
				// 如果是 DNS 查询，调用 DNS 处理函数
				return handleDNSQuery(rawClientData, webSocket, vlessResponseHeader, log);
			}
			// 处理 TCP 出站连接
			log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
			handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
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

	// 返回一个 WebSocket 升级的响应
	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * 处理出站 TCP 连接。
 *
 * @param {any} remoteSocket 远程 Socket 的包装器，用于存储实际的 Socket 对象
 * @param {number} addressType 要连接的远程地址类型（如 IP 类型：IPv4 或 IPv6）
 * @param {string} addressRemote 要连接的远程地址
 * @param {number} portRemote 要连接的远程端口
 * @param {Uint8Array} rawClientData 要写入的原始客户端数据
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 用于传递远程 Socket 的 WebSocket
 * @param {Uint8Array} vlessResponseHeader VLESS 响应头部
 * @param {function} log 日志记录函数
 * @returns {Promise<void>} 异步操作的 Promise
 */
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {
	/**
	 * 连接远程服务器并写入数据
	 * @param {string} address 要连接的地址
	 * @param {number} port 要连接的端口
	 * @param {boolean} socks 是否使用 SOCKS5 代理连接
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} 连接后的 TCP Socket
	 */

	async function connectAndWrite(address, port, socks = false) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		log(`connected to ${address}:${port}`);
		//if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;

		// 注释整段google DNS解析功能，开通使用 /*
		// 通过将address变量的域名值事先解析成IPv4地址，这样在下面的connect阶段将通过IPv4地址建立TCP会话，从而避免通过IPv6连接
		//if (address.includes('fast.com') || address.includes('netflix.com') || address.includes('netflix.net') || address.includes('nflxext.com') || address.includes('nflxso.net') || address.includes('nflxvideo.net') || address.includes('nflxsearch.net') || address.includes('nflximg.com')) {
		if (address.includes('163.com')) {
			// 解析域名为 IPv4 地址
			address = await resolveDomainToIPv4(address);
			}else if (address.includes('263.com') || address.includes('ipv4.ip.sb')) {
			// 如果域名包含 dtcs520.com，则直接使用 proxyIP 作为目标地址
			if (typeof proxyIP !== 'undefined' && proxyIP) {
				log(`using proxyIP ${proxyIP} for ${address}`);
				address = proxyIP;
			} else {
				log(`proxyIP not defined, using original address: ${address}`);
			}
		}
		    
			//通过google的web DNS服务解析IPv4地址
			async function resolveDomainToIPv4(address) {
				try {
					const response = await fetch(`https://dns.google/resolve?name=${address}&type=A`);
					
					// 检查响应状态码
					if (!response.ok) {
						console.error(`Failed to fetch DNS data: ${response.status} ${response.statusText}`);
						return null;
					}
			
					const data = await response.json();
			
					// 检查 DNS 解析的结果,google的DNS会解析出多个类型的地址，IPv4地址type为1，并且排在后面，需要通过下面代码筛选
					if (data.Status === 0 && Array.isArray(data.Answer) && data.Answer.length > 0) {
						// 查找第一个 type 为 1 的条目
						const firstIPv4Record = data.Answer.find(record => record.type === 1);
						
						if (firstIPv4Record) {
							// 返回第一个 IPv4 地址
							return firstIPv4Record.data;
						} else {
							console.warn(`No valid A record found for ${address}`);
							return null;
						}
					} else {
						console.warn(`No valid A record found for ${address}`);
						return null;
					}
				} catch (error) {
					console.error('DNS resolution error:', error);
					return null;
				}
			}
		
		// 注释整段google DNS解析功能，结尾使用 */	
                       
        // 如果指定使用 SOCKS5 代理，则通过 SOCKS5 协议连接；否则直接连接
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
			: connect({
				hostname: address,
				port: port,
			});
		remoteSocket.value = tcpSocket;
		//log(`connected to ${address}:${port}`);

		// 计算 rawClientData 的哈希值（SHA-256）
        const hashBuffer = await crypto.subtle.digest("SHA-256", rawClientData);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
        log(`rawClientData SHA-256: ${hashHex}`);
		
		const writer = tcpSocket.writable.getWriter();
		// 首次写入，通常是 TLS 客户端 Hello 消息
		// -----------------------------
        await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}
    

	/**
	 * 重试函数：当 Cloudflare 的 TCP Socket 没有传入数据时，我们尝试重定向 IP
	 * 这可能是因为某些网络问题导致的连接失败
	 */
	async function retry() {
		if (enableSocks) {
			// 如果启用了 SOCKS5，通过 SOCKS5 代理重试连接
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			// 否则，尝试使用预设的代理 IP（如果有）或原始地址重试连接
			tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		}
		// 无论重试是否成功，都要关闭 WebSocket（可能是为了重新建立连接）
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		// 建立从远程 Socket 到 WebSocket 的数据流
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	// 首次尝试连接远程服务器
	let tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// 当远程 Socket 就绪时，将其传递给 WebSocket
	// 建立从远程服务器到 WebSocket 的数据流，用于将远程服务器的响应发送回客户端
	// 如果连接失败或无数据，retry 函数将被调用进行重试
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * 将 WebSocket 转换为可读流（ReadableStream）
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer 服务器端的 WebSocket 对象
 * @param {string} earlyDataHeader WebSocket 0-RTT（零往返时间）的早期数据头部
 * @param {(info: string)=> void} log 日志记录函数，用于记录 WebSocket 0-RTT 相关信息
 * @returns {ReadableStream} 由 WebSocket 消息组成的可读流
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	// 标记可读流是否已被取消
	let readableStreamCancel = false;

	// 创建一个新的可读流
	const stream = new ReadableStream({
		// 当流开始时的初始化函数
		start(controller) {
			// 监听 WebSocket 的消息事件
			webSocketServer.addEventListener('message', (event) => {
				// 如果流已被取消，不再处理新消息
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				// 将消息加入流的队列中
				controller.enqueue(message);
			});

			// 监听 WebSocket 的关闭事件
			// 注意：这个事件意味着客户端关闭了客户端 -> 服务器的流
			// 但是，服务器 -> 客户端的流仍然打开，直到在服务器端调用 close()
			// WebSocket 协议要求在每个方向上都要发送单独的关闭消息，以完全关闭 Socket
			webSocketServer.addEventListener('close', () => {
				// 客户端发送了关闭信号，需要关闭服务器端
				safeCloseWebSocket(webSocketServer);
				// 如果流未被取消，则关闭控制器
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});

			/*
			// 监听 WebSocket 的错误事件
			webSocketServer.addEventListener('error', (err) => {
				log('WebSocket 服务器发生错误');
				// 将错误传递给控制器
				controller.error(err);
			});
			*/

			function diagnoseWebSocketError(event, webSocketServer, log) {
	try {
		log('⚠️ WebSocket 服务器发生错误');
		log(`🔸事件类型: ${event?.type || '未知'}`);
		log(`🔸readyState: ${webSocketServer.readyState}`);

		// Cloudflare Workers 的 WebSocket 没有标准 Error 对象
		// 尽量输出所有可能的信息
		if (event && typeof event === 'object') {
			const details = JSON.stringify(event, null, 2);
			if (details && details !== '{}') log(`🔸事件详情: ${details}`);
		} else {
			log(`🔸事件原始值: ${String(event)}`);
		}

		// 根据 readyState 猜测问题阶段
		switch (webSocketServer.readyState) {
			case WebSocket.CONNECTING:
				log('🟡 阶段: 连接中 → 可能原因:');
				log('   - 握手失败（Upgrade / Connection 头无效）');
				log('   - 客户端或代理在握手期间断开');
				log('   - Cloudflare 节点拒绝 TLS 或协议错误');
				break;

			case WebSocket.OPEN:
				log('🟢 阶段: 已连接 → 可能原因:');
				log('   - 数据帧异常（格式错误、非UTF-8文本）');
				log('   - 客户端提前断开连接（RST 或中途关闭）');
				log('   - Worker 触发 controller.error() 或 safeClose() 次序异常');
				log('   - 消息太大超出CF内存限制（>1MB）');
				break;

			case WebSocket.CLOSING:
				log('🟠 阶段: 正在关闭 → 可能原因:');
				log('   - 双方关闭顺序冲突');
				log('   - 控制帧重复发送');
				break;

			case WebSocket.CLOSED:
				log('🔴 阶段: 已关闭 → 可能原因:');
				log('   - 客户端主动关闭（常见）');
				log('   - Cloudflare 边缘节点迁移或Worker超时');
				log('   - Durable Object 销毁或断线重连中');
				break;

			default:
				log('⚫ 未知阶段 → 请检查 Worker runtime 日志。');
		}
	} catch (e) {
		log(`❌ 诊断函数异常: ${e.stack || e}`);
	}
}


			// 处理 WebSocket 0-RTT（零往返时间）的早期数据
			// 0-RTT 允许在完全建立连接之前发送数据，提高了效率
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				// 如果解码早期数据时出错，将错误传递给控制器
				controller.error(error);
			} else if (earlyData) {
				// 如果有早期数据，将其加入流的队列中
				controller.enqueue(earlyData);
			}
		},

		// 当使用者从流中拉取数据时调用
		pull(controller) {
			// 这里可以实现反压机制
			// 如果 WebSocket 可以在流满时停止读取，我们就可以实现反压
			// 参考：https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},

		// 当流被取消时调用
		cancel(reason) {
			// 流被取消的几种情况：
			// 1. 当管道的 WritableStream 有错误时，这个取消函数会被调用，所以在这里处理 WebSocket 服务器的关闭
			// 2. 如果 ReadableStream 被取消，所有 controller.close/enqueue 都需要跳过
			// 3. 但是经过测试，即使 ReadableStream 被取消，controller.error 仍然有效
			if (readableStreamCancel) {
				return;
			}
			log(`可读流被取消，原因是 ${reason}`);
			readableStreamCancel = true;
			// 安全地关闭 WebSocket
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * 解析 VLESS 协议的头部数据
 * @param { ArrayBuffer} vlessBuffer VLESS 协议的原始头部数据
 * @param {string} userID 用于验证的用户 ID
 * @returns {Object} 解析结果，包括是否有错误、错误信息、远程地址信息等
 */
function processVlessHeader(vlessBuffer, userID) {
	// 检查数据长度是否足够（至少需要 24 字节）
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	// 解析 VLESS 协议版本（第一个字节）
	const version = new Uint8Array(vlessBuffer.slice(0, 1));

	let isValidUser = false;
	let isUDP = false;

	// 验证用户 ID（接下来的 16 个字节）
	if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID) {
		isValidUser = true;
	}
	// 如果用户 ID 无效，返回错误
	if (!isValidUser) {
		return {
			hasError: true,
			message: `invalid user ${(new Uint8Array(vlessBuffer.slice(1, 17)))}`,
		};
	}

	// 获取附加选项的长度（第 17 个字节）
	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	// 暂时跳过附加选项

	// 解析命令（紧跟在选项之后的 1 个字节）
	// 0x01: TCP, 0x02: UDP, 0x03: MUX（多路复用）
	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
		// TCP 命令，不需特殊处理
	} else if (command === 2) {
		// UDP 命令
		isUDP = true;
	} else {
		// 不支持的命令
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}

	// 解析远程端口（大端序，2 字节）
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	// 解析地址类型和地址
	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 地址类型：1-IPv4(4字节), 2-域名(可变长), 3-IPv6(16字节)
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';

	switch (addressType) {
		case 1:
			// IPv4 地址
			addressLength = 4;
			// 将 4 个字节转为点分十进制格式
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			// 域名
			// 第一个字节是域名长度
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			// 解码域名
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			// IPv6 地址
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 每 2 字节构成 IPv6 地址的一部分
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			// 无效的地址类型
			return {
				hasError: true,
				message: `invild addressType is ${addressType}`,
			};
	}

	// 确保地址不为空
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	// 返回解析结果
	return {
		hasError: false,
		addressRemote: addressValue,  // 解析后的远程地址
		addressType,                 // 地址类型
		portRemote,                 // 远程端口
		rawDataIndex: addressValueIndex + addressLength,  // 原始数据的实际起始位置
		vlessVersion: version,      // VLESS 协议版本
		isUDP,                     // 是否是 UDP 请求
	};
}


/**
 * 将远程 Socket 的数据转发到 WebSocket
 * 
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket 远程服务器的 Socket 连接
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 客户端的 WebSocket 连接
 * @param {ArrayBuffer} vlessResponseHeader VLESS 协议的响应头部
 * @param {(() => Promise<void>) | null} retry 重试函数，当没有数据时调用
 * @param {*} log 日志函数
 */


	/**
 * 将远程 TCP Socket 的数据流转发到 WebSocket
 * 并记录详细的关闭原因。
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	let hasIncomingData = false;
	let vlessHeader = vlessResponseHeader;
	let closedByRemote = false;
	let aborted = false;
	let errorCaught = null;

	try {
		await remoteSocket.readable.pipeTo(
			new WritableStream({
				async write(chunk, controller) {
					hasIncomingData = true;

					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error('❌ WebSocket 已关闭，无法继续写入');
						return;
					}

					try {
						if (vlessHeader) {
							await webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
							vlessHeader = null;
						} else {
							await webSocket.send(chunk);
						}
					} catch (err) {
						controller.error(`❌ 写入 WebSocket 出错: ${err.message || err}`);
					}
				},

				close() {
					closedByRemote = true;
					const reason = hasIncomingData
						? '✅ 远程服务器正常关闭（有返回数据）'
						: '⚠️ 远程服务器提前关闭（无返回数据）';
					log(`remoteSocket.readable closed → ${reason}`);
				},

				abort(reason) {
					aborted = true;
					log(`❌ remoteSocket.readable aborted: ${reason}`);
				},
			})
		);
	} catch (err) {
		errorCaught = err;
		log(`🚨 remoteSocketToWS 捕获异常: ${err.message || err}`);
	}

	// ========== 关闭阶段诊断 ==========
	if (errorCaught) {
		// 如果捕获异常，通常是 CF runtime 或客户端中止
		log(`🔎 关闭分析 → 异常触发: ${errorCaught.message || errorCaught}`);
		safeCloseWebSocket(webSocket);
	} else if (aborted) {
		log('🔎 关闭分析 → 流中止（可能客户端断开 WebSocket）');
		safeCloseWebSocket(webSocket);
	} else if (!hasIncomingData && closedByRemote) {
		log('🔎 关闭分析 → 无返回数据即关闭 → 可能远程连接拒绝 / SYN 后立即 FIN / RST');
		retry && (await retry());
	} else {
		log('🔎 关闭分析 → 正常结束，无需重试');
	}
}




/**
 * 将 Base64 编码的字符串转换为 ArrayBuffer
 * 
 * @param {string} base64Str Base64 编码的输入字符串
 * @returns {{ earlyData: ArrayBuffer | undefined, error: Error | null }} 返回解码后的 ArrayBuffer 或错误
 */
function base64ToArrayBuffer(base64Str) {
	// 如果输入为空，直接返回空结果
	if (!base64Str) {
		return { error: null };
	}
	try {
		// Go 语言使用了 URL 安全的 Base64 变体（RFC 4648）
		// 这种变体使用 '-' 和 '_' 来代替标准 Base64 中的 '+' 和 '/'
		// JavaScript 的 atob 函数不直接支持这种变体，所以我们需要先转换
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		
		// 使用 atob 函数解码 Base64 字符串
		// atob 将 Base64 编码的 ASCII 字符串转换为原始的二进制字符串
		const decode = atob(base64Str);
		
		// 将二进制字符串转换为 Uint8Array
		// 这是通过遍历字符串中的每个字符并获取其 Unicode 编码值（0-255）来完成的
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		
		// 返回 Uint8Array 的底层 ArrayBuffer
		// 这是实际的二进制数据，可以用于网络传输或其他二进制操作
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		// 如果在任何步骤中出现错误（如非法 Base64 字符），则返回错误
		return { error };
	}
}

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

// WebSocket 的两个重要状态常量
const WS_READY_STATE_OPEN = 1;     // WebSocket 处于开放状态，可以发送和接收消息
const WS_READY_STATE_CLOSING = 2;  // WebSocket 正在关闭过程中

/**
 * 安全地关闭 WebSocket 连接
 * 通常，WebSocket 在关闭时不会抛出异常，但为了以防万一，我们还是用 try-catch 包裹
 * @param {import("@cloudflare/workers-types").WebSocket} socket 要关闭的 WebSocket 对象
 */
function safeCloseWebSocket(socket) {
	try {
		// 只有在 WebSocket 处于开放或正在关闭状态时才调用 close()
		// 这避免了在已关闭或连接中的 WebSocket 上调用 close()
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		// 记录任何可能发生的错误，虽然按照规范不应该有错误
		console.error('safeCloseWebSocket error', error);
	}
}

// 预计算 0-255 每个字节的十六进制表示
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	// (i + 256).toString(16) 确保总是得到两位数的十六进制
	// .slice(1) 删除前导的 "1"，只保留两位十六进制数
	byteToHex.push((i + 256).toString(16).slice(1));
}

/**
 * 快速地将字节数组转换为 UUID 字符串，不进行有效性检查
 * 这是一个底层函数，直接操作字节，不做任何验证
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} UUID 字符串
 */
function unsafeStringify(arr, offset = 0) {
	// 直接从查找表中获取每个字节的十六进制表示，并拼接成 UUID 格式
	// 8-4-4-4-12 的分组是通过精心放置的连字符 "-" 实现的
	// toLowerCase() 确保整个 UUID 是小写的
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
		byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
		byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
		byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
		byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
		byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

/**
 * 将字节数组转换为 UUID 字符串，并验证其有效性
 * 这是一个安全的函数，它确保返回的 UUID 格式正确
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} 有效的 UUID 字符串
 * @throws {TypeError} 如果生成的 UUID 字符串无效
 */
function stringify(arr, offset = 0) {
	// 使用不安全的函数快速生成 UUID 字符串
	const uuid = unsafeStringify(arr, offset);
	// 验证生成的 UUID 是否有效
	if (!isValidUUID(uuid)) {
		// 原：throw TypeError("Stringified UUID is invalid");
		throw TypeError(`生成的 UUID 不符合规范 ${uuid}`); 
		//uuid = userID;
	}
	return uuid;
}

/**
 * 处理 DNS 查询的函数
 * @param {ArrayBuffer} udpChunk - 客户端发送的 DNS 查询数据
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket - 与客户端建立的 WebSocket 连接
 * @param {ArrayBuffer} vlessResponseHeader - VLESS 协议的响应头部数据
 * @param {(string)=> void} log - 日志记录函数
 */
async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
    // 无论客户端发送到哪个 DNS 服务器，我们总是使用硬编码的服务器
    // 因为有些 DNS 服务器不支持 DNS over TCP
	//上面的udpChunk参数的意思是仅处理udp包，本段代码就是udp的DNS包，如果DNS查询采用TCP，本段代码不生效。如果要同时支持UDP和TCP的DNS请求，需要求改udpChunk为dnsQueryData
    try {
        // 选用 Google 的 DNS 服务器（注：后续可能会改为 Cloudflare 的 1.1.1.1）
        const dnsServer = '1.1.1.1'; // 在 Cloudflare 修复连接自身 IP 的 bug 后，将改为 1.1.1.1
        const dnsPort = 53; // DNS 服务的标准端口

        /** @type {ArrayBuffer | null} */
        let vlessHeader = vlessResponseHeader; // 保存 VLESS 响应头部，用于后续发送

        /** @type {import("@cloudflare/workers-types").Socket} */
        // 与指定的 DNS 服务器建立 TCP 连接
        const tcpSocket = connect({
            hostname: dnsServer,
            port: dnsPort,
        });

        log(`连接到 ${dnsServer}:${dnsPort}`); // 记录连接信息
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk); // 将客户端的 DNS 查询数据发送给 DNS 服务器
        writer.releaseLock(); // 释放写入器，允许其他部分使用

        // 将从 DNS 服务器接收到的响应数据通过 WebSocket 发送回客户端
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    if (vlessHeader) {
                        // 如果有 VLESS 头部，则将其与 DNS 响应数据合并后发送
                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                        vlessHeader = null; // 头部只发送一次，之后置为 null
                    } else {
                        // 否则直接发送 DNS 响应数据
                        webSocket.send(chunk);
                    }
                }
            },
            close() {
                log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`); // 记录连接关闭信息
            },
            abort(reason) {
                console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason); // 记录异常中断原因
            },
        }));
    } catch (error) {
        // 捕获并记录任何可能发生的错误
        console.error(
            `handleDNSQuery 函数发生异常，错误信息: ${error.message}`
        );
    }
}

/**
 * 建立 SOCKS5 代理连接
 * @param {number} addressType 目标地址类型（1: IPv4, 2: 域名, 3: IPv6）
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 * @param {function} log 日志记录函数
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
	const { username, password, hostname, port } = parsedSocks5Address;
	// 连接到 SOCKS5 代理服务器
	const socket = connect({
		hostname, // SOCKS5 服务器的主机名
		port,    // SOCKS5 服务器的端口
	});

	// 请求头格式（Worker -> SOCKS5 服务器）:
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	// https://en.wikipedia.org/wiki/SOCKS#SOCKS5
	// METHODS 字段的含义:
	// 0x00 不需要认证
	// 0x02 用户名/密码认证 https://datatracker.ietf.org/doc/html/rfc1929
	const socksGreeting = new Uint8Array([5, 2, 0, 2]);
	// 5: SOCKS5 版本号, 2: 支持的认证方法数, 0和2: 两种认证方法（无认证和用户名/密码）

	const writer = socket.writable.getWriter();

	await writer.write(socksGreeting);
	log('已发送 SOCKS5 问候消息');

	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	let res = (await reader.read()).value;
	// 响应格式（SOCKS5 服务器 -> Worker）:
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	if (res[0] !== 0x05) {
		log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
		return;
	}
	if (res[1] === 0xff) {
		log("服务器不接受任何认证方法");
		return;
	}

	// 如果返回 0x0502，表示需要用户名/密码认证
	if (res[1] === 0x02) {
		log("SOCKS5 服务器需要认证");
		if (!username || !password) {
			log("请提供用户名和密码");
			return;
		}
		// 认证请求格式:
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		const authRequest = new Uint8Array([
			1,                   // 认证子协议版本
			username.length,    // 用户名长度
			...encoder.encode(username), // 用户名
			password.length,    // 密码长度
			...encoder.encode(password)  // 密码
		]);
		await writer.write(authRequest);
		res = (await reader.read()).value;
		// 期望返回 0x0100 表示认证成功
		if (res[0] !== 0x01 || res[1] !== 0x00) {
			log("SOCKS5 服务器认证失败");
			return;
		}
	}

	// 请求数据格式（Worker -> SOCKS5 服务器）:
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// ATYP: 地址类型
	// 0x01: IPv4 地址
	// 0x03: 域名
	// 0x04: IPv6 地址
	// DST.ADDR: 目标地址
	// DST.PORT: 目标端口（网络字节序）

	// addressType
	// 1 --> IPv4  地址长度 = 4
	// 2 --> 域名
	// 3 --> IPv6  地址长度 = 16
	let DSTADDR;	// DSTADDR = ATYP + DST.ADDR
	switch (addressType) {
		case 1: // IPv4
			DSTADDR = new Uint8Array(
				[1, ...addressRemote.split('.').map(Number)]
			);
			break;
		case 2: // 域名
			DSTADDR = new Uint8Array(
				[3, addressRemote.length, ...encoder.encode(addressRemote)]
			);
			break;
		case 3: // IPv6
			DSTADDR = new Uint8Array(
				[4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
			);
			break;
		default:
			log(`无效的地址类型: ${addressType}`);
			return;
	}
	const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
	// 5: SOCKS5版本, 1: 表示CONNECT请求, 0: 保留字段
	// ...DSTADDR: 目标地址, portRemote >> 8 和 & 0xff: 将端口转为网络字节序
	await writer.write(socksRequest);
	log('已发送 SOCKS5 请求');

	res = (await reader.read()).value;
	// 响应格式（SOCKS5 服务器 -> Worker）:
	//  +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	if (res[1] === 0x00) {
		log("SOCKS5 连接已建立");
	} else {
		log("SOCKS5 连接建立失败");
		return;
	}
	writer.releaseLock();
	reader.releaseLock();
	return socket;
}


/**
 * SOCKS5 代理地址解析器
 * 此函数用于解析 SOCKS5 代理地址字符串，提取出用户名、密码、主机名和端口号
 * 
 * @param {string} address SOCKS5 代理地址，格式可以是：
 *   - "username:password@hostname:port" （带认证）
 *   - "hostname:port" （不需认证）
 *   - "username:password@[ipv6]:port" （IPv6 地址需要用方括号括起来）
 */
function socks5AddressParser(address) {
	// 使用 "@" 分割地址，分为认证部分和服务器地址部分
	// reverse() 是为了处理没有认证信息的情况，确保 latter 总是包含服务器地址
	let [latter, former] = address.split("@").reverse();
	let username, password, hostname, port;

	// 如果存在 former 部分，说明提供了认证信息
	if (former) {
		const formers = former.split(":");
		if (formers.length !== 2) {
			throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
		}
		[username, password] = formers;
	}

	// 解析服务器地址部分
	const latters = latter.split(":");
	// 从末尾提取端口号（因为 IPv6 地址中也包含冒号）
	port = Number(latters.pop());
	if (isNaN(port)) {
		throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
	}

	// 剩余部分就是主机名（可能是域名、IPv4 或 IPv6 地址）
	hostname = latters.join(":");

	// 处理 IPv6 地址的特殊情况
	// IPv6 地址包含多个冒号，所以必须用方括号括起来，如 [2001:db8::1]
	const regex = /^\[.*\]$/;
	if (hostname.includes(":") && !regex.test(hostname)) {
		throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
	}

	if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
	// 返回解析后的结果
	return {
		username,  // 用户名，如果没有则为 undefined
		password,  // 密码，如果没有则为 undefined
		hostname,  // 主机名，可以是域名、IPv4 或 IPv6 地址
		port,     // 端口号，已转换为数字类型
	}
}

/**
 * 恢复被伪装的信息
 * 这个函数用于将内容中的假用户ID和假主机名替换回真实的值
 * 
 * @param {string} content 需要处理的内容
 * @param {string} userID 真实的用户ID
 * @param {string} hostName 真实的主机名
 * @param {boolean} isBase64 内容是否是Base64编码的
 * @returns {string} 恢复真实信息后的内容
 */
function revertFakeInfo(content, userID, hostName, isBase64) {
	if (isBase64) content = atob(content);  // 如果内容是Base64编码的，先解码
	
	// 使用正则表达式全局替换（'g'标志）
	// 将所有出现的假用户ID和假主机名替换为真实的值
	content = content.replace(new RegExp(fakeUserID, 'g'), userID)
	               .replace(new RegExp(fakeHostName, 'g'), hostName);
	
	if (isBase64) content = btoa(content);  // 如果原内容是Base64编码的，处理完后再次编码
	
	return content;
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
  
	// 第一次MD5哈希
	const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
	const firstPassArray = Array.from(new Uint8Array(firstPass));
	const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	// 第二次MD5哈希，使用第一次哈希结果的中间部分（索引7到26）
	const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
	const secondPassArray = Array.from(new Uint8Array(secondPass));
	const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
	return secondHex.toLowerCase();  // 返回小写的十六进制字符串
}

/**
 * 解析并清理环境变量中的地址列表
 * 这个函数用于处理包含多个地址的环境变量
 * 它会移除所有的空白字符、引号等，并将地址列表转换为数组
 * 
 * @param {string} envadd 包含地址列表的环境变量值
 * @returns {Promise<string[]>} 清理和分割后的地址数组
 */
async function ADD(envadd) {
	// 将制表符、双引号、单引号和换行符都替换为逗号
	// 然后将连续的多个逗号替换为单个逗号
	var addtext = envadd.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
	
	// 删除开头和结尾的逗号（如果有的话）
	if (addtext.charAt(0) == ',') addtext = addtext.slice(1);
	if (addtext.charAt(addtext.length - 1) == ',') addtext = addtext.slice(0, addtext.length - 1);
	
	// 使用逗号分割字符串，得到地址数组
	const add = addtext.split(',');
	
	return add;
}

const 啥啥啥_写的这是啥啊 = 'dmxlc3M=';
function 配置信息(UUID, 域名地址) {
	const 协议类型 = atob(啥啥啥_写的这是啥啊);
	
	const 别名 = 域名地址;
	let 地址 = 域名地址;
	let 端口 = 443;

	const 用户ID = UUID;
	const 加密方式 = 'none';
	
	const 传输层协议 = 'ws';
	const 伪装域名 = 域名地址;
	const 路径 = '/?ed=2560';
	
	let 传输层安全 = ['tls',true];
	const SNI = 域名地址;
	const 指纹 = 'randomized';

	if (域名地址.includes('.workers.dev')){
		地址 = 'www.wto.org';
		端口 = 80 ;
		传输层安全 = ['',false];
	}

	const v2ray = `${协议类型}://${用户ID}@${地址}:${端口}?encryption=${加密方式}&security=${传输层安全[0]}&sni=${SNI}&fp=${指纹}&type=${传输层协议}&host=${伪装域名}&path=${encodeURIComponent(路径)}#${encodeURIComponent(别名)}`;
	const clash = `- type: ${协议类型}
  name: ${别名}
  server: ${地址}
  port: ${端口}
  uuid: ${用户ID}
  network: ${传输层协议}
  tls: ${传输层安全[1]}
  udp: false
  sni: ${SNI}
  client-fingerprint: ${指纹}
  ws-opts:
    path: "${路径}"
    headers:
      host: ${伪装域名}`;
	return [v2ray,clash];
}

let subParams = ['sub','base64','b64','clash','singbox','sb'];

/**
 * @param {string} userID
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
async function getVLESSConfig(userID, hostName, sub, UA, RproxyIP, _url) {
	const userAgent = UA.toLowerCase();
	const Config = 配置信息(userID , hostName);
	const v2ray = Config[0];
	const clash = Config[1];
	let proxyhost = "";
	if(hostName.includes(".workers.dev") || hostName.includes(".pages.dev")){
		if ( proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
			try {
				const response = await fetch(proxyhostsURL); 
			
				if (!response.ok) {
					console.error('获取地址时出错:', response.status, response.statusText);
					return; // 如果有错误，直接返回
				}
			
				const text = await response.text();
				const lines = text.split('\n');
				// 过滤掉空行或只包含空白字符的行
				const nonEmptyLines = lines.filter(line => line.trim() !== '');
			
				proxyhosts = proxyhosts.concat(nonEmptyLines);
			} catch (error) {
				//console.error('获取地址时出错:', error);
			}
		} 
		if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
	}

	if ( userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
		let 订阅器 = `您的订阅内容由 ${sub} 提供维护支持, 自动获取ProxyIP: ${RproxyIP}`;
		if (!sub || sub == '') {
			if (!proxyIP || proxyIP =='') {
				订阅器 = '您的订阅内容由 内置 addresses/ADD 参数提供, 当前使用的ProxyIP为空, 推荐您设置 proxyIP/PROXYIP ！！！';
			} else {
				订阅器 = `您的订阅内容由 内置 addresses/ADD 参数提供, 当前使用的ProxyIP： ${proxyIPs.join(',')}`;
			}
		} else if (RproxyIP != 'true'){
			订阅器 += `, 当前使用的ProxyIP： ${proxyIPs.join(',')}`;
		}
		return `
################################################################
Subscribe / sub 订阅地址, 支持 Base64、clash-meta、sing-box 订阅格式, ${订阅器}
---------------------------------------------------------------
快速自适应订阅地址:
https://${proxyhost}${hostName}/${userID}

Base64订阅地址:
https://${proxyhost}${hostName}/${userID}?sub
https://${proxyhost}${hostName}/${userID}?b64
https://${proxyhost}${hostName}/${userID}?base64

clash订阅地址:
https://${proxyhost}${hostName}/${userID}?clash

singbox订阅地址:
https://${proxyhost}${hostName}/${userID}?sb
https://${proxyhost}${hostName}/${userID}?singbox
---------------------------------------------------------------
################################################################
v2ray
---------------------------------------------------------------
${v2ray}
---------------------------------------------------------------
################################################################
clash-meta
---------------------------------------------------------------
${clash}
---------------------------------------------------------------
################################################################
telegram 交流群 技术大佬~在线发牌!
https://t.me/CMLiussss
---------------------------------------------------------------
github 项目地址 Star!Star!Star!!!
https://github.com/cmliu/edgetunnel
---------------------------------------------------------------
################################################################
`;
	} else {
		if (typeof fetch != 'function') {
			return 'Error: fetch is not available in this environment.';
		}

		let newAddressesapi ;
		let newAddressescsv ;
		let newAddressesnotlsapi;
		let newAddressesnotlscsv;

		// 如果是使用默认域名，则改成一个workers的域名，订阅器会加上代理
		if (hostName.includes(".workers.dev")){
			fakeHostName = `${fakeHostName}.workers.dev`;
			newAddressesnotlsapi = await getAddressesapi(addressesnotlsapi);
			newAddressesnotlscsv = await getAddressescsv('FALSE');
		} else if (hostName.includes(".pages.dev")){
			fakeHostName = `${fakeHostName}.pages.dev`;
		} else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true'){
			fakeHostName = `notls.${fakeHostName}.net`;
			newAddressesnotlsapi = await getAddressesapi(addressesnotlsapi);
			newAddressesnotlscsv = await getAddressescsv('FALSE');
		} else {
			fakeHostName = `${fakeHostName}.xyz`
		}

		let url = `https://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID}&edgetunnel=cmliu&proxyip=${RproxyIP}`; //到订阅服务器获取各节点vless配置。
		let isBase64 = true;

		if (!sub || sub == ""){
			if(hostName.includes('workers.dev') || hostName.includes('pages.dev')) {
				if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
					try {
						const response = await fetch(proxyhostsURL); 
					
						if (!response.ok) {
							console.error('获取地址时出错:', response.status, response.statusText);
							return; // 如果有错误，直接返回
						}
					
						const text = await response.text();
						const lines = text.split('\n');
						// 过滤掉空行或只包含空白字符的行
						const nonEmptyLines = lines.filter(line => line.trim() !== '');
					
						proxyhosts = proxyhosts.concat(nonEmptyLines);
					} catch (error) {
						console.error('获取地址时出错:', error);
					}
				}
				// 使用Set对象去重
				proxyhosts = [...new Set(proxyhosts)];
			}
	
			newAddressesapi = await getAddressesapi(addressesapi);
			newAddressescsv = await getAddressescsv('TRUE');
			url = `https://${hostName}/${fakeUserID}`;
		} 

		//通过订阅转换转换各种客户端的配置文件
		if (!userAgent.includes(('CF-Workers-SUB').toLowerCase())){
			if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || ( _url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
				url = `https://${subconverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subconfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			} else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || (( _url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
				url = `https://${subconverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subconfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			}
		}
		
		try {
			let content;
			if ((!sub || sub == "") && isBase64 == true) {
				content = await subAddresses(fakeHostName,fakeUserID,noTLS,newAddressesapi,newAddressescsv,newAddressesnotlsapi,newAddressesnotlscsv);
			} else {
				const response = await fetch(url ,{
					headers: {
						'User-Agent': `${UA} CF-Workers-edgetunnel/cmliu`
					}});
				content = await response.text();
			}
			
			//由于原始订阅请求的url的UUID字段为fakeUserID前的明文，所以在以下检测部分发现!_url.pathname.includes(`/${fakeUserID}`匹配，便进行revertFakeInfo函数的明文转换
			if (!_url.pathname.includes(`/${fakeUserID}`))  {
                               content = revertFakeInfo(content, userID, hostName, isBase64);
			       // 将 tls://1.1.1.1 修改为 tls://8.8.8.8  订阅转无法修改dns配置
                               content = content.replace('tls://1.1.1.1', 'tls://8.8.8.8');
                               // 将 query_type: ["A", "AAAA"] 修改为 query_type: ["A"]  订阅转无法修改dns配置
                               content = content.replace('"query_type":["A","AAAA"]', '"query_type":["A"]');
                        }
			return content;
		} catch (error) {
			console.error('Error fetching content:', error);
			return `Error fetching content: ${error.message}`;
		}

	}
}

async function getAccountId(email, key) {
	try {
		const url = 'https://api.cloudflare.com/client/v4/accounts';
		const headers = new Headers({
			'X-AUTH-EMAIL': email,
			'X-AUTH-KEY': key
		});
		const response = await fetch(url, { headers });
		const data = await response.json();
		return data.result[0].id; // 假设我们需要第一个账号ID
	} catch (error) {
		return false ;
	}
}

async function getSum(accountId, accountIndex, email, key, startDate, endDate) {
	try {
		const startDateISO = new Date(startDate).toISOString();
		const endDateISO = new Date(endDate).toISOString();
	
		const query = JSON.stringify({
			query: `query getBillingMetrics($accountId: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
				viewer {
					accounts(filter: {accountTag: $accountId}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) {
							sum {
								requests
							}
						}
						workersInvocationsAdaptive(limit: 10000, filter: $filter) {
							sum {
								requests
							}
						}
					}
				}
			}`,
			variables: {
				accountId,
				filter: { datetime_geq: startDateISO, datetime_leq: endDateISO }
			},
		});
	
		const headers = new Headers({
			'Content-Type': 'application/json',
			'X-AUTH-EMAIL': email,
			'X-AUTH-KEY': key,
		});
	
		const response = await fetch(`https://api.cloudflare.com/client/v4/graphql`, {
			method: 'POST',
			headers: headers,
			body: query
		});
	
		if (!response.ok) {
			throw new Error(`HTTP error! status: ${response.status}`);
		}
	
		const res = await response.json();
	
		const pagesFunctionsInvocationsAdaptiveGroups = res?.data?.viewer?.accounts?.[accountIndex]?.pagesFunctionsInvocationsAdaptiveGroups;
		const workersInvocationsAdaptive = res?.data?.viewer?.accounts?.[accountIndex]?.workersInvocationsAdaptive;
	
		if (!pagesFunctionsInvocationsAdaptiveGroups && !workersInvocationsAdaptive) {
			throw new Error('找不到数据');
		}
	
		const pagesSum = pagesFunctionsInvocationsAdaptiveGroups.reduce((a, b) => a + b?.sum.requests, 0);
		const workersSum = workersInvocationsAdaptive.reduce((a, b) => a + b?.sum.requests, 0);
	
		//console.log(`范围: ${startDateISO} ~ ${endDateISO}\n默认取第 ${accountIndex} 项`);
	
		return [pagesSum, workersSum ];
	} catch (error) {
		return [ 0,0 ];
	}
}

async function getAddressesapi(api) {
	if (!api || api.length === 0) {
		return [];
	}

	let newapi = "";

	// 创建一个AbortController对象，用于控制fetch请求的取消
	const controller = new AbortController();

	const timeout = setTimeout(() => {
		controller.abort(); // 取消所有请求
	}, 2000); // 2秒后触发

	try {
		// 使用Promise.allSettled等待所有API请求完成，无论成功或失败
		// 对api数组进行遍历，对每个API地址发起fetch请求
		const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
			method: 'get', 
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'User-Agent': 'CF-Workers-edgetunnel/cmliu'
			},
			signal: controller.signal // 将AbortController的信号量添加到fetch请求中，以便于需要时可以取消请求
		}).then(response => response.ok ? response.text() : Promise.reject())));

		// 遍历所有响应
		for (const response of responses) {
			// 检查响应状态是否为'fulfilled'，即请求成功完成
			if (response.status === 'fulfilled') {
				// 获取响应的内容
				const content = await response.value;
				newapi += content + '\n';
			}
		}
	} catch (error) {
		console.error(error);
	} finally {
		// 无论成功或失败，最后都清除设置的超时定时器
		clearTimeout(timeout);
	}

	const newAddressesapi = await ADD(newapi);

	// 返回处理后的结果
	return newAddressesapi;
}

async function getAddressescsv(tls) {
	if (!addressescsv || addressescsv.length === 0) {
		return [];
	}
	
	let newAddressescsv = [];
	
	for (const csvUrl of addressescsv) {
		try {
			const response = await fetch(csvUrl);
		
			if (!response.ok) {
				console.error('获取CSV地址时出错:', response.status, response.statusText);
				continue;
			}
		
			const text = await response.text();// 使用正确的字符编码解析文本内容
			let lines;
			if (text.includes('\r\n')){
				lines = text.split('\r\n');
			} else {
				lines = text.split('\n');
			}
		
			// 检查CSV头部是否包含必需字段
			const header = lines[0].split(',');
			const tlsIndex = header.indexOf('TLS');
			const speedIndex = header.length - 1; // 最后一个字段
		
			const ipAddressIndex = 0;// IP地址在 CSV 头部的位置
			const portIndex = 1;// 端口在 CSV 头部的位置
			const dataCenterIndex = tlsIndex + 1; // 数据中心是 TLS 的后一个字段
		
			if (tlsIndex === -1) {
				console.error('CSV文件缺少必需的字段');
				continue;
			}
		
			// 从第二行开始遍历CSV行
			for (let i = 1; i < lines.length; i++) {
				const columns = lines[i].split(',');
		
				// 检查TLS是否为"TRUE"且速度大于DLS
				if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
					const ipAddress = columns[ipAddressIndex];
					const port = columns[portIndex];
					const dataCenter = columns[dataCenterIndex];
			
					const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
					newAddressescsv.push(formattedAddress);
				}
			}
		} catch (error) {
			console.error('获取CSV地址时出错:', error);
			continue;
		}
	}
	
	return newAddressescsv;
}

function subAddresses(host,UUID,noTLS,newAddressesapi,newAddressescsv,newAddressesnotlsapi,newAddressesnotlscsv) {
	const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
	addresses = addresses.concat(newAddressesapi);
	addresses = addresses.concat(newAddressescsv);
	let notlsresponseBody ;
	if (noTLS == 'true'){
		addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
		addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
		const uniqueAddressesnotls = [...new Set(addressesnotls)];

		notlsresponseBody = uniqueAddressesnotls.map(address => {
			let port = "80";
			let addressid = address;
		
			const match = addressid.match(regex);
			if (!match) {
				if (address.includes(':') && address.includes('#')) {
					const parts = address.split(':');
					address = parts[0];
					const subParts = parts[1].split('#');
					port = subParts[0];
					addressid = subParts[1];
				} else if (address.includes(':')) {
					const parts = address.split(':');
					address = parts[0];
					port = parts[1];
				} else if (address.includes('#')) {
					const parts = address.split('#');
					address = parts[0];
					addressid = parts[1];
				}
			
				if (addressid.includes(':')) {
					addressid = addressid.split(':')[0];
				}
			} else {
				address = match[1];
				port = match[2] || port;
				addressid = match[3] || address;
			}

			let 伪装域名 = host ;
			let 最终路径 = '/?ed=2560' ;
			let 节点备注 = '';
			
			if(proxyhosts.length > 0 && (伪装域名.includes('.workers.dev') || 伪装域名.includes('pages.dev'))) {
				最终路径 = `/${伪装域名}${最终路径}`;
				伪装域名 = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
				节点备注 = ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
			}

			const vlessLink = `vless://${UUID}@${address}:${port}?encryption=none&security=&type=ws&host=${伪装域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;
	
			return vlessLink;

		}).join('\n');

	}

	// 使用Set对象去重
	const uniqueAddresses = [...new Set(addresses)];

	const responseBody = uniqueAddresses.map(address => {
		let port = "443";
		let addressid = address;

		const match = addressid.match(regex);
		if (!match) {
			if (address.includes(':') && address.includes('#')) {
				const parts = address.split(':');
				address = parts[0];
				const subParts = parts[1].split('#');
				port = subParts[0];
				addressid = subParts[1];
			} else if (address.includes(':')) {
				const parts = address.split(':');
				address = parts[0];
				port = parts[1];
			} else if (address.includes('#')) {
				const parts = address.split('#');
				address = parts[0];
				addressid = parts[1];
			}
		
			if (addressid.includes(':')) {
				addressid = addressid.split(':')[0];
			}
		} else {
			address = match[1];
			port = match[2] || port;
			addressid = match[3] || address;
		}
		
		let 伪装域名 = host ;
		let 最终路径 = '/?ed=2560' ;
		let 节点备注 = '';
		
		if(proxyhosts.length > 0 && (伪装域名.includes('.workers.dev') || 伪装域名.includes('pages.dev'))) {
			最终路径 = `/${伪装域名}${最终路径}`;
			伪装域名 = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
			节点备注 = ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
		}
		
		const 协议类型 = atob(啥啥啥_写的这是啥啊);
		const vlessLink = `${协议类型}://${UUID}@${address}:${port}?encryption=none&security=tls&sni=${伪装域名}&fp=random&type=ws&host=${伪装域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;
			
		return vlessLink;
	}).join('\n');

	let base64Response = responseBody; // 重新进行 Base64 编码
	if(noTLS == 'true') base64Response += `\nnotlsresponseBody`;
	return btoa(base64Response);
}

async function sendMessage(type, ip, add_data = "") {
	if ( BotToken !== '' && ChatID !== ''){
		let msg = "";
		const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
		if (response.status == 200) {
			const ipInfo = await response.json();
			msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
		} else {
			msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
		}
	
		let url = "https://api.telegram.org/bot"+ BotToken +"/sendMessage?chat_id=" + ChatID + "&parse_mode=HTML&text=" + encodeURIComponent(msg);
		return fetch(url, {
			method: 'get',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
			}
		});
	}
}
