#!/usr/bin/env python3
"""AgentRouter OAuth 重放签到

AgentRouter（NewAPI 站点）没有独立签到接口：每日 $25 额度由服务端登录 handler 发放，
回包带 checked_in 字段。带着已有 session 调任何接口都不会触发签到，必须真的重走一次
登录鉴权。OAuth 注册的账号没有密码，只能重放 OAuth：

	1. GET  {domain}/api/oauth/state              取 state token（约 10 分钟过期）
	   同时下发 acw_tc（阿里 WAF）与匿名 session，后续 callback 校验 state 依赖它，
	   所以第 1 步和第 3 步必须共用同一个 cookie jar。
	2. GET  {authorize_url}                       带上游 session cookie 换 code
	   已授权过 -> 302，Location 里含 code；首次授权 -> 200 consent 页，需要先取
	   authenticity_token 再 POST 一次。
	3. GET  {domain}/api/oauth/{provider}         触发签到，回包 data.checked_in

支持 GitHub 与 LinuxDO 两种上游身份（NewAPI 的 /api/oauth/{github,linuxdo} 都是真实路由）。
凭据是上游站点的 session cookie：GitHub 的 user_session 官方两周滚动续期；LinuxDO 是
Discourse，认证 cookie 为 _t。

注意：connect.linux.do 有 Cloudflare JS 挑战，从数据中心 IP 纯 HTTP 请求会被 403 拦截
（cf-mitigated: challenge）。家宽出口是否同样被拦需要实测。
"""

import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx

QUOTA_PER_UNIT = 500000  # NewAPI: 500,000 unit = $1
REWARD_UNITS = 12500000  # 每日签到 $25
CHECK_IN_LOG_TYPE = 4  # NewAPI 日志 type=4 为签到记录

_DEFAULT_USER_AGENT = (
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'
)

# cf_clearance 绑定「解挑战时的 IP + User-Agent」，UA 不一致会被 Cloudflare 拒。
# 用 CHECKIN_USER_AGENT 覆盖成浏览器里的真实 UA。
USER_AGENT = os.getenv('CHECKIN_USER_AGENT', '').strip() or _DEFAULT_USER_AGENT

# 站点按北京时间跨日
SITE_TZ = timezone(timedelta(hours=8))


@dataclass(frozen=True)
class OAuthProvider:
	"""上游 OAuth 身份提供方

	Attributes:
		name: NewAPI 的回调路径名，对应 /api/oauth/{name}
		authorize_url: 上游授权端点
		cookie_name: 上游站点的认证 cookie 名，用户只粘裸值时用它补全
		client_id: 站点在上游注册的 client_id（可由 /api/status 覆盖）
		scope: 授权 scope，LinuxDO 不需要
		login_markers: 出现即说明 cookie 失效（被弹回登录页）的页面特征
	"""

	name: str
	authorize_url: str
	cookie_name: str
	client_id: str
	scope: str | None = None
	login_markers: tuple[str, ...] = ()
	# 上游是否需要跟多跳重定向才拿到 code。GitHub 一跳直达；LinuxDO 走 Discourse
	# SSO：authorize -> linux.do/session/sso_provider -> sso_callback -> authorize
	max_redirects: int = 1
	# 跟跳时哪些 host 要带上游 cookie
	cookie_hosts: tuple[str, ...] = ()


GITHUB = OAuthProvider(
	name='github',
	authorize_url='https://github.com/login/oauth/authorize',
	cookie_name='user_session',
	client_id='Ov23lidtiR4LeVZvVRNL',
	scope='user:email',
	login_markers=('id="login_field"', 'action="/session"'),
	max_redirects=1,
	cookie_hosts=('github.com',),
)

LINUXDO = OAuthProvider(
	name='linuxdo',
	authorize_url='https://connect.linux.do/oauth2/authorize',
	cookie_name='_t',
	client_id='KZUecGfhhDZMVnv8UtEdhOhf9sNOhqVX',
	scope=None,
	login_markers=('id="login-account-name"', '/session/csrf', 'Just a moment'),
	max_redirects=8,
	cookie_hosts=('linux.do',),
)

OAUTH_PROVIDERS = {'github': GITHUB, 'linuxdo': LINUXDO}


def get_oauth_provider(name: str | None) -> OAuthProvider:
	"""按名称取上游 provider，默认 GitHub（向后兼容）"""
	key = (name or 'github').strip().lower().replace('-', '').replace('_', '')
	if key in ('linuxdo', 'linux'):
		return LINUXDO
	if key == 'github':
		return GITHUB
	raise ValueError(f'Unsupported OAuth provider: {name}')


def quota_to_usd(quota) -> float:
	"""额度单位换算成美元"""
	if not quota:
		return 0.0
	return round(quota / QUOTA_PER_UNIT, 2)


def format_upstream_cookie(raw_cookie: str, provider: OAuthProvider = GITHUB) -> str:
	"""把裸 cookie 值或完整 cookie 串规范成 Cookie 头的值

	用户从 DevTools 复制的可能只是认证 cookie 的值，也可能是整条 cookie 串。
	整条串按原样透传（只清掉换行），避免猜错上游需要的其他 cookie。
	"""
	trimmed = (raw_cookie or '').strip()
	if not trimmed:
		return ''
	if f'{provider.cookie_name}=' not in trimmed and ';' not in trimmed:
		if provider is GITHUB:
			return f'{provider.cookie_name}={trimmed}; logged_in=yes'
		return f'{provider.cookie_name}={trimmed}'
	return re.sub(r'[\r\n\t]+', ' ', trimmed)


def is_timestamp_today(raw) -> bool:
	"""判断时间戳是否落在站点时区的今天（秒级/毫秒级/字符串都接受）"""
	if raw is None or isinstance(raw, bool):
		return False
	try:
		value = float(raw)
	except (TypeError, ValueError):
		return False
	if value <= 0:
		return False
	seconds = value if value < 1e12 else value / 1000
	try:
		stamp = datetime.fromtimestamp(seconds, tz=SITE_TZ)
	except (OverflowError, OSError, ValueError):
		return False
	return stamp.date() == datetime.now(tz=SITE_TZ).date()


def site_headers(domain: str) -> dict:
	"""站内 API 请求头"""
	return {
		'User-Agent': USER_AGENT,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
		'Referer': f'{domain}/login',
		'Origin': domain,
		'Sec-Fetch-Dest': 'empty',
		'Sec-Fetch-Mode': 'cors',
		'Sec-Fetch-Site': 'same-origin',
	}


def fetch_oauth_state(client: httpx.Client, domain: str) -> tuple[str | None, str | None]:
	"""第 1 步：取 state token

	响应同时下发 acw_tc 与匿名 session，由 client 的 cookie jar 持有，
	callback 校验 state 时要带回去。

	Returns:
		(state, error)
	"""
	try:
		response = client.get(f'{domain}/api/oauth/state', params={'mode': 'login'}, headers=site_headers(domain))
	except Exception as e:
		return None, f'请求 state 失败: {type(e).__name__}: {str(e)[:80]}'

	if response.status_code != 200:
		return None, f'state 接口返回 HTTP {response.status_code}'

	try:
		payload = response.json()
	except ValueError:
		return None, f'state 接口返回非 JSON: {response.text[:80]}'

	if payload.get('success') and payload.get('data'):
		return str(payload['data']), None

	return None, f'state 接口未返回 token: {payload.get("message") or response.text[:80]}'


def _code_from_location(location: str) -> tuple[str | None, str | None]:
	"""从 302 的 Location 中取 code 与 state"""
	if not location:
		return None, None
	query = parse_qs(urlparse(location).query)
	code = query.get('code', [None])[0]
	state = query.get('state', [None])[0]
	return code, state


def _looks_like_login_page(location: str, body: str, provider: OAuthProvider) -> bool:
	"""判断上游是否把我们弹回了登录页（等价于 cookie 失效）"""
	host = urlparse(provider.authorize_url).netloc
	if location and (f'{host}/login' in location or location.startswith('/login')):
		return True
	return any(marker in body for marker in provider.login_markers)


def get_oauth_code(
	client: httpx.Client, state: str, upstream_cookie: str, provider: OAuthProvider = GITHUB
) -> tuple[str | None, str | None, str | None]:
	"""第 2 步：用上游 session cookie 换 authorization code

	Returns:
		(code, returned_state, error)
	"""
	cookie_header = format_upstream_cookie(upstream_cookie, provider)
	if not cookie_header:
		return None, None, f'{provider.name} cookie 为空'

	params = {'client_id': provider.client_id, 'state': state}
	if provider.scope:
		params['scope'] = provider.scope
	else:
		# LinuxDO(Discourse) 的 OAuth2 端点要求显式 response_type
		params['response_type'] = 'code'

	headers = {
		'User-Agent': USER_AGENT,
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'en-US,en;q=0.9',
		'Cookie': cookie_header,
	}

	try:
		response = client.get(provider.authorize_url, params=params, headers=headers, follow_redirects=False)
	except Exception as e:
		return None, None, f'请求 {provider.name} authorize 失败: {type(e).__name__}: {str(e)[:80]}'

	location = response.headers.get('location', '')

	# 已授权过：直接 302 带回 code
	if response.status_code in (301, 302):
		if _looks_like_login_page(location, '', provider):
			return None, None, f'{provider.name} cookie 已失效，请重新从浏览器复制 {provider.cookie_name}'
		code, returned_state = _code_from_location(location)
		if code:
			return code, returned_state or state, None
		return None, None, f'{provider.name} 302 未带 code: {location[:100]}'

	# 首次授权：200 consent 页，取 authenticity_token 再 POST 一次
	if response.status_code == 200:
		body = response.text
		if _looks_like_login_page('', body, provider):
			return None, None, f'{provider.name} 要求重新登录，{provider.cookie_name} cookie 无效'
		return _submit_consent_form(client, body, state, cookie_header, provider)

	# Cloudflare 对数据中心 IP 的 JS 挑战
	if response.status_code == 403 and 'challenge' in response.headers.get('cf-mitigated', ''):
		return None, None, f'{provider.name} 被 Cloudflare 挑战拦截（当前出口 IP 需换网络或用浏览器方案）'

	return None, None, f'{provider.name} authorize 返回 HTTP {response.status_code}'


def _submit_consent_form(
	client: httpx.Client, html: str, state: str, cookie_header: str, provider: OAuthProvider = GITHUB
) -> tuple[str | None, str | None, str | None]:
	"""在 consent 页提交授权表单换 code"""
	match = re.search(r'name=["\']authenticity_token["\']\s+value=["\']([^"\']+)["\']', html, re.I)
	if not match:
		return None, None, 'consent 页未找到 authenticity_token'

	form = {
		'authenticity_token': match.group(1),
		'client_id': provider.client_id,
		'state': state,
		'authorize': '1',
	}
	if provider.scope:
		form['scope'] = provider.scope
	else:
		form['response_type'] = 'code'

	headers = {
		'User-Agent': USER_AGENT,
		'Content-Type': 'application/x-www-form-urlencoded',
		'Cookie': cookie_header,
		'Referer': provider.authorize_url,
	}

	try:
		response = client.post(provider.authorize_url, data=form, headers=headers, follow_redirects=False)
	except Exception as e:
		return None, None, f'提交 consent 表单失败: {type(e).__name__}: {str(e)[:80]}'

	if response.status_code in (301, 302):
		code, returned_state = _code_from_location(response.headers.get('location', ''))
		if code:
			return code, returned_state or state, None

	return None, None, f'consent 表单提交后未拿到 code (HTTP {response.status_code})'


def exchange_oauth_callback(
	client: httpx.Client, domain: str, code: str, state: str, provider: OAuthProvider = GITHUB
) -> tuple[dict | None, str | None]:
	"""第 3 步：回调触发签到

	Returns:
		(user_data, error)
	"""
	params = {'code': code, 'state': state, 'mode': 'login'}
	try:
		response = client.get(f'{domain}/api/oauth/{provider.name}', params=params, headers=site_headers(domain))
	except Exception as e:
		return None, f'OAuth 回调失败: {type(e).__name__}: {str(e)[:80]}'

	try:
		payload = response.json()
	except ValueError:
		return None, f'OAuth 回调返回非 JSON (HTTP {response.status_code}): {response.text[:80]}'

	if payload.get('success'):
		data = payload.get('data') or {}
		user = data.get('user') if isinstance(data.get('user'), dict) else data
		return user or {}, None

	return None, f'OAuth 回调被拒: {payload.get("message") or f"HTTP {response.status_code}"}'


def password_login(
	client: httpx.Client, domain: str, username: str, password: str, login_path: str = '/api/user/login'
) -> tuple[dict | None, str | None]:
	"""用账号密码重新登录，触发签到

	和 OAuth 回调是同一个服务端 handler：当天未签到就发放额度，回包带 checked_in。
	站点 turnstile_check 为 false 时 turnstile 参数留空即可。

	Returns:
		(user_data, error)
	"""
	if not username or not password:
		return None, '缺少 username 或 password'

	headers = site_headers(domain)
	headers['Content-Type'] = 'application/json'

	try:
		response = client.post(
			f'{domain}{login_path}',
			params={'turnstile': ''},
			json={'username': username, 'password': password},
			headers=headers,
		)
	except Exception as e:
		return None, f'密码登录失败: {type(e).__name__}: {str(e)[:80]}'

	try:
		payload = response.json()
	except ValueError:
		return None, f'登录接口返回非 JSON (HTTP {response.status_code}): {response.text[:80]}'

	if payload.get('success'):
		data = payload.get('data') or {}
		user = data.get('user') if isinstance(data.get('user'), dict) else data
		return user or {}, None

	return None, f'登录被拒: {payload.get("message") or f"HTTP {response.status_code}"}'


def fetch_user_self(client: httpx.Client, domain: str, api_user: str | None) -> dict | None:
	"""读 /api/user/self（纯读，不触发签到）"""
	headers = site_headers(domain)
	headers['Referer'] = f'{domain}/console'
	if api_user:
		headers['New-Api-User'] = str(api_user)

	try:
		response = client.get(f'{domain}/api/user/self', headers=headers)
	except Exception:
		return None

	if response.status_code != 200:
		return None

	try:
		payload = response.json()
	except ValueError:
		return None

	if payload.get('success') and isinstance(payload.get('data'), dict):
		return payload['data']
	return None


def has_check_in_log_today(client: httpx.Client, domain: str, api_user: str | None) -> bool:
	"""查 /api/log/self 里今天有没有签到记录

	额度增量测不到时的第二重证据（例如签到后余额查询失败，或今天已签过）。
	"""
	headers = site_headers(domain)
	headers['Referer'] = f'{domain}/console/log'
	if api_user:
		headers['New-Api-User'] = str(api_user)

	# 必须带 type 过滤：账号请求量大时，不过滤的第一页会被 type=2 消费记录占满，
	# 今天的签到记录被挤到后面几页，核验就会假阴性。
	params = {'p': 1, 'page_size': 20, 'type': CHECK_IN_LOG_TYPE}
	try:
		response = client.get(f'{domain}/api/log/self', params=params, headers=headers)
	except Exception:
		return False

	if response.status_code != 200:
		return False

	try:
		payload = response.json()
	except ValueError:
		return False

	data = payload.get('data')
	items = data.get('items') if isinstance(data, dict) else data
	if not isinstance(items, list):
		return False

	for item in items:
		if not isinstance(item, dict):
			continue
		if item.get('type') != CHECK_IN_LOG_TYPE:
			continue
		if is_timestamp_today(item.get('created_at') or item.get('timestamp')):
			return True
	return False


def reward_visible_in_delta(user: dict, quota_before: int | None, quota_before_fresh: bool) -> bool:
	"""额度增量本身是否已经证明签到到账

	站方是在登录 handler 里异步发放 $25 的，登录后立刻复读余额往往看不到增量
	（也可能刚到账就被正在跑的请求花掉）。所以只有这里返回 True 才允许省掉日志核验。
	"""
	if not quota_before_fresh or quota_before is None:
		return False
	quota_now = user.get('quota') if isinstance(user, dict) else None
	if not isinstance(quota_now, (int, float)):
		return False
	return quota_now - quota_before >= REWARD_UNITS


def build_check_in_result(
	user: dict,
	quota_before: int | None,
	quota_before_fresh: bool,
	log_confirms_today: bool,
) -> dict:
	"""按硬证据判定签到结果，不猜

	三档：
		verified       额度增量 >= $25，或站内日志有今天的签到记录 —— 确实到账
		already_claimed 登录时间是今天但增量为 0 —— 今天早先已签过
		ambiguous      链路走通但拿不到任何证据 —— 报告出去，不谎称成功
	"""
	quota_now = user.get('quota') if isinstance(user, dict) else None
	login_today = is_timestamp_today(user.get('last_login_time') if isinstance(user, dict) else None)

	delta = None
	if quota_before is not None and isinstance(quota_now, (int, float)):
		delta = quota_now - quota_before

	reward_measured = reward_visible_in_delta(user, quota_before, quota_before_fresh)
	verified = bool(reward_measured or log_confirms_today)
	already_claimed = bool(login_today and not verified)

	if reward_measured:
		message = f'签到到账 +${quota_to_usd(delta)}（额度增量已核实）'
	elif log_confirms_today:
		message = '签到成功（站内日志已有今日签到记录）'
	elif already_claimed:
		message = '今日已签到（登录时间为今天，额度无增量）'
	elif login_today:
		message = '登录成功但无法确认签到是否到账'
	else:
		message = '登录后 last_login_time 不是今天，签到可能未生效'

	return {
		'verified': verified,
		'already_claimed': already_claimed,
		'login_today': login_today,
		'quota': quota_now,
		'quota_delta': delta,
		'message': message,
		'used_quota': user.get('used_quota') if isinstance(user, dict) else None,
		'user_id': user.get('id') if isinstance(user, dict) else None,
		'display_name': (user.get('display_name') or user.get('username')) if isinstance(user, dict) else None,
	}


def _read_quota_baseline(domain: str, session_cookie: str | None, api_user: str | None) -> tuple[int | None, bool]:
	"""用旧 session 读签到前额度作为基线

	纯读操作，不触发签到。拿不到就返回 (None, False)，后续判定改用日志证据。
	"""
	if not session_cookie:
		return None, False

	try:
		with httpx.Client(http2=True, timeout=30.0, cookies={'session': session_cookie}) as client:
			user = fetch_user_self(client, domain, api_user)
	except Exception:
		return None, False

	if user and isinstance(user.get('quota'), (int, float)):
		return int(user['quota']), True
	return None, False


def check_in_via_password(
	account_name: str,
	domain: str,
	username: str,
	password: str,
	api_user: str | None = None,
	session_cookie: str | None = None,
	login_path: str = '/api/user/login',
) -> tuple[bool, dict | None, str | None]:
	"""用密码重新登录完成一次签到

	比 OAuth 重放简单一个数量级：没有上游站点，也就没有反爬和跨站跳转。

	Returns:
		(success, result, error)
	"""
	if not username or not password:
		return False, None, '未配置 username/password，无法用密码登录签到'

	quota_before, quota_before_fresh = _read_quota_baseline(domain, session_cookie, api_user)
	if quota_before is not None:
		print(f'[INFO] {account_name}: 签到前余额 ${quota_to_usd(quota_before)}')
	else:
		print(f'[INFO] {account_name}: 未取到签到前余额基线，将改用站内日志核验')

	with httpx.Client(http2=True, timeout=30.0, follow_redirects=False) as client:
		user, error = password_login(client, domain, username, password, login_path)
		if user is None:
			return False, None, error

		print(f'[SUCCESS] {account_name}: 密码登录完成，登录态已刷新')

		# 登录下发的新 session 已在 jar 里，用它复读一次拿权威额度
		fresh_user = fetch_user_self(client, domain, api_user or user.get('id'))
		if fresh_user:
			user = fresh_user

		# 增量没能证明到账时，一定要查站内日志——不能退而用「登录时间是今天」猜
		log_confirms_today = False
		if not reward_visible_in_delta(user, quota_before, quota_before_fresh):
			log_confirms_today = has_check_in_log_today(client, domain, api_user or user.get('id'))

	result = build_check_in_result(user, quota_before, quota_before_fresh, log_confirms_today)
	success = bool(result['verified'] or result['already_claimed'])
	return success, result, None if success else result['message']


def check_in_via_oauth(
	account_name: str,
	domain: str,
	upstream_cookie: str,
	api_user: str | None = None,
	session_cookie: str | None = None,
	provider: OAuthProvider = GITHUB,
) -> tuple[bool, dict | None, str | None]:
	"""重放上游 OAuth 完成一次签到

	Returns:
		(success, result, error) —— success 表示链路走通且有签到证据
	"""
	if not upstream_cookie:
		return False, None, f'未配置 {provider.name} cookie，无法重放 OAuth'

	quota_before, quota_before_fresh = _read_quota_baseline(domain, session_cookie, api_user)
	if quota_before is not None:
		print(f'[INFO] {account_name}: 签到前余额 ${quota_to_usd(quota_before)}')
	else:
		print(f'[INFO] {account_name}: 未取到签到前余额基线，将改用站内日志核验')

	# state 与 callback 必须共用 cookie jar：state 下发的匿名 session 是回调的校验凭据
	with httpx.Client(http2=True, timeout=30.0, follow_redirects=False) as client:
		state, error = fetch_oauth_state(client, domain)
		if not state:
			return False, None, error

		print(f'[INFO] {account_name}: 已取到 state token')

		code, returned_state, error = get_oauth_code(client, state, upstream_cookie, provider)
		if not code:
			return False, None, error

		print(f'[INFO] {account_name}: 已从 {provider.name} 换到 authorization code')

		user, error = exchange_oauth_callback(client, domain, code, returned_state or state, provider)
		if user is None:
			return False, None, error

		print(f'[SUCCESS] {account_name}: OAuth 回调完成，登录态已刷新')

		# 回调下发的新 session 已在 jar 里，用它复读一次拿到权威额度
		fresh_user = fetch_user_self(client, domain, api_user or user.get('id'))
		if fresh_user:
			user = fresh_user

		# 增量没能证明到账时，一定要查站内日志——不能退而用「登录时间是今天」猜
		log_confirms_today = False
		if not reward_visible_in_delta(user, quota_before, quota_before_fresh):
			log_confirms_today = has_check_in_log_today(client, domain, api_user or user.get('id'))

	result = build_check_in_result(user, quota_before, quota_before_fresh, log_confirms_today)
	success = bool(result['verified'] or result['already_claimed'])
	return success, result, None if success else result['message']
