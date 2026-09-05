#!/usr/bin/env python3
"""
配置管理模块
"""

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Literal


@dataclass
class ProviderConfig:
	"""Provider 配置"""

	name: str
	domain: str
	login_path: str = '/login'
	sign_in_path: str | None = '/api/user/sign_in'
	user_info_path: str = '/api/user/self'
	api_user_key: str = 'new-api-user'
	bypass_method: Literal['waf_cookies'] | None = None
	waf_cookie_names: List[str] | None = None
	check_in_method: Literal['sign_in_api', 'github_oauth', 'password_login'] = 'sign_in_api'
	backup_domain: str | None = None
	login_api_path: str = '/api/user/login'
	# 浏览器去哪个地址触发 WAF 挑战。acw_sc__v2 只在挑战真的弹出后才下发，
	# 所以这个地址必须是会被拦的那个——两个站的拦截位置不一样：
	# anyrouter 的 /login 页面就被拦，agentrouter 只拦 API。
	waf_warmup_path: str | None = None
	# 整条链路都在浏览器里跑，而不是抠出 cookie 交给 httpx。
	# acw_sc__v2 绑浏览器上下文，抠出来重放很脆——UA/IP/时序任一不吻合就失效。
	check_in_in_browser: bool = False

	def __post_init__(self):
		required_waf_cookies = set()
		if self.waf_cookie_names and isinstance(self.waf_cookie_names, List):
			for item in self.waf_cookie_names:
				name = '' if not item or not isinstance(item, str) else item.strip()
				if not name:
					print(f'[WARNING] Found invalid WAF cookie name: {item}')
					continue

				required_waf_cookies.add(name)

		if not required_waf_cookies:
			self.bypass_method = None

		self.waf_cookie_names = list(required_waf_cookies)

	@classmethod
	def from_dict(cls, name: str, data: dict) -> 'ProviderConfig':
		"""从字典创建 ProviderConfig

		配置格式:
		- 基础: {"domain": "https://example.com"}
		- 完整: {"domain": "https://example.com", "login_path": "/login", "api_user_key": "x-api-user", "bypass_method": "waf_cookies", ...}
		"""
		return cls(
			name=name,
			domain=data['domain'],
			login_path=data.get('login_path', '/login'),
			sign_in_path=data.get('sign_in_path', '/api/user/sign_in'),
			user_info_path=data.get('user_info_path', '/api/user/self'),
			api_user_key=data.get('api_user_key', 'new-api-user'),
			bypass_method=data.get('bypass_method'),
			waf_cookie_names=data.get('waf_cookie_names'),
			check_in_method=data.get('check_in_method', 'sign_in_api'),
			backup_domain=data.get('backup_domain'),
			login_api_path=data.get('login_api_path', '/api/user/login'),
			waf_warmup_path=data.get('waf_warmup_path'),
			check_in_in_browser=bool(data.get('check_in_in_browser', False)),
		)

	def needs_waf_cookies(self) -> bool:
		"""判断是否需要获取 WAF cookies"""
		return self.bypass_method == 'waf_cookies'

	def waf_warmup_url(self, domain: str | None = None) -> str:
		"""浏览器该访问哪个地址来触发 WAF 挑战

		默认用登录页，配了 waf_warmup_path 就用它——只拦 API 的站点必须指到
		被拦的接口上，否则浏览器一路畅通，拿不到 acw_sc__v2。
		"""
		return f'{domain or self.domain}{self.waf_warmup_path or self.login_path}'

	def uses_password_login(self) -> bool:
		"""判断是否靠账号密码重新登录触发签到

		和 OAuth 同一个服务端 handler，但只需一个 POST，且不受上游反爬影响。
		"""
		return self.check_in_method == 'password_login'

	def uses_github_oauth(self) -> bool:
		"""判断是否靠重放 GitHub OAuth 触发签到

		这类站点（agentrouter）没有签到接口，额度由登录 handler 发放。
		"""
		return self.check_in_method == 'github_oauth'

	def needs_manual_check_in(self) -> bool:
		"""判断是否需要手动调用签到接口"""
		return self.check_in_method == 'sign_in_api' and self.sign_in_path is not None

	def candidate_domains(self) -> List[str]:
		"""主域名 + 备用域名（主域名被 DNS 污染/WAF 拦时回退）"""
		domains = [self.domain]
		if self.backup_domain and self.backup_domain not in domains:
			domains.append(self.backup_domain)
		return domains


@dataclass
class AppConfig:
	"""应用配置"""

	providers: Dict[str, ProviderConfig]

	@classmethod
	def load_from_env(cls) -> 'AppConfig':
		"""从环境变量加载配置"""
		providers = {
			'anyrouter': ProviderConfig(
				name='anyrouter',
				domain='https://anyrouter.top',
				login_path='/login',
				sign_in_path='/api/user/sign_in',
				user_info_path='/api/user/self',
				api_user_key='new-api-user',
				bypass_method='waf_cookies',
				waf_cookie_names=['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'],
			),
			# agentrouter 没有签到接口：每日 $25 由服务端登录 handler 发放，
			# 必须重放一次登录才会触发。带旧 session 查任何接口都没用。
			#
			# 同样在阿里云 WAF 后面：住宅 IP 直连没事，机房 IP（GitHub Actions）
			# 会被 HTTP 200 + JS 挑战页顶回来（body 里有 aliyun_waf_aa 标记），
			# 所以和 anyrouter 一样要先用浏览器解挑战拿 cookie。
			'agentrouter': ProviderConfig(
				name='agentrouter',
				domain='https://agentrouter.org',
				login_path='/login',
				sign_in_path=None,
				user_info_path='/api/user/self',
				api_user_key='new-api-user',
				bypass_method='waf_cookies',
				waf_cookie_names=['acw_tc', 'acw_sc__v2'],
				# /login 是前端页面，不被拦；挑战只在 API 上弹，所以浏览器得去
				# 打这个接口，否则拿不到 acw_sc__v2（CI 实测只拿到 acw_tc）。
				waf_warmup_path='/api/oauth/state?mode=login',
				check_in_in_browser=True,
				check_in_method='github_oauth',
				backup_domain='https://ps.air-outer.com',
			),
		}

		# 尝试从环境变量加载自定义 providers
		providers_str = os.getenv('PROVIDERS')
		if providers_str:
			try:
				providers_data = json.loads(providers_str)

				if not isinstance(providers_data, dict):
					print('[WARNING] PROVIDERS must be a JSON object, ignoring custom providers')
					return cls(providers=providers)

				# 解析自定义 providers,会覆盖默认配置
				for name, provider_data in providers_data.items():
					try:
						providers[name] = ProviderConfig.from_dict(name, provider_data)
					except Exception as e:
						print(f'[WARNING] Failed to parse provider "{name}": {e}, skipping')
						continue

				print(f'[INFO] Loaded {len(providers_data)} custom provider(s) from PROVIDERS environment variable')
			except json.JSONDecodeError as e:
				print(
					f'[WARNING] Failed to parse PROVIDERS environment variable: {e}, using default configuration only'
				)
			except Exception as e:
				print(f'[WARNING] Error loading PROVIDERS: {e}, using default configuration only')

		return cls(providers=providers)

	def get_provider(self, name: str) -> ProviderConfig | None:
		"""获取指定 provider 配置

		支持以下格式匹配:
		- 精确名称: "anyrouter", "agentrouter"
		- 域名格式: "anyrouter.top", "agentrouter.org"
		- 完整URL: "https://anyrouter.top"
		"""
		# 1. 精确匹配
		provider = self.providers.get(name)
		if provider:
			return provider

		# 2. 域名/URL 模糊匹配
		normalized = name.lower().strip()
		# 移除协议前缀
		for prefix in ('https://', 'http://'):
			if normalized.startswith(prefix):
				normalized = normalized[len(prefix) :]
				break
		# 移除尾部斜杠
		normalized = normalized.rstrip('/')

		for provider in self.providers.values():
			domain = provider.domain.lower()
			for prefix in ('https://', 'http://'):
				if domain.startswith(prefix):
					domain = domain[len(prefix) :]
					break
			domain = domain.rstrip('/')
			if domain == normalized:
				return provider

		return None


@dataclass
class AccountConfig:
	"""账号配置"""

	cookies: dict | str
	api_user: str
	provider: str = 'anyrouter'
	name: str | None = None
	oauth_cookie: str | None = None
	oauth_provider: str = 'github'
	username: str | None = None
	password: str | None = None

	@classmethod
	def from_dict(cls, data: dict, index: int) -> 'AccountConfig':
		"""从字典创建 AccountConfig"""
		provider = data.get('provider', 'anyrouter')
		name = data.get('name', f'Account {index + 1}')

		# oauth_cookie 是新名字，github_cookie 保留兼容
		oauth_cookie = data.get('oauth_cookie') or data.get('github_cookie')
		oauth_provider = data.get('oauth_provider') or 'github'

		return cls(
			cookies=data.get('cookies') or {},
			api_user=data['api_user'],
			provider=provider,
			name=name if name else None,
			oauth_cookie=resolve_secret(oauth_cookie),
			oauth_provider=str(oauth_provider).strip().lower(),
			username=resolve_secret(data.get('username')),
			password=resolve_secret(data.get('password')),
		)

	def has_password_credentials(self) -> bool:
		"""是否具备密码登录所需凭据"""
		return bool(self.username and self.password)

	def get_display_name(self, index: int) -> str:
		"""获取显示名称"""
		return self.name if self.name else f'Account {index + 1}'

	def get_session_cookie(self) -> str | None:
		"""取站内 session cookie（用于读签到前余额基线）"""
		if isinstance(self.cookies, dict):
			value = self.cookies.get('session')
			return str(value) if value else None
		if isinstance(self.cookies, str):
			for pair in self.cookies.split(';'):
				if '=' in pair:
					key, value = pair.strip().split('=', 1)
					if key == 'session':
						return value
		return None


def resolve_secret(value: str | None) -> str | None:
	"""解析 "env:VAR" 形式的间接引用

	让账号 JSON 里只写变量名，真正的凭据放环境变量/Actions secrets。
	"""
	if not value or not isinstance(value, str):
		return None
	trimmed = value.strip()
	if trimmed.startswith('env:'):
		env_name = trimmed[4:].strip()
		if not env_name:
			return None
		resolved = os.getenv(env_name)
		if not resolved:
			print(f'[WARNING] Environment variable "{env_name}" referenced but not set')
			return None
		return resolved.strip()
	return trimmed


def load_accounts_config() -> list[AccountConfig] | None:
	"""从环境变量加载账号配置"""
	accounts_str = os.getenv('ANYROUTER_ACCOUNTS')
	if not accounts_str:
		print('ERROR: ANYROUTER_ACCOUNTS environment variable not found')
		return None

	try:
		accounts_data = json.loads(accounts_str)

		if not isinstance(accounts_data, list):
			print('ERROR: Account configuration must use array format [{}]')
			return None

		accounts = []
		for i, account_dict in enumerate(accounts_data):
			if not isinstance(account_dict, dict):
				print(f'ERROR: Account {i + 1} configuration format is incorrect')
				return None

			if 'api_user' not in account_dict:
				print(f'ERROR: Account {i + 1} missing required field (api_user)')
				return None

			# OAuth 重放与密码登录都不需要站内 cookies（session 由登录现取）
			has_oauth_cookie = 'oauth_cookie' in account_dict or 'github_cookie' in account_dict
			has_password = 'username' in account_dict and 'password' in account_dict
			if 'cookies' not in account_dict and not has_oauth_cookie and not has_password:
				print(f'ERROR: Account {i + 1} needs one of: cookies, oauth_cookie, or username+password')
				return None

			if 'name' in account_dict and not account_dict['name']:
				print(f'ERROR: Account {i + 1} name field cannot be empty')
				return None

			accounts.append(AccountConfig.from_dict(account_dict, i))

		return accounts
	except Exception as e:
		print(f'ERROR: Account configuration format is incorrect: {e}')
		return None
