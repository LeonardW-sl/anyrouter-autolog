#!/usr/bin/env python3
"""密码登录签到测试"""

import json
import sys
from pathlib import Path

import httpx

# 添加项目根目录到 PATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest

import checkin
from utils.agentrouter_oauth import REWARD_UNITS, password_login
from utils.config import AccountConfig, AppConfig, ProviderConfig, load_accounts_config

DOMAIN = 'https://agentrouter.org'
FAKE_WAF = {'acw_tc': 'a', 'cdn_sec_tc': 'b', 'acw_sc__v2': 'c'}


@pytest.fixture(autouse=True)
def stub_waf(monkeypatch):
	"""agentrouter 现在要过阿里云 WAF，单元测试不该真起浏览器"""

	async def fake_waf(account_name, login_url, required, allow_partial=False):
		return dict(FAKE_WAF)

	monkeypatch.setattr(checkin, 'get_waf_cookies_with_playwright', fake_waf)


def make_client(handler) -> httpx.Client:
	return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


class TestPasswordLogin:
	def test_login_posts_credentials(self):
		captured = {}

		def handler(request: httpx.Request) -> httpx.Response:
			captured['path'] = request.url.path
			captured['turnstile'] = request.url.params.get('turnstile')
			captured['body'] = json.loads(request.content)
			payload = {'success': True, 'data': {'id': 245573, 'quota': 13000000, 'checked_in': True}}
			return httpx.Response(200, json=payload)

		with make_client(handler) as client:
			user, error = password_login(client, DOMAIN, 'linuxdo_245573', 'secret')

		assert error is None
		assert user['id'] == 245573
		assert captured['path'] == '/api/user/login'
		# turnstile_check 为 false，参数留空
		assert captured['turnstile'] == ''
		assert captured['body'] == {'username': 'linuxdo_245573', 'password': 'secret'}

	def test_nested_user_payload(self):
		payload = {'success': True, 'data': {'user': {'id': 1, 'quota': 5}}}
		with make_client(lambda r: httpx.Response(200, json=payload)) as client:
			user, error = password_login(client, DOMAIN, 'u', 'p')

		assert user['id'] == 1

	def test_wrong_password(self):
		payload = {'success': False, 'message': '用户名或密码错误，或用户已被封禁'}
		with make_client(lambda r: httpx.Response(200, json=payload)) as client:
			user, error = password_login(client, DOMAIN, 'u', 'bad')

		assert user is None
		assert '密码错误' in error

	def test_missing_credentials(self):
		with make_client(lambda r: httpx.Response(200)) as client:
			user, error = password_login(client, DOMAIN, '', 'p')

		assert user is None
		assert 'username' in error

	def test_non_json_response(self):
		with make_client(lambda r: httpx.Response(405, text='blocked')) as client:
			user, error = password_login(client, DOMAIN, 'u', 'p')

		assert user is None
		assert '非 JSON' in error

	def test_custom_login_path(self):
		def handler(request: httpx.Request) -> httpx.Response:
			assert request.url.path == '/api/auth/signin'
			return httpx.Response(200, json={'success': True, 'data': {'id': 1}})

		with make_client(handler) as client:
			user, error = password_login(client, DOMAIN, 'u', 'p', '/api/auth/signin')

		assert error is None


class TestPasswordConfig:
	def test_provider_password_mode(self):
		provider = ProviderConfig.from_dict('ag', {'domain': DOMAIN, 'check_in_method': 'password_login'})

		assert provider.uses_password_login() is True
		assert provider.uses_github_oauth() is False
		assert provider.needs_manual_check_in() is False
		assert provider.login_api_path == '/api/user/login'

	def test_credentials_resolved_from_env(self, monkeypatch):
		monkeypatch.setenv('AG2_USER', 'linuxdo_245573')
		monkeypatch.setenv('AG2_PASS', 'generated-pw')
		account = AccountConfig.from_dict(
			{
				'api_user': '245573',
				'provider': 'agentrouter',
				'username': 'env:AG2_USER',
				'password': 'env:AG2_PASS',
			},
			0,
		)

		assert account.username == 'linuxdo_245573'
		assert account.password == 'generated-pw'
		assert account.has_password_credentials() is True

	def test_partial_credentials_not_usable(self):
		account = AccountConfig(cookies={}, api_user='1', username='u')

		assert account.has_password_credentials() is False

	def test_password_only_account_loads(self, monkeypatch):
		"""只有 username/password 的账号也应通过校验"""
		accounts_json = json.dumps(
			[{'provider': 'agentrouter', 'api_user': '245573', 'username': 'u', 'password': 'p'}]
		)
		monkeypatch.setenv('ANYROUTER_ACCOUNTS', accounts_json)

		accounts = load_accounts_config()

		assert accounts is not None
		assert accounts[0].has_password_credentials() is True


class TestCheckInDispatch:
	def _account(self, **kw):
		defaults = {
			'cookies': {'session': 'stale'},
			'api_user': '245573',
			'provider': 'agentrouter',
			'name': 'AG2',
			'username': 'linuxdo_245573',
			'password': 'pw',
		}
		defaults.update(kw)
		return AccountConfig(**defaults)

	def _result(self, delta=REWARD_UNITS):
		return {
			'verified': True,
			'already_claimed': False,
			'login_today': True,
			'quota': 13000000,
			'used_quota': 0,
			'quota_delta': delta,
			'message': 'ok',
			'user_id': 245573,
			'display_name': 'x',
		}

	async def test_password_preferred_over_oauth(self, monkeypatch):
		"""agentrouter 默认是 github_oauth，但配了密码就该走密码"""
		called = {}

		def fake_pw(**kw):
			called['pw'] = kw
			return True, self._result(), None

		def fake_oauth(**kw):
			called['oauth'] = kw
			return True, self._result(), None

		monkeypatch.setattr(checkin, 'check_in_via_password', fake_pw)
		monkeypatch.setattr(checkin, 'check_in_via_oauth', fake_oauth)

		success, before, after = await checkin.check_in_account(
			self._account(oauth_cookie='gh'), 0, AppConfig.load_from_env()
		)

		assert success is True
		assert 'pw' in called
		assert 'oauth' not in called
		assert called['pw']['username'] == 'linuxdo_245573'

	async def test_oauth_still_used_without_password(self, monkeypatch):
		called = {}

		def fake_oauth(**kw):
			called['oauth'] = kw
			return True, self._result(), None

		monkeypatch.setattr(checkin, 'check_in_via_oauth', fake_oauth)

		account = self._account(username=None, password=None, oauth_cookie='gh')
		success, before, after = await checkin.check_in_account(account, 0, AppConfig.load_from_env())

		assert success is True
		assert 'oauth' in called

	def test_backup_domain_fallback(self, monkeypatch):
		attempts = []

		def fake_pw(**kw):
			attempts.append(kw['domain'])
			if 'agentrouter.org' in kw['domain']:
				return False, None, 'WAF 拦截'
			return True, self._result(), None

		monkeypatch.setattr(checkin, 'check_in_via_password', fake_pw)
		provider = AppConfig.load_from_env().get_provider('agentrouter')

		success, before, after = checkin.check_in_with_password(self._account(), 'AG2', provider)

		assert attempts == ['https://agentrouter.org', 'https://ps.air-outer.com']
		assert success is True

	def test_missing_baseline_suppresses_fake_reward(self, monkeypatch):
		monkeypatch.setattr(checkin, 'check_in_via_password', lambda **kw: (True, self._result(delta=None), None))
		provider = AppConfig.load_from_env().get_provider('agentrouter')

		success, before, after = checkin.check_in_with_password(self._account(), 'AG2', provider)

		assert success is True
		assert before['success'] is False
		assert after['success'] is True

	def test_all_domains_fail(self, monkeypatch):
		monkeypatch.setattr(checkin, 'check_in_via_password', lambda **kw: (False, None, '密码错误'))
		provider = AppConfig.load_from_env().get_provider('agentrouter')

		success, before, after = checkin.check_in_with_password(self._account(), 'AG2', provider)

		assert success is False
		assert '密码错误' in before['error']
		assert after is None
