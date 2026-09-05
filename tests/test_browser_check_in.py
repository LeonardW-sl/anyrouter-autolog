"""浏览器内签到路径的测试

agentrouter 的 API 在阿里云 WAF 后面，acw_sc__v2 绑浏览器上下文，抠出来给 httpx
重放很脆。这条路径让浏览器自己发请求，测试用假 page 顶掉真浏览器。
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import checkin
from utils.agentrouter_oauth import CHECK_IN_LOG_TYPE, REWARD_UNITS
from utils.config import AccountConfig, AppConfig

WAF_PAGE = '<html><head><meta name="aliyun_waf_aa" content="x"></head><body></body></html>'


class FakeContext:
	def __init__(self):
		self.added_cookies = []

	async def add_cookies(self, cookies):
		self.added_cookies.extend(cookies)


class FakePage:
	"""按 (method, path) 回放预置响应，并记录调用顺序"""

	def __init__(self, responses, url='https://agentrouter.org/login'):
		self.responses = responses
		self.calls = []
		self.url = url
		self.context = FakeContext()

	async def evaluate(self, _js, arg):
		key = (arg['method'], arg['path'])
		self.calls.append({'key': key, 'body': arg['body'], 'apiUser': arg['apiUser']})
		if key not in self.responses:
			raise AssertionError(f'unexpected call: {key}')
		entry = self.responses[key]
		if isinstance(entry, list):
			entry = entry.pop(0)
		if isinstance(entry, Exception):
			raise entry
		return entry


def ok(payload_text: str, status: int = 200):
	return {'status': status, 'text': payload_text}


def user_json(quota: int) -> str:
	return '{"success": true, "data": {"quota": %d, "used_quota": 0, "id": 245573, "username": "u"}}' % quota


class TestParseApiJson:
	def test_network_failure_reports_label(self):
		payload, error = checkin.parse_api_json(0, 'TimeoutError: boom', '登录接口')
		assert payload is None
		assert '登录接口' in error and 'TimeoutError' in error

	def test_waf_challenge_page_is_not_json(self):
		payload, error = checkin.parse_api_json(200, WAF_PAGE, '登录接口')
		assert payload is None
		assert '非 JSON' in error
		# 拦截线索要留在错误里，否则下次还得重跑一遍才知道是被 WAF 顶了
		assert 'aliyun_waf_aa' in error

	def test_squashes_multiline_body(self):
		payload, error = checkin.parse_api_json(502, 'bad\n\ngateway\n', '用户信息')
		assert payload is None
		assert '\n' not in error

	def test_non_dict_json_rejected(self):
		payload, error = checkin.parse_api_json(200, '[1, 2]', '日志')
		assert payload is None
		assert '结构异常' in error

	def test_valid_json(self):
		payload, error = checkin.parse_api_json(200, '{"success": true}', '登录接口')
		assert payload == {'success': True}
		assert error is None


class TestBrowserApiCall:
	async def test_forwards_method_body_and_api_user(self):
		page = FakePage({('POST', '/api/user/login'): ok('{"success": true}')})
		status, text = await checkin.browser_api_call(
			page, '/api/user/login', method='POST', body={'username': 'u'}, api_user='245573'
		)
		assert (status, text) == (200, '{"success": true}')
		assert page.calls[0]['body'] == {'username': 'u'}
		assert page.calls[0]['apiUser'] == '245573'

	async def test_evaluate_exception_becomes_status_zero(self):
		page = FakePage({('GET', '/api/user/self'): RuntimeError('navigation destroyed')})
		status, text = await checkin.browser_api_call(page, '/api/user/self')
		assert status == 0
		assert 'RuntimeError' in text


class TestBrowserLogConfirmsToday:
	def _provider(self):
		return AppConfig.load_from_env().get_provider('agentrouter')

	def _log_path(self):
		return f'/api/log/self?p=1&page_size=20&type={CHECK_IN_LOG_TYPE}'

	async def test_filters_by_type_server_side(self):
		"""不带 type 过滤时第一页会被消费记录占满，签到记录被挤到后面几页"""
		page = FakePage({('GET', self._log_path()): ok('{"success": true, "data": {"items": []}}')})
		await checkin.browser_log_confirms_today(page, self._provider(), '245573')
		assert f'type={CHECK_IN_LOG_TYPE}' in page.calls[0]['key'][1]

	async def test_today_record_confirms(self, monkeypatch):
		monkeypatch.setattr(checkin, 'is_timestamp_today', lambda ts: ts == 1)
		body = '{"success": true, "data": {"items": [{"type": 4, "created_at": 1}]}}'
		page = FakePage({('GET', self._log_path()): ok(body)})
		assert await checkin.browser_log_confirms_today(page, self._provider(), '245573') is True

	async def test_yesterday_record_does_not_confirm(self, monkeypatch):
		monkeypatch.setattr(checkin, 'is_timestamp_today', lambda ts: False)
		body = '{"success": true, "data": {"items": [{"type": 4, "created_at": 1}]}}'
		page = FakePage({('GET', self._log_path()): ok(body)})
		assert await checkin.browser_log_confirms_today(page, self._provider(), '245573') is False

	async def test_challenge_page_does_not_confirm(self):
		page = FakePage({('GET', self._log_path()): ok(WAF_PAGE)})
		assert await checkin.browser_log_confirms_today(page, self._provider(), '245573') is False


class TestRunBrowserCheckIn:
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

	def _provider(self):
		return AppConfig.load_from_env().get_provider('agentrouter')

	def _run(self, page, account=None):
		return checkin.run_browser_check_in(page, account or self._account(), 'AG2', self._provider())

	def _login_key(self, provider):
		return ('POST', f'{provider.login_api_path}?turnstile=')

	async def test_delta_alone_proves_reward(self):
		provider = self._provider()
		page = FakePage(
			{
				('GET', provider.user_info_path): [ok(user_json(1000)), ok(user_json(1000 + REWARD_UNITS))],
				self._login_key(provider): ok('{"success": true, "data": {"id": 245573}}'),
			}
		)
		success, before, _ = await self._run(page)
		assert success is True
		# 增量已经证明到账，不该再去查日志
		assert all('/api/log/self' not in call['key'][1] for call in page.calls)

	async def test_falls_back_to_log_when_delta_invisible(self, monkeypatch):
		"""站方在登录 handler 里异步发放，登录后立刻复读余额常常看不到增量"""
		monkeypatch.setattr(checkin, 'is_timestamp_today', lambda ts: True)
		provider = self._provider()
		page = FakePage(
			{
				('GET', provider.user_info_path): [ok(user_json(1000)), ok(user_json(1000))],
				self._login_key(provider): ok('{"success": true, "data": {"id": 245573}}'),
				('GET', f'/api/log/self?p=1&page_size=20&type={CHECK_IN_LOG_TYPE}'): ok(
					'{"success": true, "data": {"items": [{"type": 4, "created_at": 1}]}}'
				),
			}
		)
		success, _, _ = await self._run(page)
		assert success is True

	async def test_no_evidence_is_failure(self, monkeypatch):
		monkeypatch.setattr(checkin, 'is_timestamp_today', lambda ts: False)
		provider = self._provider()
		page = FakePage(
			{
				('GET', provider.user_info_path): [ok(user_json(1000)), ok(user_json(1000))],
				self._login_key(provider): ok('{"success": true, "data": {"id": 245573}}'),
				('GET', f'/api/log/self?p=1&page_size=20&type={CHECK_IN_LOG_TYPE}'): ok(
					'{"success": true, "data": {"items": []}}'
				),
			}
		)
		success, _, _ = await self._run(page)
		assert success is False

	async def test_login_rejected(self):
		provider = self._provider()
		page = FakePage(
			{
				('GET', provider.user_info_path): ok(user_json(1000)),
				self._login_key(provider): ok('{"success": false, "message": "密码错误"}'),
			}
		)
		success, before, after = await self._run(page)
		assert success is False
		assert '密码错误' in before['error']
		assert after is None

	async def test_challenge_on_login_surfaces_marker(self):
		provider = self._provider()
		page = FakePage(
			{
				('GET', provider.user_info_path): ok(WAF_PAGE),
				self._login_key(provider): ok(WAF_PAGE),
			}
		)
		success, before, _ = await self._run(page)
		assert success is False
		assert 'aliyun_waf_aa' in before['error']

	async def test_missing_baseline_still_verifies_via_log(self, monkeypatch):
		"""基线拿不到也不能影响判定——日志才是硬证据"""
		monkeypatch.setattr(checkin, 'is_timestamp_today', lambda ts: True)
		provider = self._provider()
		page = FakePage(
			{
				('GET', provider.user_info_path): [
					ok('{"success": false}'),
					ok(user_json(1000)),
				],
				self._login_key(provider): ok('{"success": true, "data": {"id": 245573}}'),
				('GET', f'/api/log/self?p=1&page_size=20&type={CHECK_IN_LOG_TYPE}'): ok(
					'{"success": true, "data": {"items": [{"type": 4, "created_at": 1}]}}'
				),
			}
		)
		success, _, _ = await self._run(page)
		assert success is True

	async def test_baseline_uses_injected_session(self):
		"""浏览器是全新 profile，基线得靠注进去的旧 session 才读得到"""
		provider = self._provider()
		page = FakePage(
			{
				('GET', provider.user_info_path): [ok(user_json(1000)), ok(user_json(1000 + REWARD_UNITS))],
				self._login_key(provider): ok('{"success": true, "data": {"id": 245573}}'),
			}
		)
		await self._run(page)
		assert [c['name'] for c in page.context.added_cookies] == ['session']
		assert page.context.added_cookies[0]['value'] == 'stale'

	async def test_no_session_skips_baseline_read(self, monkeypatch):
		"""没有旧 session 就别浪费一次请求，直接走日志核验"""
		monkeypatch.setattr(checkin, 'is_timestamp_today', lambda ts: True)
		provider = self._provider()
		page = FakePage(
			{
				('GET', provider.user_info_path): ok(user_json(1000)),
				self._login_key(provider): ok('{"success": true, "data": {"id": 245573}}'),
				('GET', f'/api/log/self?p=1&page_size=20&type={CHECK_IN_LOG_TYPE}'): ok(
					'{"success": true, "data": {"items": [{"type": 4, "created_at": 1}]}}'
				),
			}
		)
		success, _, _ = await self._run(page, account=self._account(cookies={}))
		assert success is True
		assert page.context.added_cookies == []
		user_info_calls = [c for c in page.calls if c['key'][1] == provider.user_info_path]
		assert len(user_info_calls) == 1


class TestCheckInInBrowserGuard:
	async def test_requires_password(self):
		account = AccountConfig(
			cookies={}, api_user='245573', provider='agentrouter', name='AG1', username=None, password=None
		)
		provider = AppConfig.load_from_env().get_provider('agentrouter')
		success, before, after = await checkin.check_in_in_browser(account, 'AG1', provider)
		assert success is False
		assert 'username/password' in before['error']


class TestFilterAccountsByProvider:
	def _accounts(self):
		return [
			AccountConfig(cookies={}, api_user='1', provider='anyrouter', name='A1'),
			AccountConfig(cookies={}, api_user='2', provider='anyrouter', name='A2'),
			AccountConfig(cookies={}, api_user='3', provider='agentrouter', name='G1'),
		]

	def test_empty_keeps_everything(self):
		accounts = self._accounts()
		assert checkin.filter_accounts_by_provider(accounts, None) == accounts
		assert checkin.filter_accounts_by_provider(accounts, '   ') == accounts

	def test_single_provider(self):
		kept = checkin.filter_accounts_by_provider(self._accounts(), 'agentrouter')
		assert [a.name for a in kept] == ['G1']

	def test_case_and_space_insensitive(self):
		kept = checkin.filter_accounts_by_provider(self._accounts(), ' AgentRouter , anyrouter ')
		assert len(kept) == 3

	def test_unknown_name_yields_empty(self):
		"""名字写错时返回空，让调用方报错退出——静默跑全部会打到不想碰的站点"""
		assert checkin.filter_accounts_by_provider(self._accounts(), 'typo') == []


if __name__ == '__main__':
	pytest.main([__file__, '-v'])
