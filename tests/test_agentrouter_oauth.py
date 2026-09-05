#!/usr/bin/env python3
"""AgentRouter GitHub OAuth 重放签到测试"""

import sys
import time
from pathlib import Path

import httpx

# 添加项目根目录到 PATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest

from utils.agentrouter_oauth import (
	GITHUB,
	LINUXDO,
	REWARD_UNITS,
	build_check_in_result,
	describe_non_json,
	exchange_oauth_callback,
	fetch_oauth_state,
	format_upstream_cookie,
	get_oauth_code,
	get_oauth_provider,
	has_check_in_log_today,
	is_timestamp_today,
	quota_to_usd,
	reward_visible_in_delta,
)

DOMAIN = 'https://agentrouter.org'


def make_client(handler) -> httpx.Client:
	return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


class TestHelpers:
	def test_quota_to_usd(self):
		assert quota_to_usd(500000) == 1.0
		assert quota_to_usd(REWARD_UNITS) == 25.0
		assert quota_to_usd(0) == 0.0
		assert quota_to_usd(None) == 0.0

	def test_format_github_cookie_bare_token(self):
		"""裸 user_session 值要补全成完整 Cookie 头"""
		result = format_upstream_cookie('abc123')
		assert 'user_session=abc123' in result
		assert 'logged_in=yes' in result

	def test_format_github_cookie_full_string(self):
		assert format_upstream_cookie('user_session=xyz; logged_in=yes') == 'user_session=xyz; logged_in=yes'

	def test_format_github_cookie_strips_control_chars(self):
		"""DevTools 复制可能带换行"""
		assert '\n' not in format_upstream_cookie('user_session=a\nb; logged_in=yes')

	def test_format_github_cookie_empty(self):
		assert format_upstream_cookie('') == ''
		assert format_upstream_cookie(None) == ''

	def test_is_timestamp_today(self):
		now = int(time.time())
		assert is_timestamp_today(now) is True
		assert is_timestamp_today(now * 1000) is True
		assert is_timestamp_today(str(now)) is True
		assert is_timestamp_today(now - 3 * 86400) is False
		assert is_timestamp_today(None) is False
		assert is_timestamp_today(0) is False
		assert is_timestamp_today('not-a-number') is False


class TestProviderSelection:
	def test_github_default(self):
		assert get_oauth_provider(None) is GITHUB
		assert get_oauth_provider('github') is GITHUB

	def test_linuxdo_aliases(self):
		for name in ('linuxdo', 'LinuxDO', 'linux_do', 'linux-do'):
			assert get_oauth_provider(name) is LINUXDO

	def test_unsupported_provider(self):
		with pytest.raises(ValueError, match='Unsupported OAuth provider'):
			get_oauth_provider('wechat')

	def test_provider_metadata(self):
		"""回调路径必须与 NewAPI 的 /api/oauth/{name} 对齐"""
		assert GITHUB.name == 'github'
		assert GITHUB.cookie_name == 'user_session'
		assert LINUXDO.name == 'linuxdo'
		assert LINUXDO.cookie_name == '_t'
		assert 'connect.linux.do' in LINUXDO.authorize_url
		# LinuxDO 走 response_type=code，没有 scope
		assert LINUXDO.scope is None


class TestLinuxDoFlow:
	def test_authorize_uses_response_type(self):
		captured = {}

		def handler(request: httpx.Request) -> httpx.Response:
			captured.update(request.url.params)
			assert 'connect.linux.do' in str(request.url)
			assert request.headers['Cookie'].startswith('_t=')
			return httpx.Response(302, headers={'location': f'{DOMAIN}/oauth/linuxdo?code=ld-code&state=st'})

		with make_client(handler) as client:
			code, state, error = get_oauth_code(client, 'st', 'discourse-token', LINUXDO)

		assert code == 'ld-code'
		assert error is None
		assert captured['response_type'] == 'code'
		assert captured['client_id'] == LINUXDO.client_id
		assert 'scope' not in captured

	def test_bare_token_gets_discourse_cookie_name(self):
		"""LinuxDO 裸值补成 _t=，且不加 GitHub 的 logged_in"""
		result = format_upstream_cookie('abc123', LINUXDO)

		assert result == '_t=abc123'
		assert 'logged_in' not in result

	def test_callback_hits_linuxdo_path(self):
		def handler(request: httpx.Request) -> httpx.Response:
			assert request.url.path == '/api/oauth/linuxdo'
			return httpx.Response(200, json={'success': True, 'data': {'user': {'id': 245573}}})

		with make_client(handler) as client:
			user, error = exchange_oauth_callback(client, DOMAIN, 'c', 's', LINUXDO)

		assert user['id'] == 245573
		assert error is None

	def test_cloudflare_challenge_is_reported_clearly(self):
		"""数据中心 IP 会吃 CF 挑战，错误要说人话"""
		handler = lambda r: httpx.Response(403, headers={'cf-mitigated': 'challenge'}, text='Just a moment')  # noqa: E731
		with make_client(handler) as client:
			code, state, error = get_oauth_code(client, 'st', 'tok', LINUXDO)

		assert code is None
		assert 'Cloudflare' in error

	def test_discourse_login_page_means_stale_cookie(self):
		html = '<div id="login-account-name"></div>'
		with make_client(lambda r: httpx.Response(200, text=html)) as client:
			code, state, error = get_oauth_code(client, 'st', 'stale', LINUXDO)

		assert code is None
		assert '_t' in error


class TestFetchOAuthState:
	def test_returns_state_token(self):
		def handler(request: httpx.Request) -> httpx.Response:
			assert request.url.path == '/api/oauth/state'
			return httpx.Response(200, json={'success': True, 'data': 'state-token-abc', 'message': ''})

		with make_client(handler) as client:
			state, error = fetch_oauth_state(client, DOMAIN)

		assert state == 'state-token-abc'
		assert error is None

	def test_http_error(self):
		with make_client(lambda r: httpx.Response(503, text='unavailable')) as client:
			state, error = fetch_oauth_state(client, DOMAIN)

		assert state is None
		assert 'HTTP 503' in error

	def test_non_json_response(self):
		"""WAF 拦截时常返回 HTML"""
		with make_client(lambda r: httpx.Response(200, text='<html>blocked</html>')) as client:
			state, error = fetch_oauth_state(client, DOMAIN)

		assert state is None
		assert '非 JSON' in error

	def test_success_false(self):
		handler = lambda r: httpx.Response(200, json={'success': False, 'message': 'rate limited'})  # noqa: E731
		with make_client(handler) as client:
			state, error = fetch_oauth_state(client, DOMAIN)

		assert state is None
		assert 'rate limited' in error

	def test_connection_failure(self):
		def handler(request: httpx.Request) -> httpx.Response:
			raise httpx.ConnectError('dns failure')

		with make_client(handler) as client:
			state, error = fetch_oauth_state(client, DOMAIN)

		assert state is None
		assert 'ConnectError' in error


class TestGithubOAuthCode:
	def test_already_authorized_302(self):
		"""老账号：直接 302 带回 code"""

		def handler(request: httpx.Request) -> httpx.Response:
			assert request.url.params['client_id'] == GITHUB.client_id
			assert request.headers['Cookie'].startswith('user_session=')
			location = f'{DOMAIN}/oauth/github?code=the-code&state=st-1'
			return httpx.Response(302, headers={'location': location})

		with make_client(handler) as client:
			code, state, error = get_oauth_code(client, 'st-1', 'ghs-token')

		assert code == 'the-code'
		assert state == 'st-1'
		assert error is None

	def test_expired_cookie_redirects_to_login(self):
		location = 'https://github.com/login?client_id=Ov23lidtiR4LeVZvVRNL'
		with make_client(lambda r: httpx.Response(302, headers={'location': location})) as client:
			code, state, error = get_oauth_code(client, 'st-1', 'stale')

		assert code is None
		assert '失效' in error

	def test_consent_page_then_code(self):
		"""首次授权：200 consent 页 -> POST -> 302 拿 code"""
		calls = []

		def handler(request: httpx.Request) -> httpx.Response:
			calls.append(request.method)
			if request.method == 'GET':
				html = '<form><input name="authenticity_token" value="tok-42" /></form>'
				return httpx.Response(200, text=html)
			body = request.content.decode()
			assert 'authorize=1' in body
			assert 'authenticity_token=tok-42' in body
			return httpx.Response(302, headers={'location': f'{DOMAIN}/oauth/github?code=c2&state=st-2'})

		with make_client(handler) as client:
			code, state, error = get_oauth_code(client, 'st-2', 'ghs-token')

		assert calls == ['GET', 'POST']
		assert code == 'c2'
		assert error is None

	def test_consent_page_without_token(self):
		with make_client(lambda r: httpx.Response(200, text='<html>no token here</html>')) as client:
			code, state, error = get_oauth_code(client, 'st', 'ghs')

		assert code is None
		assert 'authenticity_token' in error

	def test_login_page_body_means_invalid_cookie(self):
		html = '<form action="/session"><input id="login_field" /></form>'
		with make_client(lambda r: httpx.Response(200, text=html)) as client:
			code, state, error = get_oauth_code(client, 'st', 'bad')

		assert code is None
		assert '无效' in error

	def test_empty_cookie(self):
		with make_client(lambda r: httpx.Response(200)) as client:
			code, state, error = get_oauth_code(client, 'st', '')

		assert code is None
		assert '为空' in error

	def test_302_without_code(self):
		with make_client(lambda r: httpx.Response(302, headers={'location': f'{DOMAIN}/error'})) as client:
			code, state, error = get_oauth_code(client, 'st', 'ghs')

		assert code is None
		assert '未带 code' in error


class TestExchangeCallback:
	def test_returns_nested_user(self):
		def handler(request: httpx.Request) -> httpx.Response:
			assert request.url.path == '/api/oauth/github'
			assert request.url.params['code'] == 'c1'
			assert request.url.params['state'] == 's1'
			payload = {'success': True, 'data': {'user': {'id': 223050, 'quota': 1000, 'checked_in': True}}}
			return httpx.Response(200, json=payload)

		with make_client(handler) as client:
			user, error = exchange_oauth_callback(client, DOMAIN, 'c1', 's1')

		assert user['id'] == 223050
		assert error is None

	def test_returns_flat_user(self):
		"""有的版本 data 直接就是 user"""
		payload = {'success': True, 'data': {'id': 1, 'quota': 5}}
		with make_client(lambda r: httpx.Response(200, json=payload)) as client:
			user, error = exchange_oauth_callback(client, DOMAIN, 'c', 's')

		assert user['id'] == 1

	def test_rejected_callback(self):
		payload = {'success': False, 'message': 'state is empty or not same'}
		with make_client(lambda r: httpx.Response(403, json=payload)) as client:
			user, error = exchange_oauth_callback(client, DOMAIN, 'c', 's')

		assert user is None
		assert 'state is empty' in error

	def test_non_json(self):
		with make_client(lambda r: httpx.Response(405, text='blocked by waf')) as client:
			user, error = exchange_oauth_callback(client, DOMAIN, 'c', 's')

		assert user is None
		assert '非 JSON' in error


class TestCheckInLog:
	def test_finds_today_check_in(self):
		now = int(time.time())
		payload = {'success': True, 'data': {'items': [{'type': 4, 'created_at': now}]}}
		with make_client(lambda r: httpx.Response(200, json=payload)) as client:
			assert has_check_in_log_today(client, DOMAIN, '223050') is True

	def test_ignores_other_log_types(self):
		now = int(time.time())
		payload = {'success': True, 'data': {'items': [{'type': 2, 'created_at': now}]}}
		with make_client(lambda r: httpx.Response(200, json=payload)) as client:
			assert has_check_in_log_today(client, DOMAIN, '223050') is False

	def test_ignores_older_check_in(self):
		old = int(time.time()) - 3 * 86400
		payload = {'success': True, 'data': {'items': [{'type': 4, 'created_at': old}]}}
		with make_client(lambda r: httpx.Response(200, json=payload)) as client:
			assert has_check_in_log_today(client, DOMAIN, '223050') is False

	def test_handles_bare_list(self):
		now = int(time.time())
		payload = {'success': True, 'data': [{'type': 4, 'created_at': now}]}
		with make_client(lambda r: httpx.Response(200, json=payload)) as client:
			assert has_check_in_log_today(client, DOMAIN, None) is True

	def test_http_error_is_not_evidence(self):
		with make_client(lambda r: httpx.Response(403, text='denied')) as client:
			assert has_check_in_log_today(client, DOMAIN, '1') is False

	def test_filters_by_type_server_side(self):
		"""高频账号第一页会被消费记录占满，必须让服务端按 type=4 过滤"""
		captured = {}

		def handler(request: httpx.Request) -> httpx.Response:
			captured['type'] = request.url.params.get('type')
			now = int(time.time())
			return httpx.Response(200, json={'success': True, 'data': {'items': [{'type': 4, 'created_at': now}]}})

		with make_client(handler) as client:
			assert has_check_in_log_today(client, DOMAIN, '245573') is True

		assert captured['type'] == '4'


class TestBuildCheckInResult:
	"""签到判定必须靠硬证据，不能像上游那样假成功"""

	def test_verified_by_quota_delta(self):
		now = int(time.time())
		user = {'id': 1, 'quota': 13000000, 'used_quota': 100, 'last_login_time': now}
		result = build_check_in_result(user, quota_before=500000, quota_before_fresh=True, log_confirms_today=False)

		assert result['verified'] is True
		assert result['quota_delta'] == 12500000
		assert '25.0' in result['message']

	def test_delta_below_reward_is_not_verified(self):
		now = int(time.time())
		user = {'id': 1, 'quota': 600000, 'last_login_time': now}
		result = build_check_in_result(user, quota_before=500000, quota_before_fresh=True, log_confirms_today=False)

		assert result['verified'] is False
		assert result['already_claimed'] is True

	def test_stale_baseline_cannot_verify(self):
		"""基线不新鲜时增量不可信，不得据此宣布成功"""
		now = int(time.time())
		user = {'id': 1, 'quota': 13000000, 'last_login_time': now}
		result = build_check_in_result(user, quota_before=500000, quota_before_fresh=False, log_confirms_today=False)

		assert result['verified'] is False

	def test_verified_by_log_when_baseline_missing(self):
		now = int(time.time())
		user = {'id': 1, 'quota': 13000000, 'last_login_time': now}
		result = build_check_in_result(user, quota_before=None, quota_before_fresh=False, log_confirms_today=True)

		assert result['verified'] is True
		assert '日志' in result['message']

	def test_already_claimed_today(self):
		now = int(time.time())
		user = {'id': 1, 'quota': 500000, 'last_login_time': now}
		result = build_check_in_result(user, quota_before=500000, quota_before_fresh=True, log_confirms_today=False)

		assert result['verified'] is False
		assert result['already_claimed'] is True
		assert '已签到' in result['message']

	def test_login_not_today_is_failure(self):
		old = int(time.time()) - 3 * 86400
		user = {'id': 1, 'quota': 500000, 'last_login_time': old}
		result = build_check_in_result(user, quota_before=500000, quota_before_fresh=True, log_confirms_today=False)

		assert result['verified'] is False
		assert result['already_claimed'] is False
		assert result['login_today'] is False

	def test_no_evidence_at_all_is_not_success(self):
		"""拿不到任何证据时既不 verified 也不 already_claimed"""
		result = build_check_in_result({'id': 1}, quota_before=None, quota_before_fresh=False, log_confirms_today=False)

		assert result['verified'] is False
		assert result['already_claimed'] is False

	def test_passes_through_identity_fields(self):
		user = {'id': 223050, 'display_name': 'Suli Wang', 'quota': 100, 'used_quota': 7}
		result = build_check_in_result(user, None, False, False)

		assert result['user_id'] == 223050
		assert result['display_name'] == 'Suli Wang'
		assert result['used_quota'] == 7


class TestDescribeNonJson:
	"""机房 IP 被 WAF 顶回来时，报错要能认出拦截方"""

	def test_includes_status_and_single_line_body(self):
		response = httpx.Response(200, text='<!doctype html>\n<html>\n  <body>blocked</body>\n</html>')
		desc = describe_non_json(response)

		assert 'HTTP 200' in desc
		assert '\n' not in desc
		assert '<!doctype html> <html> <body>blocked' in desc

	def test_surfaces_cloudflare_markers(self):
		response = httpx.Response(
			403,
			headers={'server': 'cloudflare', 'cf-mitigated': 'challenge', 'cf-ray': 'abc123'},
			text='Just a moment...',
		)
		desc = describe_non_json(response)

		assert 'server=cloudflare' in desc
		assert 'cf-mitigated=challenge' in desc

	def test_surfaces_waf_cookie_names(self):
		response = httpx.Response(
			200,
			headers=[('set-cookie', 'acw_sc__v2=xyz; Path=/'), ('set-cookie', 'acw_tc=abc; Path=/')],
			text='<html><script>var arg1=...</script></html>',
		)
		desc = describe_non_json(response)

		assert 'acw_sc__v2' in desc
		assert 'acw_tc' in desc


class TestRewardVisibleInDelta:
	"""决定「能不能省掉日志核验」的闸门"""

	def test_true_when_delta_covers_reward(self):
		assert reward_visible_in_delta({'quota': 500000 + REWARD_UNITS}, 500000, True) is True

	def test_false_when_baseline_stale(self):
		assert reward_visible_in_delta({'quota': 500000 + REWARD_UNITS}, 500000, False) is False

	def test_false_when_no_baseline(self):
		assert reward_visible_in_delta({'quota': REWARD_UNITS}, None, True) is False

	def test_false_when_delta_flat(self):
		"""站方异步入账/额度当场被花掉时增量为 0，必须回落到日志核验"""
		assert reward_visible_in_delta({'quota': 247955000}, 247955000, True) is False

	def test_false_when_login_response_zeroes_quota(self):
		"""登录响应返回的精简 user 对象 quota 恒为 0，不能当成余额"""
		assert reward_visible_in_delta({'quota': 0}, 247955000, True) is False
