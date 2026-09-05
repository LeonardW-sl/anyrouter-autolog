#!/usr/bin/env python3
"""checkin.py 中 OAuth 分支的接线测试"""

import sys
from pathlib import Path

# 添加项目根目录到 PATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import checkin
from utils.agentrouter_oauth import REWARD_UNITS
from utils.config import AccountConfig, AppConfig


def agentrouter_account(**overrides) -> AccountConfig:
	defaults = {
		'cookies': {'session': 'stale-session'},
		'api_user': '223050',
		'provider': 'agentrouter',
		'name': 'AG1',
		'oauth_cookie': 'gh-token',
		'oauth_provider': 'github',
	}
	defaults.update(overrides)
	return AccountConfig(**defaults)


def provider():
	return AppConfig.load_from_env().get_provider('agentrouter')


class TestOAuthBranchWiring:
	def test_verified_check_in_reports_success(self, monkeypatch):
		captured = {}

		def fake_oauth(account_name, domain, upstream_cookie, api_user, session_cookie, provider):
			captured.update(domain=domain, upstream_cookie=upstream_cookie, api_user=api_user, session=session_cookie)
			result = {
				'verified': True,
				'already_claimed': False,
				'login_today': True,
				'quota': 13000000,
				'used_quota': 500000,
				'quota_delta': REWARD_UNITS,
				'message': '签到到账 +$25.0（额度增量已核实）',
				'user_id': 223050,
				'display_name': 'Suli Wang',
			}
			return True, result, None

		monkeypatch.setattr(checkin, 'check_in_via_oauth', fake_oauth)

		success, before, after = checkin.check_in_with_github_oauth(agentrouter_account(), 'AG1', provider())

		assert success is True
		assert captured['domain'] == 'https://agentrouter.org'
		assert captured['upstream_cookie'] == 'gh-token'
		assert captured['session'] == 'stale-session'
		# 主流程用 before/after 算收益，两者都要可用
		assert before['success'] is True
		assert after['success'] is True
		assert after['quota'] == 26.0
		assert round(after['quota'] + after['used_quota'] - before['quota'] - before['used_quota'], 2) == 25.0

	def test_missing_baseline_suppresses_fake_reward(self, monkeypatch):
		"""基线缺失时 before 必须标记失败，避免主流程算出假的签到收益"""
		result = {
			'verified': True,
			'already_claimed': False,
			'login_today': True,
			'quota': 13000000,
			'used_quota': 0,
			'quota_delta': None,
			'message': '签到成功（站内日志已有今日签到记录）',
			'user_id': 1,
			'display_name': 'x',
		}
		monkeypatch.setattr(checkin, 'check_in_via_oauth', lambda **kw: (True, result, None))

		success, before, after = checkin.check_in_with_github_oauth(agentrouter_account(), 'AG1', provider())

		assert success is True
		assert before['success'] is False
		assert after['success'] is True

	def test_falls_back_to_backup_domain(self, monkeypatch):
		attempts = []

		def fake_oauth(account_name, domain, upstream_cookie, api_user, session_cookie, provider):
			attempts.append(domain)
			if 'agentrouter.org' in domain:
				return False, None, 'WAF 拦截'
			result = {
				'verified': True,
				'already_claimed': False,
				'login_today': True,
				'quota': 13000000,
				'used_quota': 0,
				'quota_delta': REWARD_UNITS,
				'message': 'ok',
				'user_id': 1,
				'display_name': 'x',
			}
			return True, result, None

		monkeypatch.setattr(checkin, 'check_in_via_oauth', fake_oauth)

		success, before, after = checkin.check_in_with_github_oauth(agentrouter_account(), 'AG1', provider())

		assert attempts == ['https://agentrouter.org', 'https://ps.air-outer.com']
		assert success is True

	def test_all_domains_fail(self, monkeypatch):
		monkeypatch.setattr(checkin, 'check_in_via_oauth', lambda **kw: (False, None, 'cookie 失效'))

		success, before, after = checkin.check_in_with_github_oauth(agentrouter_account(), 'AG1', provider())

		assert success is False
		assert before['success'] is False
		assert 'cookie 失效' in before['error']
		assert after is None

	def test_unverified_result_is_not_success(self, monkeypatch):
		"""链路走通但无证据时不得报成功"""
		result = {
			'verified': False,
			'already_claimed': False,
			'login_today': False,
			'quota': 500000,
			'used_quota': 0,
			'quota_delta': 0,
			'message': '登录后 last_login_time 不是今天，签到可能未生效',
			'user_id': 1,
			'display_name': 'x',
		}
		monkeypatch.setattr(checkin, 'check_in_via_oauth', lambda **kw: (False, result, '未生效'))

		success, before, after = checkin.check_in_with_github_oauth(agentrouter_account(), 'AG1', provider())

		assert success is False
		# 有结果就仍然回报余额，方便通知里看到当前状态
		assert after['success'] is True


class TestAccountLevelGuards:
	async def test_missing_github_cookie_fails_fast(self):
		account = agentrouter_account(oauth_cookie=None)

		success, before, after = await checkin.check_in_account(account, 0, AppConfig.load_from_env())

		assert success is False
		assert 'oauth_cookie' in before['error']

	async def test_unknown_provider_returns_triple(self):
		"""provider 缺失时也必须返回三元组，否则主流程解包会崩"""
		account = agentrouter_account(provider='nonexistent')

		result = await checkin.check_in_account(account, 0, AppConfig.load_from_env())

		assert len(result) == 3
		assert result[0] is False
