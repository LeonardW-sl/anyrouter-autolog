#!/usr/bin/env python3
"""Provider 签到方式与账号凭据解析测试"""

import json
import sys
from pathlib import Path

# 添加项目根目录到 PATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.config import AccountConfig, AppConfig, ProviderConfig, load_accounts_config, resolve_secret


class TestAgentRouterDefaults:
	"""agentrouter 内置配置必须与实测事实一致"""

	def test_uses_github_oauth(self):
		provider = AppConfig.load_from_env().get_provider('agentrouter')

		assert provider.check_in_method == 'github_oauth'
		assert provider.uses_github_oauth() is True
		# 没有签到接口，绝不能走 sign_in_api 分支
		assert provider.needs_manual_check_in() is False
		assert provider.sign_in_path is None

	def test_no_playwright_needed(self):
		"""acw_tc 直接 curl 就能拿到，不该起浏览器"""
		provider = AppConfig.load_from_env().get_provider('agentrouter')

		assert provider.needs_waf_cookies() is False
		assert provider.bypass_method is None

	def test_backup_domain_available(self):
		provider = AppConfig.load_from_env().get_provider('agentrouter')
		domains = provider.candidate_domains()

		assert domains[0] == 'https://agentrouter.org'
		assert 'https://ps.air-outer.com' in domains

	def test_anyrouter_unchanged(self):
		"""anyrouter 仍走签到接口 + WAF cookies"""
		provider = AppConfig.load_from_env().get_provider('anyrouter')

		assert provider.needs_manual_check_in() is True
		assert provider.uses_github_oauth() is False
		assert provider.needs_waf_cookies() is True
		assert provider.candidate_domains() == ['https://anyrouter.top']


class TestProviderFromDict:
	def test_custom_oauth_provider(self):
		provider = ProviderConfig.from_dict(
			'custom',
			{
				'domain': 'https://example.com',
				'check_in_method': 'github_oauth',
				'backup_domain': 'https://backup.example.com',
			},
		)

		assert provider.uses_github_oauth() is True
		assert provider.candidate_domains() == ['https://example.com', 'https://backup.example.com']

	def test_defaults_to_sign_in_api(self):
		provider = ProviderConfig.from_dict('custom', {'domain': 'https://example.com'})

		assert provider.check_in_method == 'sign_in_api'
		assert provider.needs_manual_check_in() is True

	def test_sign_in_path_null_no_longer_means_auto(self):
		"""sign_in_path=None 且非 OAuth：无签到手段，不该被当成自动签到"""
		provider = ProviderConfig.from_dict('custom', {'domain': 'https://example.com', 'sign_in_path': None})

		assert provider.needs_manual_check_in() is False
		assert provider.uses_github_oauth() is False


class TestResolveSecret:
	def test_env_indirection(self, monkeypatch):
		monkeypatch.setenv('GH_SESSION_TEST', 'secret-value')

		assert resolve_secret('env:GH_SESSION_TEST') == 'secret-value'

	def test_missing_env_returns_none(self, monkeypatch):
		monkeypatch.delenv('GH_SESSION_ABSENT', raising=False)

		assert resolve_secret('env:GH_SESSION_ABSENT') is None

	def test_literal_value_passthrough(self):
		assert resolve_secret('  raw-token  ') == 'raw-token'

	def test_empty(self):
		assert resolve_secret('') is None
		assert resolve_secret(None) is None


class TestAccountConfig:
	def test_session_cookie_from_dict(self):
		account = AccountConfig(cookies={'session': 'abc'}, api_user='1')

		assert account.get_session_cookie() == 'abc'

	def test_session_cookie_from_string(self):
		account = AccountConfig(cookies='acw_tc=x; session=abc; other=y', api_user='1')

		assert account.get_session_cookie() == 'abc'

	def test_session_cookie_absent(self):
		assert AccountConfig(cookies={}, api_user='1').get_session_cookie() is None

	def test_github_cookie_resolved_from_env(self, monkeypatch):
		monkeypatch.setenv('GH_SESSION_1', 'gh-value')
		account = AccountConfig.from_dict(
			{'api_user': '223050', 'provider': 'agentrouter', 'oauth_cookie': 'env:GH_SESSION_1'}, 0
		)

		assert account.oauth_cookie == 'gh-value'
		assert account.cookies == {}


class TestLoadAccountsConfig:
	def test_oauth_account_without_cookies(self, monkeypatch):
		"""OAuth 账号不带站内 cookies 也应被接受"""
		monkeypatch.setenv('GH_SESSION_1', 'gh-value')
		accounts_json = json.dumps(
			[{'name': 'AG1', 'provider': 'agentrouter', 'api_user': '223050', 'oauth_cookie': 'env:GH_SESSION_1'}]
		)
		monkeypatch.setenv('ANYROUTER_ACCOUNTS', accounts_json)

		accounts = load_accounts_config()

		assert len(accounts) == 1
		assert accounts[0].oauth_cookie == 'gh-value'

	def test_rejects_account_without_any_credential(self, monkeypatch):
		monkeypatch.setenv('ANYROUTER_ACCOUNTS', json.dumps([{'api_user': '1'}]))

		assert load_accounts_config() is None

	def test_rejects_account_without_api_user(self, monkeypatch):
		monkeypatch.setenv('ANYROUTER_ACCOUNTS', json.dumps([{'cookies': {'session': 'a'}}]))

		assert load_accounts_config() is None

	def test_legacy_cookie_account_still_loads(self, monkeypatch):
		accounts_json = json.dumps([{'provider': 'anyrouter', 'cookies': {'session': 'a'}, 'api_user': '9'}])
		monkeypatch.setenv('ANYROUTER_ACCOUNTS', accounts_json)

		accounts = load_accounts_config()

		assert len(accounts) == 1
		assert accounts[0].oauth_cookie is None
