#!/usr/bin/env python3
"""每个 provider 推给各自的飞书机器人"""

import sys
from pathlib import Path
from unittest.mock import patch

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest

from utils.notify import NotificationKit

ANY_HOOK = 'https://open.feishu.cn/open-apis/bot/v2/hook/any'
AGENT_HOOK = 'https://open.feishu.cn/open-apis/bot/v2/hook/agent'
SHARED_HOOK = 'https://open.feishu.cn/open-apis/bot/v2/hook/shared'


@pytest.fixture
def kit(monkeypatch):
	for name in ('FEISHU_WEBHOOK', 'FEISHU_WEBHOOK_ANYROUTER', 'FEISHU_WEBHOOK_AGENTROUTER'):
		monkeypatch.delenv(name, raising=False)
	return NotificationKit()


class TestWebhookSelection:
	def test_dedicated_webhook_wins(self, kit, monkeypatch):
		monkeypatch.setenv('FEISHU_WEBHOOK', SHARED_HOOK)
		monkeypatch.setenv('FEISHU_WEBHOOK_AGENTROUTER', AGENT_HOOK)

		assert kit.feishu_webhook_for('agentrouter') == AGENT_HOOK

	def test_falls_back_to_shared(self, kit, monkeypatch):
		monkeypatch.setenv('FEISHU_WEBHOOK', SHARED_HOOK)

		assert kit.feishu_webhook_for('agentrouter') == SHARED_HOOK
		assert kit.feishu_webhook_for('anyrouter') == SHARED_HOOK

	def test_two_providers_route_apart(self, kit, monkeypatch):
		monkeypatch.setenv('FEISHU_WEBHOOK_ANYROUTER', ANY_HOOK)
		monkeypatch.setenv('FEISHU_WEBHOOK_AGENTROUTER', AGENT_HOOK)

		assert kit.feishu_webhook_for('anyrouter') == ANY_HOOK
		assert kit.feishu_webhook_for('agentrouter') == AGENT_HOOK

	def test_provider_name_is_case_insensitive(self, kit, monkeypatch):
		monkeypatch.setenv('FEISHU_WEBHOOK_AGENTROUTER', AGENT_HOOK)

		assert kit.feishu_webhook_for('AgentRouter') == AGENT_HOOK

	def test_no_provider_uses_shared(self, kit, monkeypatch):
		monkeypatch.setenv('FEISHU_WEBHOOK', SHARED_HOOK)

		assert kit.feishu_webhook_for(None) == SHARED_HOOK

	def test_nothing_configured_returns_none(self, kit):
		assert kit.feishu_webhook_for('agentrouter') is None

	def test_reads_env_at_send_time(self, kit, monkeypatch):
		"""checkin.py 的 load_dotenv() 在 import 之后才跑，不能用构造期快照"""
		assert kit.feishu_webhook is None

		monkeypatch.setenv('FEISHU_WEBHOOK', SHARED_HOOK)

		assert kit.feishu_webhook_for('anyrouter') == SHARED_HOOK

	def test_blank_dedicated_falls_back(self, kit, monkeypatch):
		monkeypatch.setenv('FEISHU_WEBHOOK', SHARED_HOOK)
		monkeypatch.setenv('FEISHU_WEBHOOK_AGENTROUTER', '   ')

		assert kit.feishu_webhook_for('agentrouter') == SHARED_HOOK


class TestSendFeishu:
	def test_posts_to_provider_webhook(self, kit, monkeypatch):
		monkeypatch.setenv('FEISHU_WEBHOOK_AGENTROUTER', AGENT_HOOK)

		with patch('httpx.Client') as client_cls:
			post = client_cls.return_value.__enter__.return_value.post
			kit.send_feishu('AgentRouter Check-in Alert', 'balance $493.00', provider='agentrouter')

		assert post.call_args.args[0] == AGENT_HOOK
		card = post.call_args.kwargs['json']['card']
		assert card['header']['title']['content'] == 'AgentRouter Check-in Alert'
		assert card['elements'][0]['content'] == 'balance $493.00'

	def test_raises_when_unconfigured(self, kit):
		with pytest.raises(ValueError, match='not configured'):
			kit.send_feishu('t', 'c', provider='agentrouter')

	def test_push_message_forwards_provider(self, kit, monkeypatch):
		monkeypatch.setenv('FEISHU_WEBHOOK_ANYROUTER', ANY_HOOK)

		with patch.object(kit, 'send_feishu') as send:
			kit.push_message('AnyRouter Check-in Alert', 'body', provider='anyrouter')

		send.assert_called_once_with('AnyRouter Check-in Alert', 'body', 'anyrouter')
