#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.agentrouter_oauth import (
	check_in_via_oauth,
	check_in_via_password,
	get_oauth_provider,
	quota_to_usd,
)
from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in required_cookies and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
					await context.close()
					return None

				print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')

				await context.close()

				return waf_cookies

			except Exception as e:
				print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
				await context.close()
				return None


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
				}
		return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				error_msg = result.get('msg', result.get('message', 'Unknown error'))
				# 检查是否是"已经签到过"的情况，这种情况也算成功
				already_checked_keywords = ['已经签到', '已签到', '重复签到', 'already checked', 'already signed']
				if any(keyword in error_msg.lower() for keyword in already_checked_keywords):
					print(f'[SUCCESS] {account_name}: Already checked in today')
					return True
				print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
				return False
		except json.JSONDecodeError:
			# 如果不是 JSON 响应，检查是否包含成功标识
			if 'success' in response.text.lower():
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
				return False
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False


PROVIDER_TITLES = {'anyrouter': 'AnyRouter', 'agentrouter': 'AgentRouter'}


def provider_title(name: str) -> str:
	"""通知标题里用的 provider 显示名"""
	return PROVIDER_TITLES.get(name, name)


def build_summary(success_count: int, total_count: int) -> list[str]:
	"""签到结果统计段"""
	summary = [
		'[STATS] Check-in result statistics:',
		f'[SUCCESS] Success: {success_count}/{total_count}',
		f'[FAIL] Failed: {total_count - success_count}/{total_count}',
	]

	if success_count == total_count:
		summary.append('[SUCCESS] All accounts check-in successful!')
	elif success_count > 0:
		summary.append('[WARN] Some accounts check-in successful')
	else:
		summary.append('[ERROR] All accounts check-in failed')

	return summary


def format_check_in_notification(detail: dict) -> str:
	"""格式化签到通知消息

	Args:
		detail: 包含签到详情的字典

	Returns:
		格式化后的通知消息
	"""
	lines = [
		f'[CHECK-IN] {detail["name"]}',
		'  ━━━━━━━━━━━━━━━━━━━━',
		'  📍 签到前',
		f'     💵 余额: ${detail["before_quota"]:.2f}  |  📊 累计消耗: ${detail["before_used"]:.2f}',
		'  📍 签到后',
		f'     💵 余额: ${detail["after_quota"]:.2f}  |  📊 累计消耗: ${detail["after_used"]:.2f}',
	]

	# 判断是否有变化
	has_reward = detail['check_in_reward'] != 0
	has_usage = detail['usage_increase'] != 0

	if has_reward or has_usage:
		lines.append('  ━━━━━━━━━━━━━━━━━━━━')

		# 已签到但期间有使用
		if not has_reward and has_usage:
			lines.append('  ℹ️  今日已签到（期间有使用）')

		# 签到获得
		if has_reward:
			lines.append(f'  🎁 签到获得: +${detail["check_in_reward"]:.2f}')

		# 期间消耗
		if has_usage:
			lines.append(f'  📉 期间消耗: ${detail["usage_increase"]:.2f}')

		# 余额变化
		if detail['balance_change'] != 0:
			change_symbol = '+' if detail['balance_change'] > 0 else ''
			change_emoji = '📈' if detail['balance_change'] > 0 else '📉'
			lines.append(f'  {change_emoji} 余额变化: {change_symbol}${detail["balance_change"]:.2f}')
	else:
		# 无任何变化
		lines.extend(['  ━━━━━━━━━━━━━━━━━━━━', '  ℹ️  今日已签到，无变化'])

	return '\n'.join(lines)


def shape_check_in_result(result: dict, success: bool, account_name: str):
	"""把签到结果转成主流程期望的 (before, after) 结构

	基线不可信时把 before 标记为失败，避免主流程算出假的签到收益。
	"""
	print(f'[{"SUCCESS" if success else "FAILED"}] {account_name}: {result["message"]}')

	quota_after = quota_to_usd(result.get('quota'))
	used_after = quota_to_usd(result.get('used_quota'))
	user_info_after = {
		'success': True,
		'quota': quota_after,
		'used_quota': used_after,
		'display': f':money: Current balance: ${quota_after}, Used: ${used_after}',
	}

	delta = result.get('quota_delta')
	if delta is not None:
		before_quota = quota_to_usd(result['quota'] - delta)
		user_info_before = {
			'success': True,
			'quota': before_quota,
			'used_quota': used_after,
			'display': f':money: Current balance: ${before_quota}, Used: ${used_after}',
		}
	else:
		user_info_before = {'success': False, 'error': 'Balance baseline unavailable'}

	return user_info_before, user_info_after


def check_in_with_password(account: AccountConfig, account_name: str, provider_config, waf_cookies: dict | None = None):
	"""用账号密码重新登录触发签到

	依次尝试主域名与备用域名，返回与普通签到一致的三元组。
	"""
	last_error = None

	for domain in provider_config.candidate_domains():
		if domain != provider_config.domain:
			print(f'[INFO] {account_name}: Retrying with backup domain {domain}')

		success, result, error = check_in_via_password(
			account_name=account_name,
			domain=domain,
			username=account.username,
			password=account.password,
			api_user=account.api_user,
			session_cookie=account.get_session_cookie(),
			login_path=provider_config.login_api_path,
			waf_cookies=waf_cookies,
		)

		if result:
			before, after = shape_check_in_result(result, success, account_name)
			return success, before, after

		last_error = error
		print(f'[FAILED] {account_name}: {error}')

	return False, {'success': False, 'error': last_error or 'Password check-in failed'}, None


def check_in_with_github_oauth(
	account: AccountConfig, account_name: str, provider_config, waf_cookies: dict | None = None
):
	"""重放 GitHub OAuth 完成签到（agentrouter 这类无签到接口的站点）

	依次尝试主域名与备用域名，返回与普通签到一致的三元组。
	"""
	last_error = None

	try:
		oauth_provider = get_oauth_provider(account.oauth_provider)
	except ValueError as e:
		print(f'[FAILED] {account_name}: {e}')
		return False, {'success': False, 'error': str(e)}, None

	print(f'[INFO] {account_name}: Replaying {oauth_provider.name} OAuth to trigger check-in')

	for domain in provider_config.candidate_domains():
		if domain != provider_config.domain:
			print(f'[INFO] {account_name}: Retrying with backup domain {domain}')

		success, result, error = check_in_via_oauth(
			account_name=account_name,
			domain=domain,
			upstream_cookie=account.oauth_cookie,
			api_user=account.api_user,
			session_cookie=account.get_session_cookie(),
			provider=oauth_provider,
			waf_cookies=waf_cookies,
		)

		if result:
			before, after = shape_check_in_result(result, success, account_name)
			return success, before, after

		last_error = error
		print(f'[FAILED] {account_name}: {error}')

	return False, {'success': False, 'error': last_error or 'OAuth check-in failed'}, None


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	# 登录触发型站点（agentrouter）。这两条路径本身是纯 HTTP，但站点在阿里云 WAF
	# 后面：住宅 IP 直连没事，机房 IP 会被 HTTP 200 + JS 挑战页顶回来，所以先用
	# 浏览器解一次挑战，把 cookie 带进后面的请求。
	login_triggered = provider_config.uses_password_login() or provider_config.uses_github_oauth()
	if login_triggered:
		waf_cookies = None
		if provider_config.needs_waf_cookies():
			login_url = f'{provider_config.domain}{provider_config.login_path}'
			waf_cookies = await get_waf_cookies_with_playwright(
				account_name, login_url, provider_config.waf_cookie_names
			)
			if not waf_cookies:
				print(f'[WARNING] {account_name}: WAF cookies unavailable, trying direct request anyway')

		if provider_config.uses_password_login():
			if not account.has_password_credentials():
				print(f'[FAILED] {account_name}: Provider requires username/password but none configured')
				return False, {'success': False, 'error': 'username/password not configured'}, None
			return check_in_with_password(account, account_name, provider_config, waf_cookies)

		# 账号配了密码就优先用它，比 OAuth 重放稳
		if account.has_password_credentials():
			print(f'[INFO] {account_name}: Password credentials present, preferring password login over OAuth')
			return check_in_with_password(account, account_name, provider_config, waf_cookies)

		if not account.oauth_cookie:
			print(f'[FAILED] {account_name}: Provider requires oauth_cookie but none configured')
			return False, {'success': False, 'error': 'oauth_cookie not configured'}, None
		return check_in_with_github_oauth(account, account_name, provider_config, waf_cookies)

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		return False, None, None

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: account.api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info_before = get_user_info(client, headers, user_info_url)
		if user_info_before and user_info_before.get('success'):
			print(user_info_before['display'])
		elif user_info_before:
			print(user_info_before.get('error', 'Unknown error'))

		if provider_config.needs_manual_check_in():
			success = execute_check_in(client, account_name, provider_config, headers)
			# 签到后再次获取用户信息，用于计算签到收益
			user_info_after = get_user_info(client, headers, user_info_url)
			return success, user_info_before, user_info_after
		else:
			# 既没有签到接口，又没有配置 OAuth 重放：查用户信息不会触发签到，
			# 这里不能报成功，否则就是当前上游那种"假成功"。
			print(f'[FAILED] {account_name}: No check-in method available for this provider')
			print(f'[HINT] {account_name}: Set sign_in_path, or use check_in_method="github_oauth" with github_cookie')
			user_info_after = get_user_info(client, headers, user_info_url)
			return False, user_info_before, user_info_after

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, None, None
	finally:
		client.close()


async def main():
	"""主函数"""
	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started (using Playwright)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')

	accounts = load_accounts_config()
	if not accounts:
		print('[FAILED] Unable to load account configuration, program exits')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	last_balance_hash = load_balance_hash()

	# 站点按出口 IP 对登录限流（连打约 3 次触发 429，罚时约 60s），账号之间留间隔
	try:
		account_interval = int(os.getenv('ACCOUNT_INTERVAL_SECONDS') or 75)
	except ValueError:
		print('[WARNING] Invalid ACCOUNT_INTERVAL_SECONDS, falling back to 75')
		account_interval = 75

	success_count = 0
	total_count = len(accounts)
	# 按 provider 分账：每个站点单独出一条通知，好推给各自的飞书机器人
	notification_by_provider: dict[str, list[str]] = {}
	provider_stats: dict[str, dict[str, int]] = {}
	current_balances = {}
	account_check_in_details = {}  # 存储每个账号的签到详情
	need_notify = False  # 是否需要发送通知
	balance_changed = False  # 余额是否有变化

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		stats = provider_stats.setdefault(account.provider, {'success': 0, 'total': 0})
		stats['total'] += 1

		if i > 0 and account_interval > 0:
			print(f'[INFO] Waiting {account_interval}s before next account (IP rate limit)')
			await asyncio.sleep(account_interval)

		try:
			success, user_info_before, user_info_after = await check_in_account(account, i, app_config)
			if success:
				success_count += 1
				stats['success'] += 1

			should_notify_this_account = False

			if not success:
				should_notify_this_account = True
				need_notify = True
				account_name = account.get_display_name(i)
				print(f'[NOTIFY] {account_name} failed, will send notification')

			# 存储签到前后的余额信息
			if user_info_after and user_info_after.get('success'):
				current_quota = user_info_after['quota']
				current_used = user_info_after['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

				# 计算签到收益
				if user_info_before and user_info_before.get('success'):
					before_quota = user_info_before['quota']
					before_used = user_info_before['used_quota']
					after_quota = user_info_after['quota']
					after_used = user_info_after['used_quota']

					# 计算总额度（余额 + 历史消耗）
					total_before = before_quota + before_used
					total_after = after_quota + after_used

					# 签到获得的额度 = 总额度增加量
					check_in_reward = total_after - total_before

					# 本次消耗 = 历史消耗增加量
					usage_increase = after_used - before_used

					# 余额变化
					balance_change = after_quota - before_quota

					account_check_in_details[account_key] = {
						'name': account.get_display_name(i),
						'provider': account.provider,
						'before_quota': before_quota,
						'before_used': before_used,
						'after_quota': after_quota,
						'after_used': after_used,
						'check_in_reward': check_in_reward,  # 签到获得
						'usage_increase': usage_increase,  # 本次消耗
						'balance_change': balance_change,  # 余额变化
						'success': success,
					}

			if should_notify_this_account:
				account_name = account.get_display_name(i)
				status = '[SUCCESS]' if success else '[FAIL]'
				account_result = f'{status} {account_name}'
				if user_info_after and user_info_after.get('success'):
					account_result += f'\n{user_info_after["display"]}'
				elif user_info_after:
					account_result += f'\n{user_info_after.get("error", "Unknown error")}'
				notification_by_provider.setdefault(account.provider, []).append(account_result)

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'[FAILED] {account_name} processing exception: {e}')
			need_notify = True  # 异常也需要通知
			notification_by_provider.setdefault(account.provider, []).append(
				f'[FAIL] {account_name} exception: {str(e)[:50]}...'
			)

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			# 首次运行
			balance_changed = True
			need_notify = True
			print('[NOTIFY] First run detected, will send notification with current balances')
		elif current_balance_hash != last_balance_hash:
			# 余额有变化
			balance_changed = True
			need_notify = True
			print('[NOTIFY] Balance changes detected, will send notification')
		else:
			print('[INFO] No balance changes detected')

	# 为有余额变化的情况添加所有成功账号到通知内容
	if balance_changed:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in account_check_in_details:
				detail = account_check_in_details[account_key]
				account_name = detail['name']

				# 使用格式化函数生成通知消息
				account_result = format_check_in_notification(detail)

				# 检查是否已经在通知内容中（避免重复）
				bucket = notification_by_provider.setdefault(detail['provider'], [])
				if not any(account_name in item for item in bucket):
					bucket.append(account_result)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if need_notify and any(notification_by_provider.values()):
		time_info = f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

		# 每个 provider 各发一条，飞书可按站点推给不同机器人
		for provider_name in sorted(notification_by_provider):
			lines = notification_by_provider[provider_name]
			if not lines:
				continue

			stats = provider_stats.get(provider_name, {'success': 0, 'total': len(lines)})
			summary = build_summary(stats['success'], stats['total'])
			notify_content = '\n\n'.join([time_info, '\n'.join(lines), '\n'.join(summary)])
			title = f'{provider_title(provider_name)} Check-in Alert'

			print(f'=== {title} ===')
			print(notify_content)
			notify.push_message(title, notify_content, msg_type='text', provider=provider_name)

		print('[NOTIFY] Notification sent due to failures or balance changes')
	else:
		print('[INFO] All accounts successful and no balance changes detected, notification skipped')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
