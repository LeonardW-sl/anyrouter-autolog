"""诊断脚本：阿里云 WAF 到底在拦什么

背景：CI（机房 IP）连着五轮拿不到 acw_sc__v2，请求被 HTTP 200 + 挑战页顶回来；
同样的代码在住宅 IP 上一次就过。要区分两种可能：

  A) WAF 只拦 XHR/fetch，放行导航。那挑战 JS 永远不会在文档上下文里跑起来
     （fetch 拿到的 HTML 只是字符串，不执行），acw_sc__v2 自然永远拿不到。
  B) WAF 对这个 IP 段是硬拦，导航也照拦。那挑战本身在这个环境不可解，
     换代码结构没用。

对同一个接口分别用「导航」和「fetch」各打一次，把状态、是否挑战页、cookie
变化全打出来。不带任何凭据，不触发签到。
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from playwright.async_api import async_playwright  # noqa: E402

from utils.agentrouter_oauth import USER_AGENT  # noqa: E402

DOMAIN = 'https://agentrouter.org'
TARGETS = ['/login', '/api/user/self', '/api/oauth/state?mode=login']
CHALLENGE_MARKER = 'aliyun_waf_aa'

FETCH_JS = """
async (path) => {
	try {
		const r = await fetch(path, { headers: { 'Accept': 'application/json' }, credentials: 'include' });
		return { status: r.status, text: (await r.text()).slice(0, 300) };
	} catch (e) {
		return { status: 0, text: String(e).slice(0, 300) };
	}
}
"""


def squash(text: str, limit: int = 200) -> str:
	return ' '.join((text or '').split())[:limit]


def verdict(body: str) -> str:
	return 'CHALLENGE' if CHALLENGE_MARKER in (body or '') else 'clean'


async def cookie_names(context) -> list[str]:
	return sorted(c['name'] for c in await context.cookies())


async def probe(context, path: str) -> dict:
	row: dict = {'path': path}

	# 1) 导航：sec-fetch-mode=navigate，挑战 JS 有机会在文档上下文里执行
	page = await context.new_page()
	try:
		response = await page.goto(f'{DOMAIN}{path}', wait_until='networkidle')
		row['nav_status'] = response.status if response else None
		row['nav_body'] = squash(await page.content())
		# 给挑战 JS 留时间算 cookie 并 reload
		await page.wait_for_timeout(6000)
		row['nav_body_after_wait'] = squash(await page.content())
		row['cookies_after_nav'] = await cookie_names(context)
	except Exception as e:
		row['nav_error'] = f'{type(e).__name__}: {str(e)[:150]}'
	finally:
		await page.close()

	# 2) fetch：sec-fetch-mode=cors，拿到的挑战页只是字符串，不会执行
	page = await context.new_page()
	try:
		await page.goto(f'{DOMAIN}/login', wait_until='domcontentloaded')
		result = await page.evaluate(FETCH_JS, path)
		row['fetch_status'] = result.get('status')
		row['fetch_body'] = squash(result.get('text'))
		row['cookies_after_fetch'] = await cookie_names(context)
	except Exception as e:
		row['fetch_error'] = f'{type(e).__name__}: {str(e)[:150]}'
	finally:
		await page.close()

	return row


async def main():
	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as tmp:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=tmp,
				executable_path=None,
				headless=False,
				user_agent=USER_AGENT,
				viewport={'width': 1920, 'height': 1080},
				args=['--disable-blink-features=AutomationControlled', '--no-sandbox'],
			)
			try:
				rows = []
				for path in TARGETS:
					row = await probe(context, path)
					rows.append(row)
					print(f'\n===== {path} =====')
					print(f'  nav   HTTP {row.get("nav_status")}  -> {verdict(row.get("nav_body"))}')
					print(f'        after 6s wait -> {verdict(row.get("nav_body_after_wait"))}')
					print(f'        cookies: {row.get("cookies_after_nav")}')
					print(f'  fetch HTTP {row.get("fetch_status")} -> {verdict(row.get("fetch_body"))}')
					print(f'        cookies: {row.get("cookies_after_fetch")}')
					if row.get('nav_error'):
						print(f'  nav_error: {row["nav_error"]}')
					if row.get('fetch_error'):
						print(f'  fetch_error: {row["fetch_error"]}')
					print(f'  nav body:   {row.get("nav_body", "")[:160]}')
					print(f'  fetch body: {row.get("fetch_body", "")[:160]}')

				print('\n===== 结论依据 =====')
				nav_challenged = any(CHALLENGE_MARKER in (r.get('nav_body') or '') for r in rows)
				fetch_challenged = any(CHALLENGE_MARKER in (r.get('fetch_body') or '') for r in rows)
				got_sc = any('acw_sc__v2' in (r.get('cookies_after_nav') or []) for r in rows) or any(
					'acw_sc__v2' in (r.get('cookies_after_fetch') or []) for r in rows
				)
				print(f'导航被挑战: {nav_challenged}')
				print(f'fetch 被挑战: {fetch_challenged}')
				print(f'拿到 acw_sc__v2: {got_sc}')
				if fetch_challenged and not nav_challenged:
					print('=> 假设 A：只拦 fetch，放行导航。挑战 JS 永远不在文档里跑，acw_sc__v2 拿不到。')
				elif nav_challenged and not got_sc:
					print('=> 假设 B：导航也被拦且挑战没解开。这个 IP 段上挑战不可解，换代码结构没用。')
				elif got_sc:
					print('=> 挑战可解，问题在时序或作用域，不在 IP。')
				else:
					print('=> 两种请求都没被挑战，本轮失败另有原因。')

				print('\n===== raw =====')
				print(json.dumps(rows, ensure_ascii=False)[:4000])
			finally:
				await context.close()


asyncio.run(main())
