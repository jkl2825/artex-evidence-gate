#!/usr/bin/env python3
"""Exercise a built/pulled image with disposable PostgreSQL and no external targets."""

import argparse
import json
import subprocess
import time
import uuid


def docker(*args, capture=False):
    result = subprocess.run(
        ["docker", *args], check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else None


def wait_for_database(name):
    for _ in range(60):
        result = subprocess.run(
            ["docker", "exec", name, "pg_isready", "-U", "artex", "-d", "artex"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("temporary PostgreSQL did not become ready")


# All HTTP traffic stays inside the app container; tokens never leave this process.
API_CHECK = r'''
import http.client, json, os, socket, time, urllib.request, urllib.error
base = 'http://127.0.0.1:8787'
def request(path, body=None, token=None, method=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, headers=headers, method=method,
                                 data=None if body is None else json.dumps(body).encode())
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.read()
for attempt in range(60):
    try:
        health = json.loads(request('/api/health'))
        break
    except (OSError, ValueError):
        if attempt == 59:
            raise
        time.sleep(1)
assert health['ok'] and health['version'] == os.environ['EXPECTED_VERSION'], health
initialized = json.loads(request('/api/auth/status'))['initialized']
assert initialized == (os.environ['RESTARTED'] == '1'), initialized
html = request('/login').decode()
assert '<html' in html and '/_next/' in html, 'embedded UI missing'
try:
    request('/api/intercept/judge')
    raise AssertionError('protected API accepted an unauthenticated request')
except urllib.error.HTTPError as error:
    assert error.code == 401, error.code
path = '/api/auth/login' if initialized else '/api/auth/init'
credentials = {'password': 'ArtexSmokeUpdated2026!' if initialized else 'ArtexSmokeOnly2026!'}
if initialized:
    credentials['username'] = 'ARTEX'
token = json.loads(request(path, credentials))['token']
config = json.loads(request('/api/intercept/judge', token=token))
assert 'retry_count' in config and 'retry_interval_ms' in config, config
expected_retries = 2 if initialized else 0
assert config['retry_count'] == expected_retries, config
if not initialized:
    config['retry_count'] = 2
    config['retry_interval_ms'] = 125
    request('/api/intercept/judge', config, token, 'PUT')
    saved = json.loads(request('/api/intercept/judge', token=token))
    assert saved['retry_count'] == 2 and saved['retry_interval_ms'] == 125, saved
else:
    assert config['retry_interval_ms'] == 125, config
    # Incomplete authentication bodies must release the shared admission slots.
    connections = []
    try:
        for _ in range(4):
            conn = socket.create_connection(('127.0.0.1', 8787), timeout=8)
            connections.append(conn)
            conn.sendall(b'POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\n'
                         b'Content-Type: application/json\r\nContent-Length: 100\r\n\r\n')
        for conn in connections:
            response = http.client.HTTPResponse(conn)
            response.begin()
            assert response.status == 400, response.status
            response.close()
        assert json.loads(request('/api/auth/login', credentials))['token']
    finally:
        for conn in connections:
            conn.close()
if not initialized:
    request('/api/auth/change-password', {'old_password': credentials['password'],
                                         'new_password': 'ArtexSmokeUpdated2026!'}, token)
    try:
        request('/api/intercept/judge', token=token)
        raise AssertionError('old session survived password change')
    except urllib.error.HTTPError as error:
        assert error.code == 401, error.code
    token = json.loads(request('/api/auth/login', {'username': 'ARTEX',
                      'password': 'ArtexSmokeUpdated2026!'}))['token']
    for attempt in range(5):
        try:
            request('/api/auth/login', {'username': 'ARTEX', 'password': 'IncorrectSmokePassword!'})
            raise AssertionError('incorrect password accepted')
        except urllib.error.HTTPError as error:
            assert error.code == (429 if attempt == 4 else 401), error.code
    try:
        request('/api/auth/login', {'username': 'ARTEX', 'password': 'ArtexSmokeUpdated2026!'})
        raise AssertionError('locked account accepted login')
    except urllib.error.HTTPError as error:
        assert error.code == 429 and error.headers.get('Retry-After'), error.code
    # An already-authenticated owner can change the password to clear a lock.
    request('/api/auth/change-password', {'old_password': 'ArtexSmokeUpdated2026!',
                                         'new_password': 'ArtexSmokeUpdated2026!'}, token)
print('PASS version, database migrations, embedded UI, session revocation, lockout, bounded authentication reads and persisted settings')
'''

BROWSER_CHECK = r'''
const { execFileSync } = require('node:child_process');
const root = execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim();
(async () => {
  for (const tool of ['playwright', '@playwright/mcp', '@playwright/cli']) {
    const entry = tool === 'playwright' ? root + '/playwright' :
      require.resolve('playwright', { paths: [root + '/' + tool] });
    const { chromium } = require(entry);
    const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
    try {
      const page = await browser.newPage();
      const response = await page.goto('http://127.0.0.1:8787/login');
      if (!response.ok()) throw new Error('login page HTTP ' + response.status());
      await page.locator('input[type="password"]').waitFor();
      console.log('PASS ' + tool + ' Chromium ' + browser.version() + ': rendered login form');
    } finally {
      await browser.close();
    }
  }
})().catch(error => { console.error(error); process.exit(1); });
'''

TOOL_CHECK = r'''
import json, selectors, subprocess
url = 'http://127.0.0.1:8787/login'
try:
    opened = subprocess.check_output(['playwright-cli', '-s=artex-smoke', 'open', url], text=True, timeout=60)
    assert '### Error' not in opened and url in opened, opened
    snapshot = subprocess.check_output(['playwright-cli', '-s=artex-smoke', 'snapshot'], text=True, timeout=30)
    assert '### Error' not in snapshot and url in snapshot, snapshot
finally:
    subprocess.run(['playwright-cli', '-s=artex-smoke', 'close'], check=False, timeout=30)
print('PASS playwright-cli: opened and inspected local login page')
process = subprocess.Popen(['npx', '--offline', '--no-install', '@playwright/mcp', '--headless'],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
selector = selectors.DefaultSelector()
selector.register(process.stdout, selectors.EVENT_READ)
def rpc(identifier, method, params):
    process.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': identifier, 'method': method, 'params': params}) + '\n').encode())
    process.stdin.flush()
    while True:
        if not selector.select(timeout=60):
            raise TimeoutError('MCP response timed out')
        line = process.stdout.readline()
        if not line:
            raise RuntimeError('MCP exited before responding')
        result = json.loads(line)
        if result.get('id') == identifier:
            assert 'error' not in result, result
            assert not result['result'].get('isError'), result
            return result['result']
try:
    rpc(1, 'initialize', {'protocolVersion': '2024-11-05', 'capabilities': {},
                         'clientInfo': {'name': 'artex-image-smoke', 'version': '1'}})
    process.stdin.write((json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n').encode())
    process.stdin.flush()
    result = rpc(2, 'tools/call', {'name': 'browser_navigate', 'arguments': {'url': url}})
    assert url in json.dumps(result), result
    rpc(3, 'tools/call', {'name': 'browser_close', 'arguments': {}})
    print('PASS playwright-mcp: initialized and navigated local login page')
finally:
    selector.close()
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
'''


def stop_cleanly(name):
    docker("stop", "--time", "20", name)
    state = json.loads(docker("inspect", name, "--format", "{{json .State}}", capture=True))
    if state["ExitCode"] != 0 or state["OOMKilled"]:
        raise RuntimeError(f"container failed to stop cleanly: {state}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("version", help="expected /api/health version, without v")
    parser.add_argument("--platform", choices=["linux/amd64", "linux/arm64"])
    options = parser.parse_args()
    prefix = "artex-smoke-" + uuid.uuid4().hex[:12]
    network, postgres, app = prefix, prefix + "-pg", prefix + "-app"
    platform = ["--platform", options.platform] if options.platform else []
    try:
        if options.platform:
            actual = docker("image", "inspect", options.image, "--format",
                            "{{.Os}}/{{.Architecture}}", capture=True)
            if actual != options.platform:
                raise RuntimeError(f"expected {options.platform}, image is {actual}")
        docker("network", "create", "--internal", network)
        docker("run", "--detach", "--name", postgres, "--network", network,
               "--network-alias", "postgres", "--env", "POSTGRES_USER=artex",
               "--env", "POSTGRES_DB=artex", "--env", "POSTGRES_PASSWORD=smoke-only",
               "postgres:16-alpine")
        wait_for_database(postgres)
        docker("run", "--detach", *platform, "--name", app, "--network", network,
               "--env", "ARTEX_PG_DSN=postgres://artex:smoke-only@postgres:5432/artex?sslmode=disable",
               options.image)
        for restarted in (False, True):
            docker("exec", "--env", f"EXPECTED_VERSION={options.version}",
                   "--env", f"RESTARTED={int(restarted)}", app, "python3", "-c", API_CHECK)
            if not restarted:
                docker("exec", app, "node", "-e", BROWSER_CHECK)
                docker("exec", app, "python3", "-c", TOOL_CHECK)
            stop_cleanly(app)
            if not restarted:
                docker("start", app)
        print(f"PASS {options.image}: startup, restart and graceful shutdown", flush=True)
    except BaseException:
        subprocess.run(["docker", "logs", "--tail", "100", app], check=False)
        raise
    finally:
        # Only names generated by this invocation are removed, including anonymous volumes.
        for name in (app, postgres):
            subprocess.run(["docker", "rm", "--force", "--volumes", name], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", network], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
