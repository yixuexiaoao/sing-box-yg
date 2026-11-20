const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const token = '1'.repeat(64);
const routes = [];
const commands = [];
let complete;
const app = {
    use() {},
    post(url, ...handlers) { routes.push({ method: 'POST', url, handlers }); },
    get(url, ...handlers) { routes.push({ method: 'GET', url, handlers }); },
    listen() {}
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8'), {
    Buffer, process: { env: {} }, setInterval() {},
    require(name) {
        if (name === 'dotenv') return { config() {} };
        if (name === 'express') return () => app;
        if (name === 'child_process') return { execFile(file, args, options, callback) {
            commands.push({ file, args, options }); complete = callback;
        } };
        if (name === 'fs') return { readFileSync(file) {
            if (file.endsWith('.sbyg-admin-token')) return token;
            if (file.endsWith('UUID.txt')) return 'test-uuid';
            if (file.endsWith('list.txt')) return 'test subscription';
            throw new Error('missing fixture');
        } };
        if (name === 'os') return { homedir: () => '/fixture', userInfo: () => ({ username: 'Test' }) };
        if (name === 'path') return path.posix;
        if (name === 'crypto') return crypto;
        throw new Error(`unexpected module ${name}`);
    }
});
function response() {
    return { code: 200, body: null, status(code) { this.code = code; return this; },
        sendStatus(code) { this.code = code; return this; },
        type() { return this; }, send(body) { this.body = body; return this; },
        json(body) { this.body = body; return this; } };
}
function invoke(route, req) {
    const res = response(); let index = 0;
    function next() { const handler = route.handlers[index++]; if (handler) handler(req, res, next); }
    next(); return res;
}
for (const url of ['/up', '/re', '/rp', '/jc']) {
    const route = routes.find(route => route.url === url);
    assert.equal(route.handlers.length, 2, `${url} has route-local authentication`);
    const res = invoke(route, { get: () => '' });
    assert.equal(res.code, 404);
}
assert.equal(commands.length, 0);
const admin = { get: () => `Bearer ${token}` };
for (const [url, script] of [['/up', 'serv00keep.sh'], ['/re', 'webrestart.sh'], ['/rp', 'webport.sh']]) {
    const route = routes.find(route => route.url === url);
    assert.equal(route.method, 'POST');
    const res = invoke(route, admin);
    assert.equal(commands.at(-1).file, 'bash');
    assert.equal(commands.at(-1).args[0], `/fixture/${script}`);
    assert.equal(invoke(route, admin).code, 409);
    complete(null, 'private output', 'private error');
    assert.equal(res.code, 200);
    assert.ok(!res.body.includes('private'));
}
const route = routes.find(route => route.url === '/up');
const failed = invoke(route, admin);
complete(new Error('fixture failure'), 'private output', 'private error');
assert.equal(failed.code, 500);
assert.ok(!failed.body.includes('private'));
const status = invoke(routes.find(route => route.url === '/jc'), admin);
assert.equal(status.body.busy, false);
assert.equal(Object.keys(status.body).length, 1);
const list = invoke(routes.find(route => route.url === '/list/:key'), { params: { key: 'test-uuid' } });
assert.equal(list.body, 'test subscription');
const keep = fs.readFileSync(path.join(__dirname, '..', 'serv00keep.sh'), 'utf8').split(/\r?\n/);
for (const [line, name] of [[14, 'UUID'], [15, 'ARGO_DOMAIN'], [16, 'ARGO_AUTH'], [17, 'vless_port'], [18, 'vmess_port'], [19, 'hy2_port'], [20, 'IP'], [21, 'reym']]) {
    assert.ok(keep[line - 1].startsWith(`export ${name}=`), `deployment slot ${line} retained`);
}
console.log('PASS Serv00 route authentication, successful operations, busy state, failures, subscription and deployment slots');
