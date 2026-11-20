require('dotenv').config();
const express = require('express');
const { execFile } = require('child_process');
const { readFileSync } = require('fs');
const { homedir, userInfo } = require('os');
const { join } = require('path');
const { timingSafeEqual } = require('crypto');
const app = express();
const home = homedir();
const username = userInfo().username.toLowerCase();
const workdir = join(home, 'domains', `${username}.serv00.net`, 'logs');
let running = false;
function readValue(path) {
    try { return readFileSync(path, 'utf8').trim(); } catch { return ''; }
}
function authorized(req) {
    const token = process.env.SBYG_ADMIN_TOKEN || readValue(join(home, '.sbyg-admin-token'));
    const supplied = req.get('authorization') || '';
    if (!/^[a-f0-9]{64}$/.test(token)) return false;
    const expected = Buffer.from(`Bearer ${token}`);
    const actual = Buffer.from(supplied);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
}
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
});
function requireAdmin(req, res, next) {
    if (!authorized(req)) return res.sendStatus(404);
    next();
}
function runScript(script, res, success) {
    if (running) {
        if (res) res.status(409).send('已有管理操作正在执行');
        return;
    }
    running = true;
    execFile('bash', [join(home, script)], { timeout: 180000, maxBuffer: 1024 * 1024 }, (error) => {
        running = false;
        if (error) {
            if (res) res.status(500).send('管理操作失败，请通过 SSH 查看日志');
            return;
        }
        if (res) res.type('text').send(success);
    });
}
app.post('/up', requireAdmin, (req, res) => runScript('serv00keep.sh', res, '网页保活启动完成'));
app.post('/re', requireAdmin, (req, res) => runScript('webrestart.sh', res, '主程序重启成功'));
app.post('/rp', requireAdmin, (req, res) => runScript('webport.sh', res, '端口重置完成'));
app.get('/jc', requireAdmin, (req, res) => res.json({ busy: running }));
app.get('/list/:key', (req, res) => {
    const uuid = readValue(join(workdir, 'UUID.txt'));
    if (!uuid || req.params.key !== uuid) return res.sendStatus(404);
    const content = readValue(join(workdir, 'list.txt'));
    if (!content) return res.sendStatus(404);
    res.type('text').send(content);
});
app.use((req, res) => res.sendStatus(404));
setInterval(() => runScript('serv00keep.sh'), (2 * 60 + 15) * 60 * 1000);
app.listen(3000);
