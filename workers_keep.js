addEventListener('scheduled', event => event.waitUntil(handleScheduled()));
// 在 Worker secret HTTP_TARGETS 中配置 JSON 数组，每项含 https URL 与独立管理 token。
async function handleScheduled() {
  const targets = JSON.parse(HTTP_TARGETS);
  if (!Array.isArray(targets) || !targets.length) throw new Error('HTTP_TARGETS 格式错误');
  for (let index = 0; index < targets.length; index++) {
    const { url, token } = targets[index];
    if (typeof url !== 'string' || !/^https:\/\/[A-Za-z0-9.-]+\/(up|re)$/.test(url) ||
        typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) {
      throw new Error(`第 ${index + 1} 项配置错误`);
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 190000);
    try {
      const response = await fetch(url, {
        method: 'POST', redirect: 'error', signal: controller.signal,
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!response.ok) throw new Error('请求失败');
      await response.body?.cancel();
      console.log(`第 ${index + 1} 项操作完成`);
    } catch {
      throw new Error(`第 ${index + 1} 项操作失败`);
    } finally {
      clearTimeout(timeout);
    }
  }
}
