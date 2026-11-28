// The Miner Configuration "Stratum URL" line (dashboard.html, the /node_info
// callback). A node with no stratum listener reports worker_port 0; the line
// then says the node has no stratum port instead of showing another coin's
// default port. Runs the callback extracted from dashboard.html itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../../../dashboard.html', import.meta.url), 'utf8');

function render(nodeInfo: unknown, hostname = 'pool.example'): string {
  const start = html.indexOf("d3.json('../node_info', function(nodeInfo) {");
  assert.ok(start >= 0, 'the /node_info callback is in dashboard.html');
  const bodyStart = html.indexOf('{', start) + 1;
  const bodyEnd = html.indexOf('c2pDeploymentConnect();', bodyStart);
  assert.ok(bodyEnd > bodyStart, 'the callback calls c2pDeploymentConnect');
  const body = html.slice(bodyStart, bodyEnd);
  const el = { textContent: '' };
  const document = { getElementById: (id: string) => (id === 'miner-url' ? el : null) };
  const window = { location: { hostname } };
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  new Function('nodeInfo', 'document', 'window', body)(nodeInfo, document, window);
  return el.textContent;
}

test('a stratum port renders host:port', () => {
  assert.equal(render({ external_ip: 'usa.example', worker_port: 7903 }), 'stratum+tcp://usa.example:7903');
  assert.equal(render({ worker_port: 9327 }), 'stratum+tcp://pool.example:9327');
  assert.equal(render({ external_ip: '0.0.0.0', worker_port: 7903 }), 'stratum+tcp://pool.example:7903');
});

test('worker_port 0 or absent says the node has no stratum port', () => {
  for (const info of [{ worker_port: 0 }, {}, { worker_port: null }, { worker_port: 70000 }]) {
    const s = render(info);
    assert.match(s, /^stratum off on this node/);
    assert.doesNotMatch(s, /9327/);
  }
});

test('no /node_info answer reads unavailable', () => {
  assert.equal(render(null), 'unavailable');
});
