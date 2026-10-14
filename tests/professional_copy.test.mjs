// User-facing copy stays neutral and advisor-appropriate.
// Run: node tests/professional_copy.test.mjs
import fs from 'node:fs';
import assert from 'node:assert/strict';

const banned = [
  'eccentric', 'respectable escape', 'red carpet', 'spectacularly', 'over the top', 'no chill',
  'clairvoyance', 'judgment', 'judgmental', 'plot twist', 'denial', 'wallet would like', 'filed a dissent',
  'heroically', 'promise from the universe', 'Even I have standards', 'gloriously', 'Miraculously',
  'undefeated', 'scandal', 'fiscal personality', 'latest evidence', 'enough attitude', 'Ask nicely',
  'Fans Only', 'Scammers', 'Foreclosure', 'DC Unc', 'behaved for once', 'won this round',
];
for (const file of ['../static/app.js', '../static/index.html', '../static/simplefin-client.js']) {
  const src = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
  const hits = banned.filter((p) => src.toLowerCase().includes(p.toLowerCase()));
  assert.deepEqual(hits, [], `${file} contains unprofessional copy`);
}
console.log('professional_copy: all assertions passed');
