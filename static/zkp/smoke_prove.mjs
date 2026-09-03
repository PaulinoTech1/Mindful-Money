import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';

const here = dirname(fileURLToPath(import.meta.url));
const artifactPath = resolve(here, '../../zkp/manual_expense/target/manual_expense.json');
const outputDir = resolve(here, '../../zkp/manual_expense/target/smoke');
const circuit = JSON.parse(await readFile(artifactPath, 'utf8'));

function fieldBytes(value) {
  const hex = BigInt(value).toString(16).padStart(64, '0');
  return Uint8Array.from(hex.match(/../g).map((byte) => Number.parseInt(byte, 16)));
}

const name = Array(120).fill(0);
for (const [index, byte] of [...Buffer.from('Coffee', 'utf8')].entries()) name[index] = byte;

const noir = new Noir(circuit);
const bb = await Barretenberg.new();
try {
  const backend = new UltraHonkBackend(circuit.bytecode, bb);
  const { witness, returnValue } = await noir.execute({
    name_bytes: name,
    name_length: 6,
    amount_cents: '4599',
    category_id: '1',
    has_category: true,
    commitment_blinding: '0x33',
    challenge: '0x11',
    record_id_hash: '0x22',
    schema_version: '1',
  });
  const proofData = await backend.generateProof(witness);
  if (!(await backend.verifyProof(proofData))) throw new Error('bb.js rejected its generated proof');
  if (proofData.publicInputs.length !== 4) {
    throw new Error(`expected 4 public inputs, got ${proofData.publicInputs.length}`);
  }
  const commitment = `0x${BigInt(returnValue).toString(16).padStart(64, '0')}`;
  if (proofData.publicInputs[3].toLowerCase() !== commitment) {
    throw new Error('public commitment is not the fourth proof public input');
  }
  const domain = `0x${Buffer.from('PAULINOTECH_MANUAL_EXPENSE_V1', 'utf8').toString('hex')}`;
  const preimage = [
    domain, '0x11', '0x22', 1n, '0x33', 4599n, 1n, 1n, 6n,
    ...name.map((byte) => BigInt(byte)),
  ];
  const nativeCommitment = await bb.poseidon2Hash({ inputs: preimage.map(fieldBytes) });
  if (`0x${Buffer.from(nativeCommitment.hash).toString('hex')}` !== commitment) {
    throw new Error('Barretenberg Poseidon2 hash does not match the Noir public return value');
  }

  await mkdir(outputDir, { recursive: true });
  await writeFile(resolve(outputDir, 'proof'), proofData.proof);
  await writeFile(
    resolve(outputDir, 'public_inputs'),
    Buffer.concat(proofData.publicInputs.map((field) => Buffer.from(field.slice(2), 'hex'))),
  );
  console.log(JSON.stringify({
    valid: true,
    proofBytes: proofData.proof.length,
    publicInputs: proofData.publicInputs,
    commitment,
  }));
} finally {
  await bb.destroy();
}
