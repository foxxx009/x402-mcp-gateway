// Zero-dependency Base mainnet RPC helpers.
// Used to VERIFY USDC transfers on-chain (read-only) and read ERC-20 metadata.
// No private key, no facilitator, no gas wallet required on the seller side.

export const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const RPC = process.env.RPC_URL || 'https://mainnet.base.org';
export const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

export async function rpc(method, params) {
  const r = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!r.ok) throw new Error('rpc http ' + r.status);
  const j = await r.json();
  if (j.error) throw new Error('rpc error ' + JSON.stringify(j.error));
  return j.result;
}

// Decode an ERC-20 string return (handles both fixed bytes32 e.g. symbol,
// and dynamic string e.g. name()).
export function decodeErc20String(hex) {
  hex = (hex || '').replace(/^0x/, '');
  if (hex.length === 64) {
    return Buffer.from(hex, 'hex').toString('utf8').replace(/\0+$/, '').trim();
  }
  if (hex.length < 64) return '';
  const offset = parseInt(hex.slice(0, 64), 16) * 2;
  const len = parseInt(hex.slice(offset, offset + 64), 16) * 2;
  const data = hex.slice(offset + 64, offset + 64 + len);
  return Buffer.from(data, 'hex').toString('utf8');
}

export function decodeUint(hex) {
  return BigInt('0x' + (hex || '0x0').replace(/^0x/, ''));
}

const SELECTORS = {
  'name()': '0x06fdde03',
  'symbol()': '0x95d89b41',
  'decimals()': '0x313ce567',
  'totalSupply()': '0x18160ddd',
};

export async function erc20(addr, fn) {
  const data = await rpc('eth_call', [{ to: addr, data: SELECTORS[fn] }, 'latest']);
  return data;
}
