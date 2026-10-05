// 资格闸裁决签名原语与签发密钥材料。
//
// 信任模型：调度服务持有一把 Ed25519 私钥，对【逐设备裁决的规范化字节】与
// 【冻结批次清单的规范化字节】签名；聚合商/监管方只需公钥即可独立验签，
// 不依赖在线服务、不依赖账本。公钥随 GATE_KEY_PUBLISHED 上链分发，
// 私钥保存在账本旁 sidecar（data/gate/gate-keys.json，权限 0600），链上永不出现私钥。
//
// 密钥轮换只追加新版本，旧密钥永不删除：历史批次永远锚定生成时的 keyId，
// 轮换后仍可按当时公钥复验，新裁决改用新 keyId。
import {
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function generateSignerKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// Ed25519 是 PureEdDSA：sign/verify 的 algorithm 参数必须为 null，
// 直接对调用方给定的规范化字节签名（不做二次哈希，避免“签名哈希”与“独立验签”口径不一致）。
export function signBytes(privateKeyPem, canonical) {
  return sign(null, Buffer.from(canonical, 'utf8'), privateKeyPem).toString('hex');
}

export function verifyBytes(publicKeyPem, canonical, signatureHex) {
  try {
    return verify(
      null,
      Buffer.from(canonical, 'utf8'),
      publicKeyPem,
      Buffer.from(signatureHex, 'hex'),
    );
  } catch {
    return false;
  }
}

export class GateKeyStore {
  // file 为 null 时纯内存（测试 / GATE_MEMORY=1）。
  constructor(file = null) {
    this.file = file;
    // [{ keyId, publicKeyPem, privateKeyPem, rotatedAt }]
    this.keys = [];
    if (file && existsSync(file)) {
      const raw = JSON.parse(readFileSync(file, 'utf8'));
      this.keys = raw.keys || [];
    }
  }

  get current() {
    return this.keys.at(-1) || null;
  }

  get currentKeyId() {
    return this.current?.keyId || null;
  }

  #persist() {
    if (!this.file) return;
    if (dirname(this.file) && dirname(this.file) !== '.') {
      mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 });
    }
    writeFileSync(
      this.file,
      JSON.stringify({ version: 1, keys: this.keys }, null, 2) + '\n',
      { mode: 0o600 },
    );
  }

  // 生成并登记一把新签发密钥（首个 keyId = gate-key-1，之后递增）。
  // 返回可上链的公开部分。
  rotate(nowIso) {
    const { publicKeyPem, privateKeyPem } = generateSignerKeyPair();
    const entry = {
      keyId: `gate-key-${this.keys.length + 1}`,
      publicKeyPem,
      privateKeyPem,
      rotatedAt: nowIso || new Date().toISOString(),
    };
    this.keys.push(entry);
    this.#persist();
    return { keyId: entry.keyId, publicKeyPem: entry.publicKeyPem, rotatedAt: entry.rotatedAt };
  }

  // 重放 GATE_KEY_PUBLISHED 时登记/核对公钥。
  // sidecar 已有 -> 必须与链上一致；sidecar 缺失 -> 只登记公钥（该版本仅可验签，不能再签发）。
  reconcile(record) {
    const existing = this.keys.find((k) => k.keyId === record.keyId);
    if (existing) {
      if (existing.publicKeyPem !== record.publicKeyPem) {
        throw new Error(`资格闸密钥 ${record.keyId} 的链上公钥与 sidecar 不一致`);
      }
      return;
    }
    this.keys.push({
      keyId: record.keyId,
      publicKeyPem: record.publicKeyPem,
      privateKeyPem: null,
      rotatedAt: record.rotatedAt,
    });
  }

  require(keyId) {
    const k = this.keys.find((x) => x.keyId === keyId);
    if (!k) throw new Error(`资格闸密钥 ${keyId} 未登记`);
    return k;
  }

  publicKey(keyId) {
    return this.require(keyId).publicKeyPem;
  }

  listPublic() {
    return this.keys.map((k) => ({
      keyId: k.keyId,
      publicKeyPem: k.publicKeyPem,
      rotatedAt: k.rotatedAt,
      canSign: !!k.privateKeyPem,
    }));
  }

  signWith(keyId, canonical) {
    const k = this.require(keyId);
    if (!k.privateKeyPem) {
      throw Object.assign(new Error(`密钥 ${keyId} 仅有公钥（sidecar 缺失），无法签发`), {
        code: 'GATE_KEY_UNAVAILABLE', status: 503,
      });
    }
    return signBytes(k.privateKeyPem, canonical);
  }

  verifyWith(keyId, canonical, signatureHex) {
    return verifyBytes(this.publicKey(keyId), canonical, signatureHex);
  }

  reset() {
    this.keys = [];
    if (this.file) writeFileSync(this.file, '');
  }
}
