import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";

const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const decode = (value) => JSON.parse(Buffer.from(value, "base64url").toString("utf8"));

export function signToken(payload, secret, { expiresIn = 3600, now = Date.now() } = {}) {
  if (!secret || Buffer.byteLength(secret) < 32) throw new Error("Secret must contain at least 32 bytes");
  const body = encode({ ...payload, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + expiresIn });
  const signature = createHmac("sha256", secret).update(body).digest("base64url");
  return body + "." + signature;
}

export function verifyToken(token, secret, { now = Date.now(), issuer, audience } = {}) {
  if (typeof token !== "string" || !secret) throw new Error("Invalid token");
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra) throw new Error("Malformed token");
  const expected = createHmac("sha256", secret).update(body).digest();
  let actual;
  try { actual = Buffer.from(signature, "base64url"); } catch { throw new Error("Invalid signature"); }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error("Invalid signature");
  const claims = decode(body);
  const seconds = Math.floor(now / 1000);
  if (!Number.isFinite(claims.exp) || claims.exp <= seconds) throw new Error("Token expired");
  if (issuer && claims.iss !== issuer) throw new Error("Invalid issuer");
  if (audience && claims.aud !== audience) throw new Error("Invalid audience");
  return claims;
}

export function bearerToken(header = "") {
  const match = /^Bearer\s+([^\s]+)$/i.exec(header);
  return match?.[1] ?? null;
}

export function createAuthGuard({ secret, issuer, audience, getToken = (req) => bearerToken(req.headers?.authorization) }) {
  if (!secret) throw new Error("A signing secret is required");
  return function authGuard(req, res, next) {
    try {
      const token = getToken(req);
      if (!token) return res.status(401).json({ error: "missing_token" });
      req.auth = verifyToken(token, secret, { issuer, audience });
      return next();
    } catch {
      return res.status(401).json({ error: "invalid_token" });
    }
  };
}

export function createOpaqueToken(bytes = 32) {
  if (!Number.isInteger(bytes) || bytes < 16 || bytes > 128) throw new RangeError("bytes must be between 16 and 128");
  return randomBytes(bytes).toString("base64url");
}
