import { getCloudflareContext } from "@opennextjs/cloudflare";


function b64decode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(s);
  const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function attestationAuthentication(attestationToken) {
  if (!attestationToken || String(attestationToken).trim() === "")
    return { error: "token_empty" };
  try {
    let claimsJson = null;
    let claimsB64 = null;
    if (typeof attestationToken === "string" && attestationToken.includes(".")) {
      const parts = attestationToken.split(".");
      if (parts.length >= 2) {
        try { claimsJson = JSON.parse(b64decode(parts[1])); claimsB64 = parts[1]; } catch {}
      }
    }
    if (!claimsJson) {
      claimsJson = JSON.parse(b64decode(attestationToken));
      claimsB64 = attestationToken;
    }
    const appState = claimsJson.app_state || {};
    const deviceState = claimsJson.device_state || {};
    if (!appState.package_id || !deviceState.device_integrity_state || !appState.app_integrity_state || !appState.package_cert_sha256_digest)
      return { error: "dev_token_missing_fields" };
    return { data: [{ message: "success", claims: claimsB64 }] };
  } catch (e) {
    return { error: `token_invalid: ${e}` };
  }
}

export async function POST(request) {
  const { env } = await getCloudflareContext({ async: true });
  const VALID_PACKAGE = env.MOTHERSHIP_VALID_PACKAGE || "com.SurvivalStudios.PlagueSurvival";

  const json403 = (msg) => Response.json({ BanMessage: msg, BanExpirationTime: "Unknown" }, { status: 403 });

  const body = await request.json();
  const { UserId } = body;

  if (!UserId) return json403("END failed: missing UserId");

  const pending = await env.DB.prepare("SELECT * FROM pending_auth WHERE userId = ? LIMIT 1").bind(UserId).first();
  if (!pending) return json403("END failed: no pending auth for this user");

  const data = await attestationAuthentication(pending.token);
  if (!data || data.error) return json403(`END failed: attestation verification failed. ${data?.error || ""}`);
  if (!data.data || data.data.length === 0) return json403("END failed: no data returned.");

  const responseData = data.data[0];
  if (responseData.message !== "success") return json403("END failed: attestation message not success.");

  const claims = responseData.claims;
  let claimsJson;
  try {
    claimsJson = JSON.parse(b64decode(claims));
  } catch {
    try { claimsJson = JSON.parse(claims); }
    catch (e) { return json403(`END failed: could not decode claims: ${e}`); }
  }

  const appState = claimsJson.app_state || {};
  const deviceState = claimsJson.device_state || {};

  if (appState.package_id !== VALID_PACKAGE || deviceState.device_integrity_state !== "Advanced")
    return json403("END failed: final checks did not pass.");

  await env.DB.prepare("INSERT INTO used_tokens (token, usedAt) VALUES (?, ?)").bind(pending.token, new Date().toISOString()).run();
  await env.DB.prepare("DELETE FROM pending_auth WHERE userId = ?").bind(UserId).run();

  return Response.json({
    Success: "OCULUS INTEGRITY AUTHENTICATION PASSED.",
    PlayFabId: pending.playfabId,
    SessionTicket: pending.sessionTicket,
    NewlyCreated: pending.newlyCreated
  });
}
