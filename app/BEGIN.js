import { getCloudflareContext } from "@opennextjs/cloudflare";

function b64decode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(s);
  const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function getBanDetails(env, playFabId) {
  try {
    const resp = await fetch(`https://${env.PLAYFAB_TITLE_ID}.playfabapi.com/Server/GetUserBans`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-SecretKey": env.PLAYFAB_DEV_KEY },
      body: JSON.stringify({ PlayFabId: playFabId })
    });
    const data = await resp.json();
    return data.data?.BanData?.find(b => b.Active) || null;
  } catch {
    return null;
  }
}

async function loginWithPlayFab(env, userId) {
  const resp = await fetch(`https://${env.PLAYFAB_TITLE_ID}.playfabapi.com/Server/LoginWithServerCustomId`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-SecretKey": env.PLAYFAB_DEV_KEY },
    body: JSON.stringify({
      ServerCustomId: userId,
      CreateAccount: true,
      InfoRequestParameters: { GetUserAccountInfo: true, GetUserBanStatus: true }
    })
  });
  return await resp.json();
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

async function writeAuthenticationRecord(env, data) {
  const { userId, playFabId, sessionTicket, newlyCreated, packageId, deviceIntegrityState, storeRecognized, uniqueId, attestationToken, ip } = data;
  await env.DB.prepare(`
    INSERT INTO authentications (
      userId, playFabId, newlyCreated, sessionTicket, authenticatedAt,
      packageId, deviceIntegrityState, storeRecognized,
      uniqueId, attestationTokenPrefix, ip
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    userId, playFabId, newlyCreated, sessionTicket, new Date().toISOString(),
    packageId, deviceIntegrityState, storeRecognized, uniqueId,
    typeof attestationToken === "string" ? attestationToken.substring(0, 64) : null,
    ip || null
  ).run();
}

export async function POST(request) {
  const { env } = await getCloudflareContext({ async: true });

  const json403 = (msg) => Response.json({ BanMessage: msg, BanExpirationTime: "Unknown" }, { status: 403 });

  const body = await request.json();
  const { UserId, AttestationToken } = body;
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || null;

  if (!AttestationToken || String(AttestationToken).trim() === "")
    return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: attestation token is null or empty.");

  const data = await attestationAuthentication(AttestationToken);
  if (!data || data.error)
    return json403(`OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: attestation verification failed. ${data?.error || ""}`);
  if (!data.data || data.data.length === 0)
    return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: no data returned.");

  const responseData = data.data[0];
  const msg = responseData.message;

  if (msg === "invalid signature") return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: invalid signature.");
  if (msg === "token expired") return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: token expired.");
  if (msg !== "success") return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: invalid token.");

  const claims = responseData.claims;
  if (!claims) return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: missing claims.");

  let claimsJson;
  try {
    claimsJson = JSON.parse(b64decode(claims));
  } catch {
    try { claimsJson = JSON.parse(claims); }
    catch (e) { return json403(`OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: could not decode claims: ${e}`); }
  }

  const appState = claimsJson.app_state || {};
  const deviceState = claimsJson.device_state || {};
  const uniqueId = deviceState.unique_id;
  const deviceIntegrityState = deviceState.device_integrity_state;
  const storeRecognized = appState.app_integrity_state;
  const packageId = appState.package_id;

  if (!uniqueId || !deviceIntegrityState || !storeRecognized || !packageId)
    return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: incomplete data.");
  if (packageId !== env.MOTHERSHIP_VALID_PACKAGE)
    return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: package id mismatch.");
  if (deviceIntegrityState !== "Advanced")
    return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: untrusted device_integrity_state.");
  if (storeRecognized !== "StoreRecognized")
    return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: unrecognized app_integrity_state.");

  // ── KV ban check by UserId (Oculus ID) — before hitting PlayFab at all ──────
  const kvBanByUserId = await env.BAN_STORE.get(`ban:${UserId}`);
  if (kvBanByUserId) {
    const ban = JSON.parse(kvBanByUserId);
    return Response.json({
      BanMessage: ban.reason || "You have been banned from Plague Survival.",
      BanExpirationTime: ban.expires || "Permanent"
    }, { status: 403 });
  }

  const usedTokenResult = await env.DB.prepare("SELECT token FROM used_tokens WHERE token = ? LIMIT 1").bind(AttestationToken).first();
  if (usedTokenResult)
    return json403("OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: token already used.");

  const playfabResult = await loginWithPlayFab(env, UserId);

  if (playfabResult.code !== 200) {
    if (playfabResult.errorCode === 1002) {
      const errorDetails = playfabResult.errorDetails || {};
      const reason = Object.keys(errorDetails)[0] || "You have been banned from Plague Survival.";
      const duration = Object.values(errorDetails)[0]?.[0] || "Permanent";
      return Response.json({ BanMessage: reason, BanExpirationTime: duration }, { status: 403 });
    }
    return json403(`PLAYFAB AUTHENTICATION FAILED. REASON: ${playfabResult.errorMessage || "unknown error"}`);
  }

  const playfabId = playfabResult.data?.PlayFabId;
  const accountInfo = playfabResult.data?.InfoResultPayload?.UserAccountInfo;

  const kvBanByPfid = await env.BAN_STORE.get(`ban:${playfabId}`);
  if (kvBanByPfid) {
    const ban = JSON.parse(kvBanByPfid);
    return Response.json({
      BanMessage: ban.reason || "You have been banned from Plague Survival.",
      BanExpirationTime: ban.expires || "Permanent"
    }, { status: 403 });
  }

  if (accountInfo?.TitleInfo?.isBanned) {
    const activeBan = await getBanDetails(env, playfabId);
    return Response.json({
      BanMessage: activeBan?.Reason || "You have been banned from Plague Survival.",
      BanExpirationTime: activeBan?.Expires || "Permanent"
    }, { status: 403 });
  }

  const playfabData = playfabResult.data;

  await env.DB.prepare(`
    INSERT INTO pending_auth (userId, token, playfabId, sessionTicket, newlyCreated, createdAt)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(userId) DO UPDATE SET
      token = excluded.token, playfabId = excluded.playfabId,
      sessionTicket = excluded.sessionTicket, newlyCreated = excluded.newlyCreated,
      createdAt = excluded.createdAt
  `).bind(UserId, AttestationToken, playfabData.PlayFabId, playfabData.SessionTicket, playfabData.NewlyCreated, new Date().toISOString()).run();

  await writeAuthenticationRecord(env, {
    userId: UserId, playFabId: playfabData.PlayFabId, sessionTicket: playfabData.SessionTicket,
    newlyCreated: playfabData.NewlyCreated, packageId, deviceIntegrityState,
    storeRecognized, uniqueId, attestationToken: AttestationToken, ip,
  });

  return Response.json({ status: "BEGIN OK" });
}
