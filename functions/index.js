/**
 * ModelVault — Square-verified Creator upgrades (anti-cheat)
 *
 * Clients cannot set role=creator (Firestore rules). Only this backend does,
 * after verifying a real Square payment (webhook signature + payment API).
 */

const { onRequest, onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret, defineString } = require("firebase-functions/params");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const crypto = require("crypto");

initializeApp();
const db = getFirestore();

const SQUARE_ACCESS_TOKEN = defineSecret("SQUARE_ACCESS_TOKEN");
const SQUARE_WEBHOOK_SIGNATURE_KEY = defineSecret("SQUARE_WEBHOOK_SIGNATURE_KEY");
const SQUARE_LOCATION_ID = defineString("SQUARE_LOCATION_ID", { default: "" });
const SQUARE_ENV = defineString("SQUARE_ENV", { default: "production" });
const CREATOR_PRICE_CENTS = defineString("CREATOR_PRICE_CENTS", { default: "1200" });
const SITE_RETURN_URL = defineString("SITE_RETURN_URL", {
  default: "https://dylman2323.github.io/modelvault/?creator_sub=success#creators",
});
const WEBHOOK_NOTIFICATION_URL = defineString("WEBHOOK_NOTIFICATION_URL", {
  default: "https://us-central1-modelvault-f7092.cloudfunctions.net/squareWebhook",
});

function squareBaseUrl() {
  return SQUARE_ENV.value() === "sandbox"
    ? "https://connect.squareupsandbox.com"
    : "https://connect.squareup.com";
}

function expectedPriceCents() {
  const n = parseInt(CREATOR_PRICE_CENTS.value() || "1200", 10);
  return Number.isFinite(n) && n > 0 ? n : 1200;
}

function todayISODate() {
  const d = new Date();
  return (
    d.getFullYear() +
    "-" +
    String(d.getMonth() + 1).padStart(2, "0") +
    "-" +
    String(d.getDate()).padStart(2, "0")
  );
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function isValidSquareSignature(body, signatureHeader, signatureKey, notificationUrl) {
  if (!signatureHeader || !signatureKey || body == null) return false;
  const hmac = crypto.createHmac("sha256", signatureKey);
  hmac.update(notificationUrl + body);
  const hash = hmac.digest("base64");
  try {
    const a = Buffer.from(hash);
    const b = Buffer.from(String(signatureHeader));
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return hash === signatureHeader;
  }
}

async function squareFetch(path, { method = "GET", body, token } = {}) {
  const res = await fetch(squareBaseUrl() + path, {
    method,
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
      "Square-Version": "2024-10-17",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  if (!res.ok) {
    const msg =
      (json && json.errors && json.errors[0] && json.errors[0].detail) ||
      text ||
      res.statusText;
    const err = new Error(msg);
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

async function paymentAlreadyProcessed(paymentId) {
  if (!paymentId) return true;
  const snap = await db.collection("processedPayments").doc(paymentId).get();
  return snap.exists;
}

async function markPaymentProcessed(paymentId, meta) {
  if (!paymentId) return;
  await db.collection("processedPayments").doc(paymentId).set(
    {
      ...meta,
      processedAt: FieldValue.serverTimestamp(),
    },
    { merge: true }
  );
}

function paymentIsCompleted(payment) {
  const status = String(payment.status || "").toUpperCase();
  return status === "COMPLETED";
}

function paymentAmountOk(payment) {
  const money = payment.amount_money || payment.amountMoney || {};
  const amount = Number(money.amount);
  const currency = String(money.currency || "USD").toUpperCase();
  if (currency !== "USD") return false;
  return amount === expectedPriceCents();
}

function extractBuyerEmail(payment) {
  return payment.buyer_email_address || payment.buyerEmailAddress || "";
}

async function findAccountRef({ uid, email }) {
  if (uid) {
    const ref = db.collection("accounts").doc(uid);
    const snap = await ref.get();
    if (snap.exists) return { ref, snap, uid };
  }
  const emailLower = normalizeEmail(email);
  if (!emailLower) return null;

  let q = await db.collection("accounts").where("emailLower", "==", emailLower).limit(3).get();
  if (!q.empty) {
    return { ref: q.docs[0].ref, snap: q.docs[0], uid: q.docs[0].id };
  }
  // Legacy docs without emailLower (bounded scan)
  const recent = await db.collection("accounts").orderBy("updatedAt", "desc").limit(200).get();
  const match = recent.docs.find((d) => normalizeEmail(d.data().email) === emailLower);
  if (match) return { ref: match.ref, snap: match, uid: match.id };
  return null;
}

async function grantCreatorAccess({ uid, email, paymentId, amountCents, source }) {
  if (paymentId && (await paymentAlreadyProcessed(paymentId))) {
    const existing = uid ? await db.collection("accounts").doc(uid).get() : null;
    if (existing && existing.exists && existing.data().role === "creator") {
      return { ok: true, uid, duplicate: true, lastRenewal: existing.data().lastRenewal };
    }
  }

  const found = await findAccountRef({ uid, email });
  if (!found) {
    console.warn("Unmatched payment", paymentId, email);
    if (paymentId) {
      await db.collection("unmatchedPayments").doc(paymentId).set({
        email: normalizeEmail(email),
        paymentId,
        amountCents: amountCents || null,
        source: source || "square",
        createdAt: FieldValue.serverTimestamp(),
      });
    }
    return { ok: false, reason: "no_account_for_email", email: normalizeEmail(email) };
  }

  const { ref, snap, uid: accountUid } = found;
  const prev = snap.data() || {};
  const lastRenewal = todayISODate();
  const data = {
    uid: accountUid,
    email: prev.email || email || "",
    emailLower: normalizeEmail(prev.email || email || ""),
    displayName: prev.displayName || "",
    role: "creator",
    status: "active",
    lastRenewal,
    lastSquarePaymentId: paymentId || prev.lastSquarePaymentId || null,
    lastPurchaseSource: source || "square_webhook",
    updatedAt: FieldValue.serverTimestamp(),
  };
  if (!prev.createdAt) data.createdAt = FieldValue.serverTimestamp();

  await ref.set(data, { merge: true });
  await db.collection("creators").doc(accountUid).set(
    {
      uid: accountUid,
      email: data.email,
      displayName: data.displayName,
      status: "active",
      lastRenewal,
      updatedAt: FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  if (paymentId) {
    await markPaymentProcessed(paymentId, {
      uid: accountUid,
      email: data.email,
      amountCents: amountCents || null,
      source: source || "square_webhook",
    });
  }

  console.log("Granted creator", accountUid, data.email, paymentId);
  return { ok: true, uid: accountUid, email: data.email, lastRenewal };
}

exports.squareWebhook = onRequest(
  {
    secrets: [SQUARE_ACCESS_TOKEN, SQUARE_WEBHOOK_SIGNATURE_KEY],
    cors: false,
    invoker: "public",
  },
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).send("Method Not Allowed");
      return;
    }

    const rawBody = Buffer.isBuffer(req.rawBody)
      ? req.rawBody.toString("utf8")
      : typeof req.body === "string"
        ? req.body
        : JSON.stringify(req.body || {});

    const signature =
      req.get("x-square-hmacsha256-signature") ||
      req.get("X-Square-HmacSha256-Signature") ||
      "";
    const sigKey = SQUARE_WEBHOOK_SIGNATURE_KEY.value();
    const urlCandidates = [
      WEBHOOK_NOTIFICATION_URL.value(),
      `https://${req.get("host")}/squareWebhook`,
      `https://${req.get("host")}${req.originalUrl || ""}`,
    ].filter(Boolean);

    const valid = urlCandidates.some((u) =>
      isValidSquareSignature(rawBody, signature, sigKey, u)
    );
    if (!valid) {
      console.warn("Invalid Square webhook signature", urlCandidates);
      res.status(403).send("Invalid signature");
      return;
    }

    let event;
    try {
      event = typeof req.body === "object" && req.body && !Buffer.isBuffer(req.body)
        ? req.body
        : JSON.parse(rawBody);
    } catch {
      res.status(400).send("Bad JSON");
      return;
    }

    const type = String(event.type || "");
    if (!type.toLowerCase().includes("payment")) {
      res.status(200).json({ ok: true, ignored: type });
      return;
    }

    const payment =
      (event.data && event.data.object && event.data.object.payment) ||
      (event.data && event.data.object) ||
      null;
    if (!payment || !payment.id) {
      res.status(200).json({ ok: true, ignored: "no_payment" });
      return;
    }

    if (!paymentIsCompleted(payment)) {
      res.status(200).json({ ok: true, skipped: "not_completed", status: payment.status });
      return;
    }
    if (!paymentAmountOk(payment)) {
      res.status(200).json({ ok: true, skipped: "amount_mismatch" });
      return;
    }

    let uid = null;
    const orderId = payment.order_id || payment.orderId || null;
    if (orderId) {
      const pending = await db.collection("pendingCheckouts").doc(String(orderId)).get();
      if (pending.exists) uid = pending.data().uid || null;
    }
    const refId = payment.reference_id || payment.referenceId || null;
    if (!uid && refId) {
      const pending = await db.collection("pendingCheckouts").doc(String(refId)).get();
      if (pending.exists) uid = pending.data().uid || null;
      // reference_id may be the firebase uid itself
      if (!uid && String(refId).length > 10) uid = String(refId);
    }

    const email = extractBuyerEmail(payment);
    const amount = Number((payment.amount_money || payment.amountMoney || {}).amount) || null;

    try {
      // Double-check with Square Payments API (don't trust payload alone beyond signature)
      let verified = payment;
      try {
        const got = await squareFetch("/v2/payments/" + encodeURIComponent(payment.id), {
          token: SQUARE_ACCESS_TOKEN.value(),
        });
        if (got && got.payment) verified = got.payment;
      } catch (e) {
        console.warn("GetPayment recheck failed, using webhook payload", e.message);
      }

      if (!paymentIsCompleted(verified) || !paymentAmountOk(verified)) {
        res.status(200).json({ ok: true, skipped: "recheck_failed" });
        return;
      }

      const result = await grantCreatorAccess({
        uid,
        email: extractBuyerEmail(verified) || email,
        paymentId: verified.id,
        amountCents: amount,
        source: "square_webhook",
      });
      res.status(200).json(result);
    } catch (e) {
      console.error(e);
      res.status(500).json({ ok: false, error: String(e.message || e) });
    }
  }
);

exports.createCreatorCheckout = onCall(
  {
    secrets: [SQUARE_ACCESS_TOKEN],
  },
  async (request) => {
    if (!request.auth || !request.auth.uid) {
      throw new HttpsError("unauthenticated", "Sign in required.");
    }
    const uid = request.auth.uid;
    const email = normalizeEmail(request.auth.token.email || "");
    if (!email) {
      throw new HttpsError("failed-precondition", "Your account needs an email address.");
    }
    const locationId = SQUARE_LOCATION_ID.value();
    if (!locationId) {
      throw new HttpsError(
        "failed-precondition",
        "Server missing SQUARE_LOCATION_ID. Owner must configure Square location."
      );
    }

    const price = expectedPriceCents();
    const idempotencyKey = `creator_${uid}_${Date.now()}`;
    const body = {
      idempotency_key: idempotencyKey,
      order: {
        location_id: locationId,
        reference_id: uid,
        line_items: [
          {
            name: "ModelVault Creator Subscription (1 month)",
            quantity: "1",
            base_price_money: { amount: price, currency: "USD" },
            note: "uid:" + uid,
          },
        ],
      },
      checkout_options: {
        redirect_url: SITE_RETURN_URL.value(),
        ask_for_shipping_address: false,
      },
      pre_populated_data: {
        buyer_email: request.auth.token.email || email,
      },
      payment_note: "ModelVault Creator uid:" + uid,
    };

    let json;
    try {
      json = await squareFetch("/v2/online-checkout/payment-links", {
        method: "POST",
        token: SQUARE_ACCESS_TOKEN.value(),
        body,
      });
    } catch (e) {
      console.error("Create payment link failed", e.body || e);
      throw new HttpsError(
        "internal",
        "Could not create Square checkout: " + (e.message || "error")
      );
    }

    const paymentLink = json.payment_link || json.paymentLink || {};
    const url = paymentLink.url || paymentLink.long_url || paymentLink.longUrl;
    const orderId = paymentLink.order_id || paymentLink.orderId || null;
    const linkId = paymentLink.id || null;
    if (!url) {
      throw new HttpsError("internal", "Square did not return a checkout URL.");
    }

    const pendingPayload = {
      uid,
      email,
      emailLower: email,
      orderId,
      linkId,
      amountCents: price,
      createdAt: FieldValue.serverTimestamp(),
    };
    const batch = db.batch();
    if (orderId) {
      batch.set(db.collection("pendingCheckouts").doc(String(orderId)), pendingPayload);
    }
    if (linkId) {
      batch.set(db.collection("pendingCheckouts").doc(String(linkId)), pendingPayload);
    }
    batch.set(db.collection("pendingCheckouts").doc(uid), pendingPayload);
    batch.set(
      db.collection("accounts").doc(uid),
      {
        uid,
        email: request.auth.token.email || email,
        emailLower: email,
        status: "checkout_started",
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    await batch.commit();

    return { url, orderId, linkId };
  }
);

/**
 * Client asks server to confirm payment. Server talks to Square — client cannot fake this.
 */
exports.confirmCreatorPayment = onCall(
  {
    secrets: [SQUARE_ACCESS_TOKEN],
  },
  async (request) => {
    if (!request.auth || !request.auth.uid) {
      throw new HttpsError("unauthenticated", "Sign in required.");
    }
    const uid = request.auth.uid;
    const email = normalizeEmail(request.auth.token.email || "");
    const paymentId = (request.data && request.data.paymentId) || null;

    const accountSnap = await db.collection("accounts").doc(uid).get();
    const account = accountSnap.data() || {};
    if (account.role === "creator" && account.status === "active") {
      return {
        ok: true,
        role: "creator",
        status: "active",
        lastRenewal: account.lastRenewal || null,
        source: "already_active",
      };
    }

    const token = SQUARE_ACCESS_TOKEN.value();
    const price = expectedPriceCents();

    async function tryGrant(payment, source) {
      if (!payment || !paymentIsCompleted(payment) || !paymentAmountOk(payment)) {
        return null;
      }
      return grantCreatorAccess({
        uid,
        email: extractBuyerEmail(payment) || email,
        paymentId: payment.id,
        amountCents: Number((payment.amount_money || payment.amountMoney || {}).amount) || price,
        source,
      });
    }

    if (paymentId) {
      try {
        const got = await squareFetch("/v2/payments/" + encodeURIComponent(paymentId), {
          token,
        });
        const result = await tryGrant(got.payment, "square_get_payment");
        if (result && result.ok) {
          return { ok: true, role: "creator", status: "active", lastRenewal: result.lastRenewal };
        }
        return { ok: false, reason: "payment_not_valid", detail: result };
      } catch (e) {
        return { ok: false, reason: "square_api_error", message: e.message };
      }
    }

    // Search recent completed payments
    try {
      const begin = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString();
      const listed = await squareFetch(
        "/v2/payments?begin_time=" +
          encodeURIComponent(begin) +
          "&sort_order=DESC&limit=50",
        { token }
      );
      const payments = listed.payments || [];
      for (const payment of payments) {
        if (!paymentIsCompleted(payment) || !paymentAmountOk(payment)) continue;
        const buyer = normalizeEmail(extractBuyerEmail(payment));
        const orderId = payment.order_id || payment.orderId;
        let matched = buyer && buyer === email;
        if (!matched && orderId) {
          const p = await db.collection("pendingCheckouts").doc(String(orderId)).get();
          if (p.exists && p.data().uid === uid) matched = true;
        }
        if (!matched) {
          const pUid = await db.collection("pendingCheckouts").doc(uid).get();
          if (pUid.exists && buyer === normalizeEmail(pUid.data().email)) matched = true;
        }
        // Also match order reference_id == uid via GetOrder if present
        if (!matched && orderId) {
          try {
            const ord = await squareFetch("/v2/orders/" + encodeURIComponent(orderId), {
              token,
            });
            const ref = (ord.order && (ord.order.reference_id || ord.order.referenceId)) || "";
            if (ref === uid) matched = true;
          } catch (_) {
            /* ignore */
          }
        }
        if (!matched) continue;
        const result = await tryGrant(payment, "square_search_payments");
        if (result && result.ok) {
          return { ok: true, role: "creator", status: "active", lastRenewal: result.lastRenewal };
        }
      }
    } catch (e) {
      console.error("Payment search failed", e);
      return {
        ok: false,
        reason: "square_search_error",
        message: e.message,
        hint: "Webhook may still activate you shortly. Pay with the same email as your ModelVault login.",
      };
    }

    return {
      ok: false,
      reason: "payment_not_found",
      hint: "No verified $12 Creator payment found for your account yet. Wait a few seconds, or make sure Square uses the same email as ModelVault.",
    };
  }
);
