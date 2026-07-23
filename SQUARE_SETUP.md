# Square + Creator status (anti-cheat setup)

ModelVault **does not trust the browser** to grant Creator. Only Cloud Functions that verify Square can set `role: creator`.

## 1. Firebase Blaze plan

Cloud Functions need the Blaze (pay-as-you-go) plan. Free Spark cannot run them.

## 2. Square Developer credentials

1. Open [Square Developer Dashboard](https://developer.squareup.com/apps)
2. Create/open an app → **Credentials**
3. Copy **Production Access Token** (or Sandbox for testing)
4. **Locations** → copy your **Location ID**
5. **Webhooks** → Add subscription:
   - URL: `https://us-central1-modelvault-f7092.cloudfunctions.net/squareWebhook`
   - Events: `payment.created`, `payment.updated`
   - Copy **Signature Key**

## 3. Deploy functions + rules

```bash
cd E:\website\mv-repo
firebase login
firebase use modelvault-f7092

# Secrets (paste when prompted)
firebase functions:secrets:set SQUARE_ACCESS_TOKEN
firebase functions:secrets:set SQUARE_WEBHOOK_SIGNATURE_KEY

# Params (production)
firebase functions:config:set is not used for v2 params — set via:
```

With Functions v2 params, set at deploy time or in Google Cloud Console:

```bash
# Example .env for functions (do NOT commit real secrets)
# functions/.env
SQUARE_LOCATION_ID=LXXXXXXXX
SQUARE_ENV=production
CREATOR_PRICE_CENTS=1200
SITE_RETURN_URL=https://dylman2323.github.io/modelvault/?creator_sub=success#creators
WEBHOOK_NOTIFICATION_URL=https://us-central1-modelvault-f7092.cloudfunctions.net/squareWebhook
```

```bash
cd functions
npm install
cd ..
firebase deploy --only functions,firestore:rules
```

## 4. How it works

1. User signs in (Firebase Auth).
2. Clicks **Subscribe as Creator** → site calls `createCreatorCheckout` (server creates a Square payment link tied to their `uid` + email).
3. User pays on Square.
4. Square sends a **signed webhook** → `squareWebhook` verifies signature + payment amount ($12) + status COMPLETED → sets `accounts/{uid}.role = creator`.
5. User returns to the site; client **polls / calls `confirmCreatorPayment`** which only **reads** Square again — it never trusts a `?success` URL alone.

## 5. What cheaters cannot do

- Visiting `?creator_sub=success` does **not** grant Creator.
- Clicking “I’ve paid” only asks the **server** to check Square.
- Firestore rules block any client write that sets `role: creator` or fakes `lastRenewal`.

## 6. Email match

Users should pay with the **same email** as their ModelVault login (pre-filled by Square checkout). Pending checkouts also store Firebase `uid` on the Square order `reference_id`.
