# Opaque-Conduit: Deployment Guide

This guide provides a complete, step-by-step process for deploying the `opaque-conduit` system from a fresh clone.

## 1. Prerequisites

Ensure you have the following software installed and configured:
-   [Git](https://git-scm.com/)
-   [Node.js](https://nodejs.org/) (LTS version)
-   [Vercel CLI](https://vercel.com/docs/cli): `npm install -g vercel`
-   [Cloudflare Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/): `npm install -g wrangler`

You will also need active accounts for:
-   [Vercel](https://vercel.com)
-   [Cloudflare](https://cloudflare.com)
-   [Upstash](https://upstash.com)

## 2. Initial Project Setup

1.  **Clone the Repository:**
    ```bash
    git clone <your-repo-url> opaque-conduit
    cd opaque-conduit
    ```

2.  **Install Dependencies:**
    ```bash
    npm install
    ```

## 3. Configuration & Key Generation

This is the most critical phase. All steps must be followed precisely.

1.  **Set Up Upstash:**
    -   Create a new Redis database in your Upstash dashboard.
    -   Copy the `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` values.

2.  **Create `.env` File:**
    -   Copy the example file: `cp .env.example .env`
    -   Open the new `.env` file and paste in your Upstash credentials.

3.  **Generate Cryptographic Keys:**
    -   Run the key generation script from your terminal:
        ```bash
        npm run generate-keys
        ```
    -   This script will output a `SERVER_PRIVATE_KEY` and a `SERVER_PUBLIC_KEY` in Base64 format directly to your console.
    -   Copy the entire `SERVER_PRIVATE_KEY` string and paste it into your `.env` file.
    -   Copy the entire `SERVER_PUBLIC_KEY` string and paste it into your `.env` file.

4.  **Generate and Set Public Key Fingerprint:**
    -   You need a way to get the SHA-256 hash of your public key. You can use an online tool or a local command.
    -   **Using Node.js (recommended):** Run this command in your terminal, replacing `YOUR_BASE64_PUBLIC_KEY` with the key you just generated:
        ```bash
        node -e "console.log(require('crypto').createHash('sha256').update(Buffer.from('YOUR_BASE64_PUBLIC_KEY', 'base64')).digest('hex'))"
        ```
    -   This will output a 64-character hex string. This is your public key fingerprint.
    -   Open `client/stage2_loader.lua`.
    -   Find the line `local HARDCODED_SERVER_FINGERPRINT = "..."`
    -   Paste your new fingerprint inside the quotes.

## 4. Payload Preparation

1.  **Add Source Scripts:** Place your human-readable Lua scripts into the `/payloads_src` directory.
2.  **Obfuscate:** Use your chosen tool (e.g., IronBrew2) to obfuscate each script. Place the obfuscated output files in a temporary location.
3.  **Bundle Payloads:**
    -   Open `scripts/bundle-payloads.js`.
    -   Modify the logic to read your obfuscated files and map them to the desired `scriptId`.
    -   Run the bundling script:
        ```bash
        npm run build:payloads
        ```
    -   This will automatically generate the `api/_lib/payloads.js` file with the scripts embedded.

## 5. Deployment

### Step 5.1: Vercel Backend

1.  **Link Project:** In your terminal, run `vercel link`. Follow the prompts to link the local directory to a new Vercel project named `opaque-conduit`.
2.  **Push Environment Variables:** Securely upload your local `.env` file to Vercel:
    ```bash
    vercel env add UPSTASH_REDIS_REST_URL <value> production
    vercel env add UPSTASH_REDIS_REST_TOKEN <value> production
    vercel env add SERVER_PRIVATE_KEY <value> production
    vercel env add SERVER_PUBLIC_KEY <value> production
    ```
3.  **Deploy:** Deploy to production:
    ```bash
    npm run deploy:prod
    ```
4.  Vercel will provide you with a production URL (e.g., `https://opaque-conduit-xxxxxxxx.vercel.app`). **This is your backend URL.**

### Step 5.2: Cloudflare Worker

1.  **Log In to Wrangler:**
    ```bash
    wrangler login
    ```
2.  **Configure Backend URL:**
    -   Open `cloudflare/worker.js`.
    -   Find the line `const VERCEL_BACKEND_URL = "..."`.
    -   Paste your Vercel production URL here.
3.  **Deploy Worker:**
    ```bash
    cd cloudflare
    wrangler deploy
    ```
4.  Wrangler will provide you with a final URL (e.g., `https://opaque-conduit-proxy.your-user.workers.dev`). **This is your final, public-facing API URL.**

### Step 5.3: Final Client Configuration

1.  Open `client/public_loader.lua` and `client/stage2_loader.lua`.
2.  Update the `BOOTSTRAP_URL` and `API_BASE_URL` variables to your new Cloudflare Worker URL.
3.  You are now ready to distribute the `client/public_loader.lua` file.