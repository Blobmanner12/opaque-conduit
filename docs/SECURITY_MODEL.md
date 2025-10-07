# Opaque-Conduit: Security Model

## 1. Core Principles

The security of the `opaque-conduit` system is built upon several non-negotiable, foundational principles derived from a "White-Box" threat model. We assume the client environment is hostile, and a determined attacker has full control over their machine, including the ability to inspect network traffic and memory.

-   **The Primary Threat is Source Code Interception:** The entire model is designed to defeat a client-side attacker who can successfully authenticate and capture the final payload. The exfiltrated asset must be cryptographically worthless and hostile to analysis.

-   **Zero-Footprint Client:** No sensitive logic, cryptographic secrets, or intellectual property is ever permanently stored on the user's machine. The client is ephemeral, downloaded into memory on each run.

-   **Forced, Instantaneous Updates:** All users run the latest version of the client logic on every execution. This eliminates version fragmentation and ensures security patches are applied universally and immediately.

-   **Server-Driven Logic:** All critical security decisions (authentication, authorization) are made on the server. The client is treated as an untrusted, remote terminal.

## 2. Threat Model: The Adversary

Our security measures are designed to defeat a specific adversary profile:

-   **Skills:** Proficient with network interception and manipulation tools (e.g., Burp Suite, Fiddler). Capable of scripting to automate attacks. Understands how to bypass TLS on a controlled machine. Possesses experience with decompilers and reverse-engineering tools.
-   **Objective:** To acquire the unencrypted, functional Lua source code of the premium scripts for redistribution or analysis.

We do **not** defend against threats outside this scope, such as social engineering attacks targeting the project developers or physical server compromise.

## 3. The Secure Delivery Flow (End-to-End)

The delivery process is a multi-stage cryptographic sequence designed to establish a secure, authenticated channel and deliver an encrypted, hostile payload.

### **Stage 0: Bootstrap**

1.  **Action:** The user executes the trivial `public_loader.lua` (Stage 1).
2.  **Request:** The loader makes a simple GET request to `/api/bootstrap`.
3.  **Response:** The server responds with the full Lua source code of the `stage2_loader.lua`.
4.  **Security Goal:** To dynamically deliver the core client logic, preventing analysis of a static file and enabling instant updates. The Stage 1 loader is disposable and contains no secrets.

### **Stage 1: Handshake & Authenticity Verification**

1.  **Action:** The `stage2_loader.lua` (now in memory) makes a GET request to `/api/handshake`.
2.  **Response:** The server provides its RSA **Public Key** and a **SHA-256 Fingerprint** of that key.
3.  **Client-Side Verification:** The client calculates its own SHA-256 hash of the received Public Key. It compares this calculated hash to a **hardcoded fingerprint** within its own source code.
4.  **Security Goal:** To defeat a **Man-in-the-Middle (MITM)** attack. If an attacker intercepts the connection and substitutes their own public key, the calculated fingerprint will not match the hardcoded one, and the client will terminate immediately. This ensures the client is communicating with the authentic server.

### **Stage 2: Secure Key Exchange**

1.  **Action:** The client generates a random, single-use, 32-byte **Symmetric Key** (for AES-256).
2.  **Client-Side Encryption:** The client encrypts this new Symmetric Key using the server's authentic Public Key (verified in the previous step).
3.  **Request:** The client POSTs the encrypted Symmetric Key to `/api/exchange`.
4.  **Server-Side Decryption:** The server uses its **Private Key** to decrypt the payload, recovering the Symmetric Key.
5.  **Session Creation:** The server generates a short-lived session token, stores a mapping of `token -> Symmetric Key` in the Redis database (e.g., with a 5-minute expiry), and returns the token to the client.
6.  **Security Goal:** To securely establish a shared secret (the Symmetric Key) that only the client and the authentic server know. Any adversary snooping on the network traffic will only see an RSA-encrypted blob, which is useless without the server's private key.

### **Stage 3: Authenticated Payload Delivery**

1.  **Action:** The client POSTs its received **Session Token** and the desired `scriptId` to `/api/get-payload`.
2.  **Server-Side Verification:**
    -   The server looks up the token in Redis. If it doesn't exist, the request is unauthorized (401).
    -   It retrieves the associated Symmetric Key.
    -   It performs authorization checks (e.g., does this user have a license for this `scriptId`?). If not, the request is forbidden (403).
3.  **Payload Preparation:** The server retrieves the requested script, which is already pre-obfuscated with a VM (e.g., IronBrew2).
4.  **Server-Side Encryption:** The server encrypts the obfuscated bytecode using the **Symmetric Key** (AES-256).
5.  **Response:** The server sends the final, symmetrically encrypted payload to the client.
6.  **Client-Side Decryption:** The client uses its stored Symmetric Key to decrypt the payload, yielding the hostile, VM-obfuscated bytecode.
7.  **Execution:** The client executes the bytecode.
8.  **Security Goal:** To ensure that only an authenticated and authorized client can receive the payload, and to protect the payload itself in transit.

## 4. Known Limitations

-   **No Perfect Forward Secrecy:** The current RSA key exchange model does not provide forward secrecy. If the server's long-term Private Key is ever compromised, an attacker with recordings of past traffic could decrypt past sessions. This is an accepted risk for the current threat model.
-   **Reliance on Executor Environment:** The client-side Lua code relies on the executor to provide the necessary cryptographic and networking functions. A malicious or faulty executor could undermine the client's security checks. This is an inherent and accepted risk of the platform.