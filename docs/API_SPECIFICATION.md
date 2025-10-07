# Opaque-Conduit: API Specification

This document provides a detailed specification for all server-side API endpoints. All endpoints are routed through the Cloudflare proxy.

**Base URL:** `https://opaque-conduit-proxy.gooeyhub.workers.dev`

---

### `GET /api/bootstrap`

Serves the Stage 2 Lua client loader.

-   **Method:** `GET`
-   **Description:** Fetches the full source code of the in-memory client application.
-   **Request Body:** None.
-   **Success Response:**
    -   **Code:** `200 OK`
    -   **Content-Type:** `text/plain`
    -   **Body:** The raw Lua script as a string.
-   **Error Response:**
    -   **Code:** `500 Internal Server Error` (If the file cannot be read, which is unlikely with the monolithic approach).

---

### `GET /api/handshake`

Initiates the secure channel by providing the server's public key and its integrity fingerprint.

-   **Method:** `GET`
-   **Description:** Allows the client to get the server's public key and verify its authenticity before sending any sensitive data.
-   **Request Body:** None.
-   **Success Response:**
    -   **Code:** `200 OK`
    -   **Content-Type:** `application/json`
    -   **Body:**
        ```json
        {
          "publicKey": "BASE64_ENCODED_PUBLIC_KEY",
          "fingerprint": "SHA256_HEX_FINGERPRINT"
        }
        ```
-   **Error Response:**
    -   **Code:** `500 Internal Server Error`
    -   **Body:** `{"error": "Internal Server Error: Could not process handshake."}`

---

### `POST /api/exchange`

Receives the client's encrypted symmetric key and exchanges it for a short-lived session token.

-   **Method:** `POST`
-   **Description:** Completes the asymmetric portion of the key exchange.
-   **Request Body:**
    -   **Content-Type:** `application/json`
    -   **Body:**
        ```json
        {
          "encryptedKey": "BASE64_ENCODED_RSA_ENCRYPTED_SYMMETRIC_KEY"
        }
        ```
-   **Success Response:**
    -   **Code:** `200 OK`
    -   **Content-Type:** `application/json`
    -   **Body:**
        ```json
        {
          "sessionToken": "SECURE_SHORT_LIVED_SESSION_TOKEN"
        }
        ```
-   **Error Responses:**
    -   **Code:** `400 Bad Request`
        -   **Body:** `{"error": "Bad Request: Missing encryptedKey."}`
        -   **Body:** `{"error": "Bad Request: Invalid encrypted payload."}` (If decryption fails)
    -   **Code:** `405 Method Not Allowed`
    -   **Code:** `500 Internal Server Error`

---

### `POST /api/get-payload`

Delivers the final, encrypted script payload to an authenticated client.

-   **Method:** `POST`
-   **Description:** The final step where an authorized client uses a session token to request a specific script.
-   **Request Body:**
    -   **Content-Type:** `application/json`
    -   **Body:**
        ```json
        {
          "sessionToken": "SESSION_TOKEN_FROM_EXCHANGE",
          "scriptId": "UNIQUE_IDENTIFIER_FOR_SCRIPT"
        }
        ```
-   **Success Response:**
    -   **Code:** `200 OK`
    -   **Content-Type:** `application/json`
    -   **Body:**
        ```json
        {
          "encryptedPayload": "BASE64_ENCODED_AES_ENCRYPTED_PAYLOAD"
        }
        ```
-   **Error Responses:**
    -   **Code:** `400 Bad Request`
        -   **Body:** `{"error": "Bad Request: Missing sessionToken or scriptId."}`
    -   **Code:** `401 Unauthorized` (If session token is invalid or expired)
    -   **Code:** `403 Forbidden` (If user is not licensed for the requested `scriptId`)
    -   **Code:** `404 Not Found` (If the `scriptId` does not exist)
    -   **Code:** `405 Method Not Allowed`
    -   **Code:** `500 Internal Server Error`