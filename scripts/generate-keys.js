 const NodeRSA = require('node-rsa');
const fs = require('fs');
const path = require('path');

console.log("Generating a new 2048-bit RSA key pair...");

const key = new NodeRSA({ b: 2048 });

// Export the keys in the standard PKCS#1 PEM format.
const privateKeyPem = key.exportKey('pkcs1-private-pem');
const publicKeyPem = key.exportKey('pkcs1-public-pem');

// For environment variables, we need to convert these multi-line PEM files
// into single-line Base64 strings. The Buffer conversion handles this perfectly.
const privateKeyB64 = Buffer.from(privateKeyPem).toString('base64');
const publicKeyB64 = Buffer.from(publicKeyPem).toString('base64');

console.log("\n--- Key Generation Complete ---");
console.log("\nCopy the following lines into your .env file:");
console.log("-------------------------------------------------");
console.log(`SERVER_PRIVATE_KEY="${privateKeyB64}"`);
console.log(`SERVER_PUBLIC_KEY="${publicKeyB64}"`);
console.log("-------------------------------------------------");

// As a best practice for security, we will NOT save the raw key files
// to disk unless explicitly needed. Using them directly from the .env
// file is more secure for this serverless architecture.
console.log("\nNOTE: Keys have been printed to the console for insertion into your .env file.");
console.log("They have not been saved to disk to minimize exposure.");