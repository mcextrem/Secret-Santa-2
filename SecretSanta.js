/**
 * Adventskalender Wichtel-Logik & Verschlüsselung
 */

// Sattolo-Shuffle: Garantiert ein echtes Derangement (kein Teilnehmer zieht sich selbst)
function generatePairings(names) {
  if (!names || names.length < 2) {
    throw new Error("Es müssen mindestens 2 Teilnehmer vorhanden sein.");
  }

  const givers = [...names];
  const receivers = [...names];
  const n = receivers.length;

  // Sattolo-Algorithmus erzeugt einen einzelnen geschlossenen Zyklus ohne Fixpunkte
  for (let i = n - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * i); // Zufallsindex von 0 bis i-1
    const temp = receivers[i];
    receivers[i] = receivers[j];
    receivers[j] = temp;
  }

  return givers.map((giver, idx) => ({
    giver: giver,
    receiver: receivers[idx]
  }));
}

// Hilfsfunktionen für Hex-Konvertierung
function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuf(hexStr) {
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes[i / 2] = parseInt(hexStr.substr(i, 2), 16);
  }
  return bytes.buffer;
}

// AES-GCM Verschlüsselung für den Link
async function encryptPairing(giver, receiver) {
  const payload = JSON.stringify({ g: giver, r: receiver, t: Date.now() });
  const encoder = new TextEncoder();
  const data = encoder.encode(payload);

  const key = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );

  const rawKey = await window.crypto.subtle.exportKey("raw", key);

  return `${bufToHex(rawKey)}:${bufToHex(iv)}:${bufToHex(encrypted)}`;
}

// AES-GCM Entschlüsselung beim Öffnen des Links
async function decryptPairing(hashPayload) {
  const cleanHash = hashPayload.replace(/^#/, '');
  const parts = cleanHash.split(':');
  if (parts.length !== 3) {
    throw new Error("Ungültiges Link-Format.");
  }

  const [keyHex, ivHex, dataHex] = parts;
  const rawKey = hexToBuf(keyHex);
  const iv = hexToBuf(ivHex);
  const encrypted = hexToBuf(dataHex);

  const key = await window.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encrypted
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decrypted));
}
