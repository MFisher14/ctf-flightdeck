// Keepers' portal: checks the PIN and shows tonight's banner.
"use strict";

const PIN_HASH = 0xceba30d8; // FNV-1a of the PIN
const SALT = 0xb4;
const ORDER = [2, 4, 3, 0, 1];
const MAT = [
  [160, 160, 180, 152, 188, 161, 175, 148, 161, 172, 186],
  [144, 169, 186, 225, 190, 230, 168],
  [196, 199, 215],
  [179, 158, 183, 173],
  [212, 204, 208, 217, 222, 199, 214, 219, 198]
];

function fnv1a(text) {
  let h = 0x811c9dc5;
  for (const ch of text) {
    h ^= ch.charCodeAt(0);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function banner() {
  let out = "";
  let n = 0;
  for (const i of ORDER) {
    for (const code of MAT[i]) {
      out += String.fromCharCode(code ^ ((SALT + n) & 0xff));
      n += 1;
    }
  }
  return out;
}

document.getElementById("pin-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const shown = document.getElementById("banner");
  const pin = document.getElementById("pin").value;
  shown.hidden = false;
  shown.textContent = fnv1a(pin) === PIN_HASH ? "Welcome, keeper: " + banner() : "Wrong PIN.";
});
