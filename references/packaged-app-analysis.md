# Analysing Packaged Desktop Apps (Electron, Tauri, Node)

Most macOS desktop apps today are not a single hand-written Mach-O —
they are a web/native hybrid where the `.app`'s main executable is a
*launcher* and the logic you care about lives one layer down. Reaching
for a disassembler on the top-level binary wastes hours. Unwrap the
container first, then decide whether the real target is JavaScript or a
bundled native module.

This complements `analysis-methodology.md`: the eight techniques apply
once you've reached the native binary; this file is about *getting
there*.

---

## Recognise the container

| Signal | Framework |
|---|---|
| `Contents/Resources/app.asar`, an `Electron Framework.framework` | **Electron** |
| Brotli-compressed blobs in the executable, `index.html` xrefs, tiny `.app` | **Tauri** |
| `resources/` with minified `dist/`, `package.json` with an `electron`/custom CLI dep | Node/Electron JS payload |
| `*.node` files alongside JS | Node native addon (real logic often here) |

## Electron — unwrap the ASAR, then follow the calls

Electron apps are JavaScript wrapping (sometimes) native code. The JS
layer frequently contains the verification/validation flow in
plaintext, which tells you what any bundled native binary expects.

```bash
npm install -g @electron/asar
asar extract Contents/Resources/app.asar app_extracted/

# Where does JS hand off to native code?
find app_extracted/ -name "*.node" -o -name "*.dylib" -o -name "*.so"
grep -rn "spawn\|execFile\|ffi\|require(.*\.node" app_extracted/
```

If the sensitive operations (vault, crypto, license, auth) are in a
bundled native module, that module — not the Electron shell — is your
real target; run the methodology's eight techniques on it. The JS side
usually reveals the expected inputs and the call sequence for free.

## Obfuscated JS — introspect at runtime, don't fight the minifier

When the JavaScript itself is heavily obfuscated (control-flow
flattening, RC4 string encoding, dead code), static reading is
prohibitively slow. The module's own decryption runs *when you load it*,
so load it and ask it directly:

```javascript
const mod = require('./app_extracted/dist/lib/crypto.js');
for (const key of Object.getOwnPropertyNames(mod)) {
  const obj = mod[key];
  console.log(key,
    Object.getOwnPropertyNames(obj),
    Object.getOwnPropertyNames(obj.prototype || {}));
}
// Hidden helpers often start with _ or __ (e.g. _raw, __getFull__)
```

`Object.getOwnPropertyNames()` surfaces methods a `.` access would hide,
including the ones the obfuscator meant to keep internal. This is the JS
analog of the runtime-over-rewrite principle in technique #4: let the
target decode itself, then read the decoded state.

## Tauri — decompress the embedded frontend

Tauri embeds the frontend as Brotli-compressed assets inside the
executable. To recover them: find the xrefs to `index.html` to locate
the asset index table, dump the blobs, and Brotli-decompress. The
layout follows `tauri-codegen/src/embedded_assets.rs`. The Rust backend
is a normal Mach-O — reverse it with the standard playbook (it demangles
like any Rust binary: `rustfilt`, `Option`/`Result`/`Vec` idioms, panic
strings for symbol recovery).

## Where the logic actually lives

| App type | Shell (skip) | Real target |
|---|---|---|
| Electron + native module | main executable, `app.asar` JS glue | the `.node`/`.dylib` native binary |
| Electron, pure JS | main executable | `dist/` JS (runtime-introspect if obfuscated) |
| Tauri | asset launcher | Rust Mach-O backend + decompressed frontend |

Decide which column you're in *before* opening a disassembler. The most
common wasted afternoon on a hybrid app is reversing the launcher.

---

*Electron/Tauri/Node extraction notes adapted from
[`zhaoxuya520/reverse-skill`](https://github.com/zhaoxuya520/reverse-skill)
(MIT), reframed for macOS desktop-app auditing.*
