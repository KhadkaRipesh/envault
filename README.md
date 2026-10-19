# envault

A local-first, command-line secrets manager for Rust projects.

`envault` keeps project credentials encrypted at rest and only hands them to the
actual process that needs them. Plaintext secrets never sit in your repo and are
never readable by AI coding agents that share your dev environment.

## Security model

- **`envault.toml`** — committed to the repo. Contains only structure (profile
  names, key names) and crypto metadata. No secret values. Safe for anyone — or
  any AI — to read.
- **`.envault/secrets.enc`** — gitignored by default. Holds every real value,
  individually encrypted with XChaCha20-Poly1305. Safe to leave out of version
  control (use `--shared` if you ever want to commit it).
- **Memory only** — secrets are decrypted into `secrecy::SecretVec` buffers and
  zeroized with `zeroize` after use. No decrypted copy is ever written to disk
  (no temp files, no `.dec` files).
- **AAD binding** — each ciphertext is bound to `profile\0key` as associated
  data, so a value can't be moved to another profile/key and still decrypt.
- **Atomic writes** — `secrets.enc` is written to `.envault/secrets.enc.tmp`
  then renamed over the original, so a crash never corrupts the store.
- **Import** — `.env` files are encrypted into the store and the source file is
  deleted (or a loud warning is emitted if deletion fails).

## Crypto

- Key derivation: Argon2id (password + stored salt), parameters stored in
  `[meta]` of `secrets.enc`.
- Cipher: XChaCha20-Poly1305 (24-byte random nonce per value).
- Master key: 32 bytes, derived once per session, held in a `SecretVec`.
- Never custom crypto — only crate primitives (`argon2`, `chacha20poly1305`).

## Installation

```sh
cargo build --release
# target/release/envault is a single static binary; copy it onto your PATH.
```

## Quick start: init → set → run

```sh
# 1. Scaffold both files and set a master password (hidden input).
$ envault init
Initialized envault:
  envault.toml (safe to commit)
  .envault/secrets.enc (gitignored, holds encrypted values)
  .gitignore updated (if present)

# 2. Declare which keys a profile needs in envault.toml (committed, no secrets).
#    [profiles.dev]
#    keys = ["DATABASE_URL", "API_KEY"]

# 3. Encrypt a secret into the store (value prompted, never echoed).
$ envault set dev DATABASE_URL
Enter master password:
Enter value for DATABASE_URL:
Set dev/DATABASE_URL

# 4. List key names only — values are never revealed.
$ envault list dev
Profile 'dev' (2 keys):
  DATABASE_URL = <encrypted>
  API_KEY = <encrypted>

# 5. Run a command with the decrypted profile keys in its environment.
#    Secrets live in memory only and are wiped after spawning.
$ envault run --profile dev -- ./bin/myapp
```

## Commands

| Command | Purpose |
|---------|---------|
| `envault init` | Scaffold `envault.toml` + `.envault/secrets.enc`, set master password, update `.gitignore`. |
| `envault set <profile> <KEY>` | Prompt for a value (hidden), encrypt it into the store. |
| `envault list <profile>` | Print key names only; values masked. |
| `envault run --profile <name> -- <cmd…>` | Decrypt profile keys into memory, exec `<cmd…>` with them in the environment, then wipe memory. |
| `envault import <.env file> --profile <name>` | Encrypt all entries from a `.env` into the store, add the keys to `envault.toml` for that profile, then delete the source file. |

## Module layout

- `cli.rs` — clap derive CLI definitions.
- `crypto.rs` — Argon2id KDF, XChaCha20-Poly1305 encrypt/decrypt, value encoding.
- `store.rs` — read/write `secrets.enc` and `envault.toml`, atomic writes, `.gitignore` handling, AAD construction.
- `commands/` — one module per command (`init`, `set`, `list`, `run`, `import`).

## License

MIT