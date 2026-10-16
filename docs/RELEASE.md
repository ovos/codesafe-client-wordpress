# Releasing the plugin

One tag does everything: the workflow verifies the version, builds the zip,
**signs it**, checks its own signature against the key in the source, and
publishes both files. What is left for a person is the four version spots, the
changelog, the tag, and the curated release text.

## 1. The four version spots

They must agree, or the workflow refuses the release:

| where | line |
|---|---|
| `ovos-codesafe.php` | ` * Version: X.Y.Z` |
| `src/Plugin.php` | `public const VERSION = 'X.Y.Z';` |
| `readme.txt` | `Stable tag: X.Y.Z` |
| `readme.txt` | `= X.Y.Z =` at the top of `== Changelog ==` |

Write the changelog as if the reader is deciding whether to update **today**.
A security fix is stated as one — what was wrong, in which shapes, since when,
and what to do about anything already sent. A security fix stated clearly is
a reference; one buried in "various improvements" is what gets found later and
quoted.

## 2. Commit, tag, push

```sh
git commit -m "X.Y.Z: <one line that says what changed>"
git tag -a vX.Y.Z -m "X.Y.Z"
git push origin develop
git push origin vX.Y.Z
```

The tag triggers `.github/workflows/release.yml`. Tags `v*` are protected by a
ruleset: only repository admins can create, move or delete one, so a release
cannot be cut from arbitrary code.

## 3. What the workflow does, and what fails it

1. **Version check** — the tag must equal the header and the stable tag.
2. **Build** — `git archive --prefix=ovos-codesafe/` at the tag. The install
   directory survives the swap because of that prefix.
3. **Sign** — Ed25519 over the whole zip, `openssl pkeyutl -sign -rawin`, with
   the PEM from the `release` environment's secret `OVOS_CONSOLE_SIGNING_KEY`.
   The signature is published as `ovos-codesafe.zip.sig`: base64 of the 64 raw
   bytes, one line, a text asset on purpose.
4. **Self-check** — the runner derives the public key from the secret and
   compares its raw 32 bytes with `Updater::PUBLIC_KEY` **in the checkout being
   released**, then verifies the signature it just made. A mismatch fails the
   job *before anything is published*, because a release signed with a key the
   plugin does not hold would brick auto-update on every site.
5. **Publish** — `gh release create` with both assets and generated notes.

The environment `release` admits `v*` tags only. A pull request, a leaked
token or a workflow on another ref cannot reach the key.

## 4. Curate the release text

`--generate-notes` writes commit titles. Replace them:

```sh
gh release edit vX.Y.Z --title "X.Y.Z — <the one line>" --notes-file notes.md
```

The body follows the earlier releases: `## X.Y.Z`, a bold lead, prose that
says what changed and why, a **Configuration change on update** paragraph
when there is one, `**Requires** PHP 8.1+, WordPress 6.0+.`, and
`` Full changelog: `readme.txt`. ``

## 5. The re-cut caveat

WordPress compares version **numbers**. A site already on X.Y.Z is never
offered a re-cut X.Y.Z zip, however different its bytes. Reaching installed
sites needs a real bump — fix the tag, bump, tag again.

## 6. How a site verifies

`Updater::download()` hooks `upgrader_pre_download` for this plugin's package
only. It downloads the zip and `ovos-codesafe.zip.sig`, verifies with
`sodium_crypto_sign_verify_detached()` — bundled by WordPress as
`sodium_compat` since 5.2, so present on every install whether or not
`ext/sodium` is — and hands WordPress the verified file. Anything that does not
verify is a `WP_Error` in the update screen and nothing is installed. A release
with no `.sig` asset is not even offered.

## 7. The keys

**Primary** (in the source as `Updater::PUBLIC_KEY`; its PEM is the `release`
environment secret):

```
0d91f295c416a035bcf3c8a3477fef635b8f306eb0f25e3d49b61ec24b919c04
```

**Spare**, generated the same day against loss of the primary, held offline
and **not** in GitHub:

```
be677491f280143fa438947ae531e8dd72a1d9ae51b2d8cb21f1e7d404d4a8f0
```

Both are also published in the console repository's `docs/DEPLOY.md` — a place
this repository cannot edit. If `PUBLIC_KEY` in a future version differs from
what is published there, something is wrong and the release should not be
trusted until it is explained.

## 8. Rotating the key

Every installed version verifies the **next** zip with the key it already
holds. So a rotation is two releases, not one:

1. **Transitional release** — signed with the **old** key, carrying the **new**
   `PUBLIC_KEY`. Sites verify it with the old key, install it, and now hold
   the new one. The self-check step will fail unless the *secret* is still the
   old key at this point — leave the secret alone for this release.
2. **Replace the secret** with the new PEM
   (`gh secret set OVOS_CONSOLE_SIGNING_KEY --env release < new.pem`).
3. **The release after** is signed with the new key.

Skip step 1 and every site refuses the update, and the only way back is a
manual reinstall on each of them. Add the retired key to this file with the
date it stopped signing.

## 9. If the self-check fails

The job says `the signing key in the environment is not the key the plugin
verifies with` and publishes nothing. Either the secret was replaced without a
transitional release (see 8), or `PUBLIC_KEY` was edited without replacing the
secret. Decide which is the truth, fix that one, delete the tag, tag again.
