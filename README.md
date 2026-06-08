# KeyBox Checker

KeyBox Checker is a **privacy-first, pure-frontend** Android `keybox.xml` checker. It parses keyboxes, private keys, and certificate chains locally in your browser. At runtime, it does not upload files, call a backend, or request external domains.

The principle is simple: the selected XML stays in local browser memory. Private-key/public-key matching, certificate chain signature verification, and validity checks run locally. Trusted roots and Google revocation status are bundled into the page as an offline snapshot.

## Use locally

Release and build outputs contain a single `index.html` file. You can double-click the local `index.html` file and open it directly in a browser. No server and no internet connection are required for normal use.

```text
dist/index.html
```

## Run

```bash
bun install
bun run dev
bun test
bun run build
```

## Privacy model

KeyBox Checker is designed to work offline after the page is loaded:

- The selected keybox file never leaves your browser.
- Private keys are parsed only in local memory for public-key comparison.
- Certificate chain signatures are verified locally with browser crypto APIs.
- Known attestation roots and Google revocation status are bundled as an offline snapshot.
- The optional `bun run update-trust-data` command is for maintainers who want to refresh the bundled snapshot before publishing a new build.

## Features

- Supports UTF-8 and UTF-16 keybox XML.
- Checks every `Key` inside each `Keybox` independently.
- Verifies private-key/public-key match.
- Verifies certificate validity windows, issuer/subject linkage, and RSA/ECDSA certificate signatures.
- Recognizes known attestation roots and checks serial numbers against the offline Google revocation snapshot.
- Uses Bun for install, test, and build workflows.

## Trust data refresh

```bash
bun run update-trust-data
```

This command is for maintainers who want to refresh the bundled Google attestation root/status snapshot before publishing. Normal users opening `index.html` do not run this network refresh.

## Distribution

### Local single-file build

```bash
bun run build
```

The production output is a single file:

```text
dist/index.html
```

You can copy it anywhere and open it directly in a browser.

### GitHub Pages

Push to `main` to publish the app with `.github/workflows/deploy-pages.yml`. The Pages build also emits the single-file `dist/index.html`.

### GitHub Release download

Create and push a version tag to publish a GitHub Release with `index.html` attached:

```bash
git tag v0.1.0
git push origin v0.1.0
```

You can also run the **Release single-file app** workflow manually and provide a tag such as `v0.1.0`. Users can download the release asset named `index.html` and use it offline.
