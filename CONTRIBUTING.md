# Contributing to nmaptui

Thanks for helping. nmaptui is MIT licensed and permanently open source.

## Getting set up

```bash
git clone https://github.com/profullstack/nmaptui
cd nmaptui
bun install
npm test                  # node --test, no TTY required
bun test test/
bun run typecheck
bun run build
node bin/nmaptui.mjs open test/fixtures/estate.xml
```

Bun is the default runtime; everything also runs under Node 22.6+.

## The rules that matter

- No runtime dependencies beyond `@profullstack/hqtui`. The XML reader, the
  model, diffing and reports are all in `src/` on purpose.
- Screens are pure functions of `UiState`. Side effects live in
  `src/ui/controller.ts`. That is what lets `test/ui.test.ts` render real
  frames headlessly and assert on them, so keep it that way.
- A new finding rule goes in `src/analysis.ts` with a fixture that triggers it
  and one that must not. False positives cost more trust than misses.
- `toArgs` in `src/profiles.ts` is the contract for what nmap receives. Any
  change there needs a test in `test/profiles.test.ts`.
- Never make the installer ask for root.

## Pull requests

Small and focused. Run the whole suite before opening one. If a change is
visible, include a headless render (`renderToText`) in the tests rather than a
screenshot in the description.
