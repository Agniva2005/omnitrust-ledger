# PROGRESS

Build log for OmniTrust Ledger, tracked against the phases in `CLAUDE.md` Section 5.

| Phase | Status | Notes |
| --- | --- | --- |
| 0 — Scaffold | Done | Next 15 + TS + Tailwind 3 + Prisma/SQLite + Vitest; Section 3 folder map created with stubs |
| 1 — Auth & RBAC | Next | — |
| 2 — Document management | Not started | — |
| 3 — Crypto orchestration | Not started | Check-in point |
| 4 — PKI layer | Not started | — |
| 5 — Signing in document flow | Not started | — |
| 6 — Verification workflow | Not started | Check-in point |
| 7 — Audit & monitoring | Not started | — |
| 8 — Benchmarking | Not started | — |
| 9 — Seed data & demo script | Not started | — |
| 10 — Polish & documentation | Not started | — |

## Phase 0 — Scaffold (complete)

Done:

- `git init`, `.gitignore` (excludes `.env`, `*.db`, `storage/`, generated benchmark JSON).
- `package.json` with the dependency set approved at kickoff. Version pins and why: Next `15.5.25` (spec allows 14+; Next 16 defaults are unnecessary risk), Prisma `6.19.3` (npm's `latest` tag for the `prisma` CLI currently points at an 8.0.0 **release candidate**; 6.19.3 is the last stable 6.x and matches the `prisma-client-js` generator shape), Tailwind `3.4.x` (shadcn/ui compatibility without the v4 CSS-first migration), Vitest `3.2.x`.
- Next.js App Router scaffold: `app/layout.tsx`, `app/page.tsx` (architecture/build-status placeholder), `app/globals.css`, `tailwind.config.ts`, `postcss.config.mjs`, `next.config.ts`, `tsconfig.json` with `@/*` path alias.
- Section 3 folder map created; every `/lib` module is a stub carrying its layer name and the phase it gets implemented in.
- `prisma/schema.prisma` — datasource + generator only, no models yet (Phase 0 DoD). `prisma/seed.ts` stub.
- `lib/db.ts` — PrismaClient singleton (guards against hot-reload connection churn in dev).
- `vitest.config.ts` + `tests/scaffold.test.ts` (19 tests: asserts the Section 3 folder map exists and that `.env.example` documents every variable the app reads while `.env` stays ignored).
- `scripts/setup.ts` behind `npm run setup`: generates `.env` from `.env.example` with a fresh random `JWT_SECRET`, creates `storage/{documents,keys}`, generates `storage/keys/master.key` (32 random bytes, mode 0600), then `prisma generate` → `prisma migrate deploy` → seed. Idempotent: never overwrites an existing `.env` or master key.
- `PROGRESS.md` (this file).

Definition of Done — verified:

- `npm run dev` serves the home page: `GET / → 200`, page renders.
- `npm test` runs: 19 passed.
- `npx prisma migrate dev` succeeds against the empty schema ("Already in sync").
- `npm run build` compiles clean, types valid.

## Decisions log

Decisions that Section 6 or the spec asks to be recorded, plus judgement calls made where the spec left room.

1. **No Prisma enums.** Prisma does not support `enum` on the SQLite provider, so every role / status / algorithm column is `String`. The allowed values live as TypeScript unions in the module that owns the concept (`lib/auth/rbac.ts`, `lib/crypto/types.ts`, `lib/documents/lifecycle.ts`, `lib/pki/keys.ts`) and are validated before every write. This is also the more Postgres-portable choice Section 1 asks for. Tradeoff: the database will not reject a bad value on its own, so the `/lib` validators are the single enforcement point and are unit-tested as such.
2. **`bcryptjs`, not `bcrypt`.** Same algorithm, pure JS, no native toolchain needed — matters on Windows and for a clean-clone demo.
3. **`jose` for the session JWT.** No transitive dependencies, and works in the edge runtime if route protection moves to middleware.
4. **`zod` added** beyond the spec's dependency list, for API-boundary input validation only. No crypto or business logic in it.
5. **shadcn/ui components are vendored by hand** rather than via the interactive `shadcn init`, which is how shadcn is designed to be consumed (copy-in, not a runtime dependency). Keeps the clean-clone path free of an interactive CLI step.
6. **Tests run serially** (`fileParallelism: false`). Test suites share one SQLite file; serial execution avoids write-lock contention. Revisit if the suite gets slow.
7. **Known dev-time advisories, accepted.** `npm audit` reports 7 findings, all in build/dev tooling and none in the app's request path: `@vitest/mocker` (test runner), `deepmerge-ts` via `@prisma/config` (Prisma CLI), and `postcss` 8.4.31 as a nested dependency of Next 15's build pipeline (the top-level `postcss` resolves to a patched 8.5.28). Every offered fix is a major upgrade that would break the pins above. To be restated in the README limitations section in Phase 10.

## Next: Phase 1 — Auth & RBAC

- `User` model in `prisma/schema.prisma` + first real migration.
- `lib/auth/session.ts`: bcrypt verify, JWT issue/verify, httpOnly cookie, `getSession()`.
- `lib/auth/rbac.ts`: `Role` union, `requireRole()`.
- `POST /api/auth/login`, `POST /api/auth/logout`, plus a protected probe route for the RBAC test.
- Login page.
- Tests: password hashing round-trip, session token tamper rejection, `requireRole()` allow/deny matrix, protected route rejects wrong role.
