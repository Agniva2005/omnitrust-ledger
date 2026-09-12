# PROGRESS

Build log for OmniTrust Ledger, tracked against the phases in `CLAUDE.md` Section 5.

| Phase | Status | Notes |
| --- | --- | --- |
| 0 — Scaffold | Done | Next 15 + TS + Tailwind 3 + Prisma/SQLite + Vitest; Section 3 folder map created with stubs |
| 1 — Auth & RBAC | Done | bcrypt + JWT httpOnly cookie, capability-based RBAC, login page; 52 tests |
| 2 — Document management | Next | — |
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

## Phase 1 — Auth & RBAC (complete)

Done:

- `User` model + first real migration (`20260912185615_add_user`).
- `lib/auth/rbac.ts` — `Role` union, `isRole`/`assertRole`, a role-to-capability map, `can()`, `requireRole()`, `requireCapability()`, and `AuthenticationError` (401) / `AuthorizationError` (403).
- `lib/auth/session.ts` — bcrypt hashing (cost 12), `authenticate()`, JWT issue/verify via `jose` (HS256, 8h, issuer-checked), httpOnly `SameSite=Lax` cookie helpers, `getSession()`.
- `lib/api.ts` — error-to-status mapping shared by every route; unknown errors become a generic 500 so internals never leak to the client.
- Routes: `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, and `GET /api/admin/probe` (an ADMIN-only diagnostic endpoint that exists for the RBAC test).
- Login page with demo-account quick-fill buttons, `(app)` route group whose layout redirects unauthenticated visitors to `/login`, dashboard showing the actor's resolved capabilities, nav + sign-out.
- shadcn/ui primitives vendored: button, input, label, card, badge.
- `prisma/fixtures.ts` (shared by the seed script and tests) seeds four demo users.
- Tests: 52 passing across `tests/auth/{rbac,session,login-route,protected-route}.test.ts`.

Definition of Done — verified:

- Seeded users can log in. Verified over real HTTP against `npm run dev`: `POST /api/auth/login` → 200 with `#HttpOnly` cookie; `GET /api/auth/me` → 200 with the right role and capability list.
- A protected route rejects wrong roles. `GET /api/admin/probe` → 200 as ADMIN, 403 as SIGNER/VERIFIER/VIEWER, 401 unauthenticated or with a forged cookie. `/dashboard` unauthenticated → 307 to `/login`.
- `npm test` 52 passed, `npm run build` clean.

Notable during this phase:

- **`zod.string().email()` had to go.** It rejects `signer@demo` because there is no TLD, which would have made the Section 5 Phase 9 demo accounts unusable. Since the spec fixes those names, the login field is validated as a length-bounded opaque identifier (resolved by exact match) rather than as an RFC email address. Noted in the route.
- **Test database harness.** `tests/global-setup.ts` deletes `prisma/test.db` and runs `prisma migrate deploy` against a fresh file, so the suite never touches `prisma/dev.db`. It deliberately does *not* use `prisma db push --force-reset`: Prisma 6 guards that command against AI agents, and applying the committed migrations forward is both non-destructive and a better test, since it proves the migration history builds a working schema.
- **Prisma CLI is invoked through `node` directly** (`lib/prisma-cli.ts`), not `npx`. Spawning the `npx.cmd` shim without a shell fails with `EINVAL` on Windows, and enabling the shell would concatenate arguments instead of escaping them.

## Decisions log

Decisions that Section 6 or the spec asks to be recorded, plus judgement calls made where the spec left room.

1. **No Prisma enums.** Prisma does not support `enum` on the SQLite provider, so every role / status / algorithm column is `String`. The allowed values live as TypeScript unions in the module that owns the concept (`lib/auth/rbac.ts`, `lib/crypto/types.ts`, `lib/documents/lifecycle.ts`, `lib/pki/keys.ts`) and are validated before every write. This is also the more Postgres-portable choice Section 1 asks for. Tradeoff: the database will not reject a bad value on its own, so the `/lib` validators are the single enforcement point and are unit-tested as such.
2. **`bcryptjs`, not `bcrypt`.** Same algorithm, pure JS, no native toolchain needed — matters on Windows and for a clean-clone demo.
3. **`jose` for the session JWT.** No transitive dependencies, and works in the edge runtime if route protection moves to middleware.
4. **`zod` added** beyond the spec's dependency list, for API-boundary input validation only. No crypto or business logic in it.
5. **shadcn/ui components are vendored by hand** rather than via the interactive `shadcn init`, which is how shadcn is designed to be consumed (copy-in, not a runtime dependency). Keeps the clean-clone path free of an interactive CLI step.
6. **Tests run serially** (`fileParallelism: false`). Test suites share one SQLite file; serial execution avoids write-lock contention. Revisit if the suite gets slow.
7. **Known dev-time advisories, accepted.** `npm audit` reports 7 findings, all in build/dev tooling and none in the app's request path: `@vitest/mocker` (test runner), `deepmerge-ts` via `@prisma/config` (Prisma CLI), and `postcss` 8.4.31 as a nested dependency of Next 15's build pipeline (the top-level `postcss` resolves to a patched 8.5.28). Every offered fix is a major upgrade that would break the pins above. To be restated in the README limitations section in Phase 10.

## Next: Phase 2 — Document management (no crypto yet)

- `Document` / `DocumentVersion` schema + migration.
- `lib/documents/lifecycle.ts`: the Figure 4 state machine with validated transitions.
- `lib/documents/storage.ts`: blob write/read under `storage/documents/`.
- `lib/documents/service.ts`: upload, SHA-256 on upload, versioning.
- Multipart upload API + upload page, document list and detail pages.
- Section 6 edge cases: zero-byte upload rejected, duplicate upload handled.
