# Login Flow Refactor – Implementation Plan

## 1. Objectives & Constraints
- Move the login/registration UI off the calendar page and into dedicated routes without abandoning the existing SPA/Vite + FastAPI architecture.
- Introduce a minimalist top-right user icon with contextual menu (login vs. profile) while keeping the calendar front and center.
- Preserve all auth semantics (CSRF protection, credential validation, email verification) while improving flow: registration → email verification (6-digit code) → username capture → login.
- Maintain developer conveniences (mock verification code display) until real email delivery is in place.

## 2. Architectural Adjustments
- Continue serving the React SPA from FastAPI; add client-side routing (React Router or comparable library).
- Establish a shared `AuthContext`/provider on the frontend that exposes auth state globally (replacing direct hook usage inside `AuthPanel`).
- Adopt a layout-based routing structure: root layout renders header (logo + user icon menu) and main content area (`<Outlet>`); calendar lives at `/`.
- Dedicated routes: `/login`, `/register`, `/verify`, and `/username-setup` (exact naming adjustable). Handle redirects based on auth/verification state.

## 3. Backend Changes
1. **User model updates**
   - Add `username` column (unique, nullable for existing users until populated).
   - Expose `username` in `MeResponse` and other relevant payloads.
   - Update `Base.metadata` models; prepare migration scripts (see §6).
2. **Registration flow**
   - Extend `/auth/register` to accept `email` + `password` only; registration response should include `pending_verification: true` and the mock verification code (in dev).
   - Optionally return a `registration_token` (JWT or signed payload) so the frontend can reference the pending account without resubmitting password during verification.
3. **Verification code updates**
   - Replace current token generator with 6-digit numeric codes:
     - Use `secrets.randbelow(1_000_000)`; zero-pad to 6 digits.
     - Hash and store code exactly as current `EmailVerificationToken` does.
   - Ensure codes remain single-use with 24h expiry; consider rate limiting (future enhancement).
   - Update `/auth/verify-code` to optionally accept `email` (or registration token) so the backend can identify the user without exposing the code.
4. **Email content**
   - Update `send_email` call to include the numeric code and keep the existing verification link for parity.
5. **Username capture endpoint**
   - Introduce `/auth/username` (POST) to set username for newly verified users.
   - Enforce uniqueness and basic validation (length, allowed chars).
   - Require authentication (session cookie) or accept a signed token produced after verification.
6. **Session handling**
   - No change to JWT session cookie creation; ensure `/auth/login` continues to reject unverified users and now checks for `username` presence (optional redirect logic handled client-side).

## 4. Frontend Changes
1. **Dependencies & bootstrapping**
   - Install `react-router-dom`.
   - Wrap root render (`main.jsx`) with `<BrowserRouter>` and new `<AuthProvider>`.
2. **Global auth context**
   - Move logic from `useAuth` into context/provider that stores `me`, loading state, and exposes `register`, `verifyCode`, `completeUsername`, `login`, `logout`, `refresh`.
   - Update hook to consume context.
3. **Layout & navigation**
   - Create `AppLayout` component with header (calendar title, subtitle) and new user icon menu.
   - User icon menu: shows “Log in” when unauthenticated (navigates to `/login`), otherwise displays avatar/initials + dropdown with username/email and “Log out”.
4. **Pages**
   - `CalendarPage`: render existing calendar components, no auth form.
   - `LoginPage`: email/password; handles errors and redirects to `/` on success; link to `/register`.
   - `RegisterPage`: collects email/password, triggers register call, displays mock code inline (white text) and CTA to `/verify` (auto redirect if result includes code).
   - `VerifyPage`: input for 6-digit code (and optional auto-populated dev code). On success, navigate to `/username-setup`.
   - `UsernameSetupPage`: allow user to choose username; call new backend endpoint, then prompt to login (or auto-login if session is established).
   - Ensure mobile-friendly layout (centered card, limited width).
5. **Routing logic**
   - Define protected routes/HOCs where necessary:
     - Redirect authenticated users away from `/login` and `/register`.
     - Ensure `/verify` and `/username-setup` gracefully handle direct hits (show helpful message if no pending registration).
6. **Styling**
   - Add minimal CSS modules or scoped styles for new components, leveraging existing stylesheet patterns.
   - Implement responsive header spacing so avatar aligns right without causing horizontal scroll.

## 5. UX & Interaction Details
- User icon: simple circular icon with SVG silhouette, hover/focus states, accessible name (`aria-label="Account"`).
- Form design: stacked inputs, large tap targets, subtle shadowed cards; maintain consistent button styling.
- Inline feedback:
  - Success/error banners within forms.
  - Display mock verification code in white text on neutral background for dev convenience; hide entirely behind feature flag when real email is live.
- Keep keyboard accessibility: focus management on navigation between steps, trap focus in modals if introduced.

## 6. Data Migration & Environment Updates
- **SQLite dev**: execute `ALTER TABLE users ADD COLUMN username TEXT UNIQUE;` (nullable). Provide helper script or documentation for developers.
- **Production (Postgres)**: create SQL migration file (or Alembic-lite script) with:
  - `ALTER TABLE users ADD COLUMN username TEXT;`
  - `CREATE UNIQUE INDEX ix_users_username ON users (username) WHERE username IS NOT NULL;`
- Optionally backfill existing verified users with derived usernames or prompt them on next login (frontend will detect missing username and route to `/username-setup`).
- Ensure deployment pipeline runs migrations before rolling out the new frontend bundle.

## 7. Testing & QA
- **Backend**
  - Unit tests for new username endpoint and verification code generator (length, digits only, collision handling).
  - Integration tests covering registration → verification → username → login success path and failure variants (invalid code, duplicate username, wrong password).
- **Frontend**
  - Component tests or Cypress-style E2E covering navigation between calendar/login/registration, verification code submission, and username setup.
  - Manual smoke test across desktop + mobile viewports for header alignment and flow.
- **Security checks**
  - Confirm CSRF token usage on all mutating requests.
  - Validate that 6-digit code verification rate-limiting is documented for future work.

## 8. Deployment & Follow-Up
- Update documentation (`README`, `todo.md`) to reflect new login flow and development notes about mock codes.
- Coordinate release: run migrations, deploy backend, deploy frontend.
- Monitor logs for new endpoint errors; capture metrics on login failures/verification attempts.
- Plan future enhancements: actual email delivery integration, rate limiting, password reset, avatar upload, profile page.
