# Local Events Calendar MVP

A desktop-first single page calendar experience that highlights seven curated local events for the current month. The app is built with a React + Vite frontend and a lightweight FastAPI wrapper used for health checks and static hosting.

## Project structure

```
.
├── app/                  # FastAPI application (health checks + static hosting)
├── frontend/             # React SPA source
│   ├── src/
│   │   ├── components/   # Calendar UI primitives
│   │   ├── data/         # Mock event data
│   │   └── utils/        # Date + accessibility helpers
├── migrations/           # SQL helpers for auth-related schema updates
├── templates/            # Fallback template when the SPA hasn’t been built yet
└── tests/                # FastAPI smoke tests
```

## Prerequisites

- Python 3.11+
- Node.js 18+ and npm

## Local development

1. **Install Python dependencies** (virtualenv recommended):
   ```bash
   pip install -r requirements.txt
   ```

2. **Install frontend dependencies** and start the Vite dev server:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

   The dev server runs on <http://localhost:5173>. During development you can point your browser there directly.

3. **Run the FastAPI app** if you need the API routes or health checks:
   ```bash
   uvicorn app.main:app --reload
   ```

   When the frontend is built (see below), visiting <http://127.0.0.1:8000/> serves the compiled SPA. Until then a friendly placeholder reminds you to run the build.

## Building for production

Generate the static assets that Render (or any static host) can serve:

```bash
cd frontend
npm install
npm run build
```

The Vite build outputs to `frontend/dist/`. The FastAPI app automatically mounts the `/assets` directory and serves the `index.html` file from that folder. Commit the source; the build output is created during deployment.

## Deployment notes

Render setup (Static Site):

- **Build command:** `npm install && npm run build`
- **Publish directory:** `frontend/dist`
- **SPA routing rule:** `/* -> /index.html`

If you are using the FastAPI wrapper instead of Render’s static hosting, ensure the build step runs before the service starts so the `dist` directory exists.

Database migrations for the login refactor are tracked in [`migrations/`](migrations/README.md). Apply those SQL snippets before deploying the new authentication flow.

## Authentication flow

The calendar now exposes dedicated auth routes instead of embedding the forms inline:

1. `/register` – create an account with email + password. In development the API response contains `mock_verification_code` so you can see the 6-digit code without inspecting email logs.
2. `/verify` – submit the 6-digit code. Successful verification issues a short-lived token for the next step.
3. `/username-setup` – pick a unique username. After saving you can proceed to log in.
4. `/login` – sign in; verified accounts without a username are rejected until they finish the username step.

The header now shows a user icon with a contextual menu. When signed out it links to the login/registration pages (and, if applicable, the next step in a pending sign-up). When signed in it displays the current user’s username/email and provides a logout action.

## Accessibility and interaction checklist

- Calendar grid is always 7×6 cells to prevent layout shift.
- Event chips are focusable buttons exposing `aria-haspopup="dialog"`.
- Right-hand drawer follows dialog semantics (`role="dialog"`, `aria-modal="true"`) and traps focus while open.
- Esc key, backdrop click, and the close button all dismiss the panel and restore focus to the triggering chip.
- “Today” receives an accent ring and is announced via the day cell’s accessible label.

## Testing

Run the backend test suite (including the new registration flow coverage) with the project’s virtualenv:

```bash
./.venv/bin/python -m pytest -s
```

This exercises the registration → verification → username → login flow, error handling, and the original `/healthz` smoke test.


There is also a Dockerfile that can be used to build a Docker image of the application.
