import React from 'react';
import { Outlet } from 'react-router-dom';

import AccountMenu from '@/components/AccountMenu.jsx';

const AppLayout = () => (
  <div className="app-shell">
    <header className="app-header">
      <div>
        <p className="app-header__eyebrow">Local events (mock)</p>
        <h1>Community calendar</h1>
        <p className="app-header__subtitle">
          Discover what&apos;s happening around town this month — curated highlights for inspiration.
        </p>
      </div>
      <AccountMenu />
    </header>
    <main className="app-main">
      <Outlet />
    </main>
  </div>
);

export default AppLayout;
