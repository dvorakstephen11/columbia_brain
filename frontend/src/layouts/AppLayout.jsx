import React from 'react';
import { Outlet } from 'react-router-dom';

import AccountMenu from '@/components/AccountMenu.jsx';

const AppLayout = () => (
  <div className="app-shell">
    <header className="app-header">
      <div className="app-header__heading">
        <div className="app-header__title-row">
          <h1>Community calendar</h1>
          <span className="app-header__badge" aria-label="Mock data badge">
            Mock data
          </span>
        </div>
        <p className="app-header__summary">Local highlights refreshed monthly.</p>
      </div>
      <AccountMenu />
    </header>
    <main className="app-main">
      <Outlet />
    </main>
  </div>
);

export default AppLayout;
