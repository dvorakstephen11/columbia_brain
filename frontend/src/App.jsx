import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import AppLayout from '@/layouts/AppLayout.jsx';
import CalendarPage from '@/pages/CalendarPage.jsx';
import LoginPage from '@/pages/LoginPage.jsx';
import RegisterPage from '@/pages/RegisterPage.jsx';
import VerifyPage from '@/pages/VerifyPage.jsx';
import UsernameSetupPage from '@/pages/UsernameSetupPage.jsx';

const App = () => (
  <Routes>
    <Route element={<AppLayout />}>
      <Route index element={<CalendarPage />} />
      <Route path="login" element={<LoginPage />} />
      <Route path="register" element={<RegisterPage />} />
      <Route path="verify" element={<VerifyPage />} />
      <Route path="username-setup" element={<UsernameSetupPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes>
);

export default App;
