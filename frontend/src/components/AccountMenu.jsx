import React, { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const routesByStage = {
  verify: '/verify',
  username: '/username-setup'
};

const AccountMenu = () => {
  const { me, loading, logout, pendingRegistration } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const triggerRef = useRef(null);
  const menuRef = useRef(null);

  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }

    function handleClick(event) {
      if (!menuRef.current || !triggerRef.current) {
        return;
      }
      if (
        !menuRef.current.contains(event.target) &&
        !triggerRef.current.contains(event.target)
      ) {
        setOpen(false);
      }
    }

    function handleKeyDown(event) {
      if (event.key === 'Escape') {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }

    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  if (loading) {
    return <div className="account-menu__placeholder" aria-hidden="true" />;
  }

  const initials = me
    ? (me.username || me.email || '?')[0]?.toUpperCase() || '?'
    : '👤';

  const pendingStage = pendingRegistration?.stage ?? null;
  const pendingEmail = pendingRegistration?.email ?? null;

  const goTo = (path) => {
    setOpen(false);
    navigate(path);
  };

  const handleLogout = async () => {
    try {
      await logout();
      setOpen(false);
    } catch (error) {
      console.error('Failed to log out', error);
    }
  };

  return (
    <div className="account-menu">
      <button
        ref={triggerRef}
        type="button"
        className="account-menu__button"
        aria-haspopup="menu"
        aria-expanded={open ? 'true' : 'false'}
        onClick={() => setOpen((prev) => !prev)}
      >
        <span className="account-menu__avatar" aria-hidden="true">
          {initials}
        </span>
        <span className="sr-only">Account</span>
      </button>
      {open ? (
        <div className="account-menu__dropdown" role="menu" ref={menuRef}>
          {me ? (
            <>
              <div className="account-menu__summary">
                <div className="account-menu__avatar account-menu__avatar--inline" aria-hidden="true">
                  {initials}
                </div>
                <div>
                  <p className="account-menu__summary-name">{me.username || 'No username set'}</p>
                  <p className="account-menu__summary-email">{me.email}</p>
                </div>
              </div>
              <button type="button" className="account-menu__item" onClick={handleLogout}>
                Log out
              </button>
            </>
          ) : (
            <>
              {pendingStage ? (
                <div className="account-menu__pending">
                  <p>Finish signing up</p>
                  <p className="account-menu__pending-email">{pendingEmail}</p>
                  <button
                    type="button"
                    className="account-menu__item account-menu__item--primary"
                    onClick={() => goTo(routesByStage[pendingStage] ?? '/register')}
                  >
                    Continue
                  </button>
                </div>
              ) : null}
              <button
                type="button"
                className="account-menu__item"
                onClick={() => goTo('/login')}
              >
                Log in
              </button>
              <button
                type="button"
                className="account-menu__item"
                onClick={() => goTo('/register')}
              >
                Create account
              </button>
            </>
          )}
        </div>
      ) : null}
    </div>
  );
};

export default AccountMenu;
