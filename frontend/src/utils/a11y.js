export const getFocusableElements = (container) => {
  if (!container) return [];
  const selector = [
    'a[href]',
    'button:not([disabled])',
    'textarea:not([disabled])',
    'input:not([type="hidden"]):not([disabled])',
    'select:not([disabled])',
    '[tabindex]:not([tabindex="-1"])'
  ].join(',');

  return Array.from(container.querySelectorAll(selector)).filter(
    (element) => !element.hasAttribute('aria-hidden') && element.offsetParent !== null
  );
};

export const trapFocus = (event, container) => {
  if (event.key !== 'Tab' || !container) return;
  const focusable = getFocusableElements(container);
  if (!focusable.length) {
    event.preventDefault();
    return;
  }

  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  const isShift = event.shiftKey;
  const active = document.activeElement;

  if (!isShift && active === last) {
    event.preventDefault();
    first.focus();
  } else if (isShift && active === first) {
    event.preventDefault();
    last.focus();
  }
};
