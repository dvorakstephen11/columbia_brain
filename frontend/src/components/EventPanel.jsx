import React, { useEffect, useRef } from 'react';
import { formatTimeRange } from '@/utils/dates';
import { trapFocus } from '@/utils/a11y';

const EventPanel = ({ event, open, onClose }) => {
  const panelRef = useRef(null);
  const closeButtonRef = useRef(null);

  useEffect(() => {
    if (open && closeButtonRef.current) {
      closeButtonRef.current.focus();
    }
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
      } else {
        trapFocus(event, panelRef.current);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  useEffect(() => {
    if (!open) return undefined;
    const original = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = original;
    };
  }, [open]);

  if (!open || !event) return null;

  const { title, description, startsAt, endsAt, location, organizer, categoryMeta, category } = event;

  return (
    <div className="event-panel__portal" role="presentation">
      <div className="event-panel__backdrop" onClick={onClose} aria-hidden="true" />
      <aside
        id="event-panel"
        className="event-panel"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={panelRef}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="event-panel__header">
          <h2>{title}</h2>
          <button
            type="button"
            ref={closeButtonRef}
            className="event-panel__close"
            onClick={onClose}
            aria-label="Close event details"
          >
            ×
          </button>
        </header>
        <div className="event-panel__meta">
          {categoryMeta && (
            <span
              className="event-panel__badge"
              style={{ backgroundColor: categoryMeta.color, color: categoryMeta.textColor }}
            >
              {categoryMeta.label}
            </span>
          )}
          <span className="event-panel__time">{formatTimeRange(startsAt, endsAt)}</span>
        </div>
        <p className="event-panel__description">{description}</p>
        <dl className="event-panel__details">
          <div>
            <dt>When</dt>
            <dd>{startsAt.toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'short' })}</dd>
          </div>
          <div>
            <dt>Where</dt>
            <dd>{location}</dd>
          </div>
          <div>
            <dt>Organizer</dt>
            <dd>{organizer}</dd>
          </div>
        </dl>
        <p className="event-panel__footnote" aria-label="Mock data note">
          Mock data for MVP · Category: {category}
        </p>
      </aside>
    </div>
  );
};

export default EventPanel;
