import React from 'react';
import { formatTimeRange } from '@/utils/dates';

const EventChip = React.forwardRef(({ event, onSelect }, ref) => {
  const { title, startsAt, endsAt, categoryMeta } = event;
  const label = `${title} ${formatTimeRange(startsAt, endsAt)}`;
  const background = categoryMeta?.color ?? '#e5e7eb';
  const textColor = categoryMeta?.textColor ?? '#1f2937';

  return (
    <button
      ref={ref}
      type="button"
      className="event-chip"
      style={{ backgroundColor: background, color: textColor }}
      onClick={() => onSelect(event)}
      aria-haspopup="dialog"
      aria-controls="event-panel"
      aria-label={label}
    >
      <span className="event-chip__title">{title}</span>
      <span className="event-chip__time">{formatTimeRange(startsAt, endsAt)}</span>
    </button>
  );
});

EventChip.displayName = 'EventChip';

export default EventChip;
