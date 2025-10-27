import React from 'react';
import EventChip from './EventChip.jsx';
import { formatDayNumber, getAccessibleDayLabel } from '@/utils/dates';

const DayCell = ({ day, events, onSelectEvent, registerTrigger }) => {
  const { date, isCurrentMonth, isToday } = day;
  const dayNumber = formatDayNumber(date);
  const accessibleLabel = getAccessibleDayLabel(date, { isToday });

  return (
    <div
      className={`day-cell${isCurrentMonth ? '' : ' day-cell--muted'}${isToday ? ' day-cell--today' : ''}`}
      role="gridcell"
      aria-label={accessibleLabel}
    >
      <div className="day-cell__header">
        <span className="day-cell__number" aria-hidden="true">
          {dayNumber}
        </span>
        {events.length > 0 && (
          <span className="day-cell__count" aria-hidden="true">
            {events.length}
          </span>
        )}
      </div>
      <div className="day-cell__events">
        {events.map((event) => (
          <EventChip
            key={event.id}
            event={event}
            onSelect={onSelectEvent}
            ref={(node) => registerTrigger(event.id, node)}
          />
        ))}
      </div>
    </div>
  );
};

export default DayCell;
