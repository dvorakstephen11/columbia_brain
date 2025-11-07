import React from 'react';

import DayCell from './DayCell.jsx';

const EMPTY_BADGES = Object.freeze([]);

const CalendarGrid = ({
  days,
  eventsByDay,
  weekdayLabels,
  onSelectEvent,
  registerTrigger,
  tagBadgesByDayKey,
  tagMetaById
}) => (
  <div id="calendar" className="calendar-grid__container" role="region" aria-label="Monthly calendar">
    <div className="weekday-row" role="row">
      {weekdayLabels.map((label) => (
        <div key={label} className="weekday" role="columnheader" aria-label={label}>
          {label}
        </div>
      ))}
    </div>
    <div className="calendar-grid" role="grid">
      {days.map((day) => {
        const dayKey = day.date.toDateString();
        return (
          <DayCell
            key={day.iso}
            day={day}
            events={eventsByDay.get(dayKey) ?? []}
            tagBadges={tagBadgesByDayKey?.get(dayKey) ?? EMPTY_BADGES}
            tagMetaById={tagMetaById}
            onSelectEvent={onSelectEvent}
            registerTrigger={registerTrigger}
          />
        );
      })}
    </div>
  </div>
);

export default CalendarGrid;
