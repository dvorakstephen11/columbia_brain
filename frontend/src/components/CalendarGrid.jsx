import React from 'react';
import DayCell from './DayCell.jsx';

const CalendarGrid = ({ days, eventsByDay, weekdayLabels, onSelectEvent, registerTrigger }) => (
  <div className="calendar-card" role="region" aria-label="Monthly calendar">
    <div className="weekday-row" role="row">
      {weekdayLabels.map((label) => (
        <div key={label} className="weekday" role="columnheader" aria-label={label}>
          {label}
        </div>
      ))}
    </div>
    <div className="calendar-grid" role="grid">
      {days.map((day) => (
        <DayCell
          key={day.iso}
          day={day}
          events={eventsByDay.get(day.date.toDateString()) ?? []}
          onSelectEvent={onSelectEvent}
          registerTrigger={registerTrigger}
        />
      ))}
    </div>
  </div>
);

export default CalendarGrid;
