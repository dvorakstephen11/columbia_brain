import React from 'react';

import EventChip from './EventChip.jsx';
import { formatDayNumber, getAccessibleDayLabel } from '@/utils/dates';

const OVERFLOW_BADGE_ID = '__overflow__';

const DayCell = ({ day, events, tagBadges, tagMetaById, onSelectEvent, registerTrigger }) => {
  const { date, iso, isCurrentMonth, isToday } = day;
  const dayNumber = formatDayNumber(date);
  const accessibleLabel = getAccessibleDayLabel(date, { isToday });
  const hasEvents = events.length > 0;
  const badges = tagBadges ?? [];

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
        {hasEvents && (
          <span className="day-cell__count" aria-hidden="true">
            {events.length}
          </span>
        )}
      </div>
      {badges.length > 0 && (
        <div className="day-cell__tag-badges">
          {badges.map((badge) => {
            if (badge.type === 'overflow' || badge.tagId === OVERFLOW_BADGE_ID) {
              return (
                <span
                  key={`${iso}-${badge.tagId}`}
                  className="tag-badge tag-badge--overflow"
                  role="img"
                  aria-label={badge.ariaLabel}
                  title={badge.ariaLabel}
                >
                  +{badge.count}
                </span>
              );
            }

            const meta = tagMetaById?.[badge.tagId];
            const label = badge.ariaLabel;
            return (
              <span
                key={`${iso}-${badge.tagId}`}
                className="tag-badge"
                role="img"
                aria-label={label}
                title={label}
                style={{
                  backgroundColor: meta?.color,
                  color: meta?.textColor,
                  boxShadow: meta?.ringColor ? `0 0 0 2px ${meta.ringColor}` : undefined
                }}
              >
                {badge.count}
              </span>
            );
          })}
        </div>
      )}
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
