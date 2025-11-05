import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import CalendarGrid from '@/components/CalendarGrid.jsx';
import EventPanel from '@/components/EventPanel.jsx';
import { mockEvents } from '@/data/mockEvents';
import { generateMonthGrid, getMonthLabel, getWeekdayLabels } from '@/utils/dates';

const CalendarPage = () => {
  const [today] = useState(() => new Date());
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [activeTriggerId, setActiveTriggerId] = useState(null);
  const triggerRefs = useRef(new Map());

  const weekdayLabels = useMemo(() => getWeekdayLabels(), []);
  const monthLabel = useMemo(() => getMonthLabel(today), [today]);
  const calendarDays = useMemo(() => generateMonthGrid(today), [today]);

  const events = useMemo(() => mockEvents, []);

  const eventsByDay = useMemo(() => {
    const map = new Map();
    events.forEach((event) => {
      const key = event.startsAt.toDateString();
      if (!map.has(key)) {
        map.set(key, []);
      }
      map.get(key).push(event);
    });
    map.forEach((list) => list.sort((a, b) => a.startsAt - b.startsAt));
    return map;
  }, [events]);

  const selectedEvent = useMemo(
    () => events.find((event) => event.id === selectedEventId) ?? null,
    [events, selectedEventId]
  );

  const handleSelectEvent = useCallback((event) => {
    setActiveTriggerId(event.id);
    setSelectedEventId(event.id);
  }, []);

  const registerTrigger = useCallback((eventId, node) => {
    if (!node) {
      triggerRefs.current.delete(eventId);
    } else {
      triggerRefs.current.set(eventId, node);
    }
  }, []);

  const handleClosePanel = useCallback(() => {
    setSelectedEventId(null);
  }, []);

  useEffect(() => {
    if (selectedEventId === null && activeTriggerId) {
      const trigger = triggerRefs.current.get(activeTriggerId);
      if (trigger) {
        trigger.focus();
      }
      setActiveTriggerId(null);
    }
  }, [selectedEventId, activeTriggerId]);

  return (
    <>
      <div className="calendar-card">
        <header className="calendar-card__header">
          <div>
            <h2 className="calendar-card__title">{monthLabel}</h2>
            <p className="calendar-card__subtitle">
              Mock data to demonstrate the layout. Events are refreshed monthly.
            </p>
          </div>
        </header>
        <CalendarGrid
          days={calendarDays}
          eventsByDay={eventsByDay}
          weekdayLabels={weekdayLabels}
          onSelectEvent={handleSelectEvent}
          registerTrigger={registerTrigger}
        />
      </div>
      <EventPanel event={selectedEvent} open={Boolean(selectedEvent)} onClose={handleClosePanel} />
    </>
  );
};

export default CalendarPage;
