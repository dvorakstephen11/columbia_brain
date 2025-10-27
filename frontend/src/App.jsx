import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import CalendarGrid from '@/components/CalendarGrid.jsx';
import EventPanel from '@/components/EventPanel.jsx';
import { generateMonthGrid, getMonthLabel, getWeekdayLabels } from '@/utils/dates';
import { mockEvents } from '@/data/mockEvents';

const App = () => {
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
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="app-header__eyebrow">Local events (mock)</p>
          <h1>{monthLabel}</h1>
        </div>
        <p className="app-header__subtitle">
          Discover what’s happening around town this month — curated highlights for inspiration.
        </p>
      </header>
      <main className="app-main" aria-hidden={selectedEvent ? true : undefined}>
        <CalendarGrid
          days={calendarDays}
          eventsByDay={eventsByDay}
          weekdayLabels={weekdayLabels}
          onSelectEvent={handleSelectEvent}
          registerTrigger={registerTrigger}
        />
      </main>
      <EventPanel event={selectedEvent} open={Boolean(selectedEvent)} onClose={handleClosePanel} />
    </div>
  );
};

export default App;
