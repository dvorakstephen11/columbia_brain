import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import CalendarGrid from '@/components/CalendarGrid.jsx';
import EventPanel from '@/components/EventPanel.jsx';
import TagFilterBar from '@/components/TagFilterBar.jsx';
import { mockEvents } from '@/data/mockEvents';
import { TAGS, tagIndexById, tagMetaById, getTagIndicesFromMask } from '@/data/tags';
import { generateMonthGrid, getMonthLabel, getWeekdayLabels } from '@/utils/dates';

const MAX_BADGES_PER_DAY = 4;

const parseMatchMode = (value) => (value === 'all' ? 'all' : 'any');

const parseTagMask = (value) => {
  if (!value) return 0;
  return value
    .split(',')
    .map((tagId) => tagId.trim())
    .filter(Boolean)
    .reduce((mask, tagId) => {
      const index = tagIndexById[tagId];
      if (typeof index === 'number') {
        return mask | (1 << index);
      }
      return mask;
    }, 0);
};

const encodeTagMask = (mask) =>
  getTagIndicesFromMask(mask)
    .map((index) => TAGS[index])
    .join(',');

const CalendarPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [today] = useState(() => new Date());
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [activeTriggerId, setActiveTriggerId] = useState(null);
  const triggerRefs = useRef(new Map());

  const weekdayLabels = useMemo(() => getWeekdayLabels(), []);
  const monthLabel = useMemo(() => getMonthLabel(today), [today]);
  const calendarDays = useMemo(() => generateMonthGrid(today), [today]);

  const events = useMemo(() => mockEvents, []);
  const selectedTagMask = useMemo(() => parseTagMask(searchParams.get('tags')), [searchParams]);
  const matchMode = useMemo(() => parseMatchMode(searchParams.get('match')), [searchParams]);

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

  const eventById = useMemo(() => {
    const map = new Map();
    events.forEach((event) => {
      map.set(event.id, event);
    });
    return map;
  }, [events]);

  const dayKeys = useMemo(
    () => calendarDays.map((day) => day.date.toDateString()),
    [calendarDays]
  );

  const dayIndexByKey = useMemo(() => {
    const indexMap = new Map();
    dayKeys.forEach((key, index) => indexMap.set(key, index));
    return indexMap;
  }, [dayKeys]);

  const { countsMatrix, monthTotalsByTag } = useMemo(() => {
    const tagCount = TAGS.length;
    const counts = new Uint16Array(calendarDays.length * tagCount);
    const totals = new Uint32Array(tagCount);

    if (dayIndexByKey.size === 0) {
      return { countsMatrix: counts, monthTotalsByTag: totals };
    }

    events.forEach((event) => {
      const dayIndex = dayIndexByKey.get(event.startsAt.toDateString());
      if (typeof dayIndex !== 'number') return;
      const tagIndices = getTagIndicesFromMask(event.tagMask);
      if (!tagIndices.length) return;
      const offset = dayIndex * tagCount;
      tagIndices.forEach((tagIndex) => {
        const matrixIndex = offset + tagIndex;
        counts[matrixIndex] += 1;
        totals[tagIndex] += 1;
      });
    });

    return { countsMatrix: counts, monthTotalsByTag: totals };
  }, [calendarDays.length, dayIndexByKey, events]);

  const selectedEvent = useMemo(
    () => eventById.get(selectedEventId) ?? null,
    [eventById, selectedEventId]
  );

  const syncFilters = useCallback(
    (nextMask, nextMatchMode = matchMode) => {
      const params = new URLSearchParams(searchParams);
      if (nextMask > 0) {
        params.set('tags', encodeTagMask(nextMask));
      } else {
        params.delete('tags');
      }
      params.set('match', nextMatchMode);
      setSearchParams(params, { replace: true });
    },
    [matchMode, searchParams, setSearchParams]
  );

  const handleToggleTag = useCallback(
    (tagId) => {
      const tagIndex = tagIndexById[tagId];
      if (typeof tagIndex !== 'number') return;
      const bit = 1 << tagIndex;
      const nextMask =
        selectedTagMask & bit ? selectedTagMask & ~bit : selectedTagMask | bit;
      syncFilters(nextMask, matchMode);
    },
    [matchMode, selectedTagMask, syncFilters]
  );

  const handleSetMatchMode = useCallback(
    (mode) => {
      if (mode === matchMode) return;
      syncFilters(selectedTagMask, mode);
    },
    [matchMode, selectedTagMask, syncFilters]
  );

  const handleClearTags = useCallback(() => {
    if (selectedTagMask === 0) return;
    syncFilters(0, matchMode);
  }, [matchMode, selectedTagMask, syncFilters]);

  const filteredEventsByDay = useMemo(() => {
    if (selectedTagMask === 0) return eventsByDay;
    const requireAll = matchMode === 'all';
    const filtered = new Map();
    eventsByDay.forEach((list, key) => {
      const matches = list.filter((event) =>
        requireAll
          ? (event.tagMask & selectedTagMask) === selectedTagMask
          : (event.tagMask & selectedTagMask) !== 0
      );
      if (matches.length > 0) {
        filtered.set(key, matches);
      }
    });
    return filtered;
  }, [eventsByDay, matchMode, selectedTagMask]);

  const selectedTagIndices = useMemo(
    () => getTagIndicesFromMask(selectedTagMask),
    [selectedTagMask]
  );

  const tagBadgesByDayKey = useMemo(() => {
    const map = new Map();
    const tagCount = TAGS.length;

    for (let dayIndex = 0; dayIndex < calendarDays.length; dayIndex += 1) {
      const dayKey = dayKeys[dayIndex];
      const offset = dayIndex * tagCount;
      let badges = [];

      if (selectedTagMask === 0) {
        for (let tagIndex = 0; tagIndex < tagCount; tagIndex += 1) {
          const count = countsMatrix[offset + tagIndex];
          if (count === 0) continue;
          const tagId = TAGS[tagIndex];
          const label = tagMetaById[tagId]?.label ?? tagId;
          badges.push({
            type: 'tag',
            tagId,
            tagIndex,
            count,
            ariaLabel: `${label}: ${count} event${count === 1 ? '' : 's'}`
          });
        }
        badges.sort((a, b) => {
          if (b.count !== a.count) {
            return b.count - a.count;
          }
          return a.tagIndex - b.tagIndex;
        });
      } else {
        badges = selectedTagIndices
          .map((tagIndex) => {
            const count = countsMatrix[offset + tagIndex];
            if (count === 0) return null;
            const tagId = TAGS[tagIndex];
            const label = tagMetaById[tagId]?.label ?? tagId;
            return {
              type: 'tag',
              tagId,
              tagIndex,
              count,
              ariaLabel: `${label}: ${count} event${count === 1 ? '' : 's'}`
            };
          })
          .filter(Boolean);
      }

      if (!badges.length) continue;

      if (badges.length > MAX_BADGES_PER_DAY) {
        const visible = badges.slice(0, MAX_BADGES_PER_DAY - 1);
        const hidden = badges.slice(MAX_BADGES_PER_DAY - 1);
        const hiddenLabel = hidden
          .map((badge) => {
            const label = tagMetaById[badge.tagId]?.label ?? badge.tagId;
            return `${label} ${badge.count}`;
          })
          .join(', ');
        visible.push({
          type: 'overflow',
          tagId: '__overflow__',
          count: hidden.length,
          ariaLabel: `+${hidden.length} more tags: ${hiddenLabel}`
        });
        map.set(dayKey, visible);
      } else {
        map.set(dayKey, badges);
      }
    }

    return map;
  }, [calendarDays.length, countsMatrix, dayKeys, selectedTagIndices, selectedTagMask]);

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
        <TagFilterBar
          tags={TAGS}
          tagMetaById={tagMetaById}
          monthTotalsByTag={monthTotalsByTag}
          selectedMask={selectedTagMask}
          matchMode={matchMode}
          onToggleTag={handleToggleTag}
          onSetMatchMode={handleSetMatchMode}
          onClearAll={handleClearTags}
        />
        <CalendarGrid
          days={calendarDays}
          eventsByDay={filteredEventsByDay}
          weekdayLabels={weekdayLabels}
          onSelectEvent={handleSelectEvent}
          registerTrigger={registerTrigger}
          tagBadgesByDayKey={tagBadgesByDayKey}
          tagMetaById={tagMetaById}
        />
      </div>
      <EventPanel event={selectedEvent} open={Boolean(selectedEvent)} onClose={handleClosePanel} />
    </>
  );
};

export default CalendarPage;
