const WEEKDAY_FORMATTER = new Intl.DateTimeFormat(undefined, {
  weekday: 'short'
});

const MONTH_FORMATTER = new Intl.DateTimeFormat(undefined, {
  month: 'long',
  year: 'numeric'
});

const DAY_NUMBER_FORMATTER = new Intl.DateTimeFormat(undefined, {
  day: 'numeric'
});

const TIME_FORMATTER = new Intl.DateTimeFormat(undefined, {
  hour: 'numeric',
  minute: '2-digit'
});

export const getWeekdayLabels = () => {
  const baseSunday = new Date(Date.UTC(2023, 0, 1));
  return Array.from({ length: 7 }, (_, index) => {
    const date = new Date(baseSunday);
    date.setUTCDate(baseSunday.getUTCDate() + index);
    return WEEKDAY_FORMATTER.format(date);
  });
};

export const getMonthLabel = (date) => MONTH_FORMATTER.format(date);

export const isSameDay = (a, b) =>
  a.getFullYear() === b.getFullYear() &&
  a.getMonth() === b.getMonth() &&
  a.getDate() === b.getDate();

const startOfMonth = (date) => new Date(date.getFullYear(), date.getMonth(), 1);
const endOfMonth = (date) => new Date(date.getFullYear(), date.getMonth() + 1, 0);

export const generateMonthGrid = (date = new Date()) => {
  const firstOfMonth = startOfMonth(date);
  const lastOfMonth = endOfMonth(date);
  const startDay = new Date(firstOfMonth);
  startDay.setDate(firstOfMonth.getDate() - firstOfMonth.getDay());

  const endDay = new Date(lastOfMonth);
  endDay.setDate(lastOfMonth.getDate() + (6 - lastOfMonth.getDay()));

  const days = [];
  const current = new Date(startDay);
  const today = new Date();

  while (days.length < 42) {
    days.push({
      date: new Date(current),
      iso: current.toISOString(),
      isCurrentMonth:
        current.getMonth() === date.getMonth() && current.getFullYear() === date.getFullYear(),
      isToday: isSameDay(current, today)
    });
    current.setDate(current.getDate() + 1);
  }

  return days;
};

export const formatDayNumber = (date) => DAY_NUMBER_FORMATTER.format(date);

export const formatTimeRange = (start, end) => `${TIME_FORMATTER.format(start)} – ${TIME_FORMATTER.format(end)}`;

export const getAccessibleDayLabel = (date, { isToday = false } = {}) => {
  const formatter = new Intl.DateTimeFormat(undefined, {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    year: 'numeric'
  });
  const base = formatter.format(date);
  return isToday ? `${base}, Today` : base;
};
