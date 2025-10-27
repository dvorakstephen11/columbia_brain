const categories = {
  market: { label: 'Market', color: '#dbeafe', textColor: '#1d4ed8' },
  civic: { label: 'Civic', color: '#fef3c7', textColor: '#b45309' },
  tech: { label: 'Tech', color: '#ede9fe', textColor: '#6d28d9' },
  rec: { label: 'Recreation', color: '#dcfce7', textColor: '#047857' },
  volunteer: { label: 'Volunteer', color: '#fee2e2', textColor: '#b91c1c' },
  maker: { label: 'Maker', color: '#fff1f2', textColor: '#be123c' },
  library: { label: 'Library', color: '#fdf2f8', textColor: '#a21caf' }
};

const current = new Date();
const currentMonth = current.getMonth();
const currentYear = current.getFullYear();

const createDateTime = (dayOfMonth, hour, minute = 0) =>
  new Date(currentYear, currentMonth, dayOfMonth, hour, minute);

const createEvent = (id, day, startHour, startMinute, durationMinutes, overrides) => {
  const startsAt = createDateTime(day, startHour, startMinute);
  const endsAt = new Date(startsAt.getTime() + durationMinutes * 60 * 1000);
  return {
    id,
    startsAt,
    endsAt,
    ...overrides
  };
};

export const mockEvents = [
  createEvent('market-1', 3, 9, 0, 120, {
    title: 'Riverside Farmers Market',
    description: 'Browse seasonal produce, artisan breads, and small-batch goods from local growers.',
    location: 'Riverside Park Plaza',
    category: 'market',
    organizer: 'City Markets Cooperative'
  }),
  createEvent('civic-1', 6, 18, 30, 90, {
    title: 'Neighborhood Council Forum',
    description: 'Discuss upcoming zoning updates and community initiatives with council members.',
    location: 'Civic Hall Auditorium',
    category: 'civic',
    organizer: '5th Ward Council'
  }),
  createEvent('tech-1', 11, 12, 0, 75, {
    title: 'Lunchtime Tech Talk: Intro to Web Accessibility',
    description: 'A friendly primer on building inclusive interfaces, led by local accessibility advocates.',
    location: 'Innovation Hub, 3rd Floor Lab',
    category: 'tech',
    organizer: 'Midtown Tech Guild'
  }),
  createEvent('rec-1', 15, 7, 30, 60, {
    title: 'Sunrise Mindful Movement',
    description: 'An easy-going blend of stretching and breathing to welcome the day beside the gardens.',
    location: 'Botanical Conservatory Lawn',
    category: 'rec',
    organizer: 'City Parks & Wellness'
  }),
  createEvent('volunteer-1', 19, 10, 0, 150, {
    title: 'Community Garden Volunteer Day',
    description: 'Help refresh garden beds, plant pollinator flowers, and connect with fellow volunteers.',
    location: 'Maple & 9th Community Garden',
    category: 'volunteer',
    organizer: 'Green Sprouts Collective'
  }),
  createEvent('maker-1', 24, 17, 0, 120, {
    title: 'Makerspace Open Build Night',
    description: 'Bring a project or collaborate on group builds with access to tools and mentors.',
    location: 'Foundry Makerspace',
    category: 'maker',
    organizer: 'Foundry Mentors'
  }),
  createEvent('library-1', 28, 14, 0, 60, {
    title: 'Library Author Spotlight: Voices of the River',
    description: 'A moderated discussion with local authors exploring storytelling and place.',
    location: 'Downtown Library Reading Room',
    category: 'library',
    organizer: 'Downtown Library Association'
  })
].map((event) => ({
  ...event,
  categoryMeta: categories[event.category] ?? null
}));

export const getEventCategoryMeta = (category) => categories[category] ?? null;
