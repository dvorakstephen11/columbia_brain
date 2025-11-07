import { buildTagMask, tagIndexById, tagMetaById } from './tags';

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

const baseEvents = [
  createEvent('market-1', 3, 9, 0, 120, {
    title: 'Riverside Farmers Market',
    description: 'Browse seasonal produce, artisan breads, and small-batch goods from local growers.',
    location: 'Riverside Park Plaza',
    category: 'market',
    tags: ['market', 'civic', 'rec'],
    organizer: 'City Markets Cooperative'
  }),
  createEvent('civic-1', 6, 18, 30, 90, {
    title: 'Neighborhood Council Forum',
    description: 'Discuss upcoming zoning updates and community initiatives with council members.',
    location: 'Civic Hall Auditorium',
    category: 'civic',
    tags: ['civic', 'volunteer'],
    organizer: '5th Ward Council'
  }),
  createEvent('tech-1', 11, 12, 0, 75, {
    title: 'Lunchtime Tech Talk: Intro to Web Accessibility',
    description: 'A friendly primer on building inclusive interfaces, led by local accessibility advocates.',
    location: 'Innovation Hub, 3rd Floor Lab',
    category: 'tech',
    tags: ['tech', 'maker', 'civic'],
    organizer: 'Midtown Tech Guild'
  }),
  createEvent('rec-1', 15, 7, 30, 60, {
    title: 'Sunrise Mindful Movement',
    description: 'An easy-going blend of stretching and breathing to welcome the day beside the gardens.',
    location: 'Botanical Conservatory Lawn',
    category: 'rec',
    tags: ['rec', 'kids'],
    organizer: 'City Parks & Wellness'
  }),
  createEvent('volunteer-1', 19, 10, 0, 150, {
    title: 'Community Garden Volunteer Day',
    description: 'Help refresh garden beds, plant pollinator flowers, and connect with fellow volunteers.',
    location: 'Maple & 9th Community Garden',
    category: 'volunteer',
    tags: ['volunteer', 'rec', 'civic'],
    organizer: 'Green Sprouts Collective'
  }),
  createEvent('maker-1', 24, 17, 0, 120, {
    title: 'Makerspace Open Build Night',
    description: 'Bring a project or collaborate on group builds with access to tools and mentors.',
    location: 'Foundry Makerspace',
    category: 'maker',
    tags: ['maker', 'tech', 'arts'],
    organizer: 'Foundry Mentors'
  }),
  createEvent('library-1', 28, 14, 0, 60, {
    title: 'Library Author Spotlight: Voices of the River',
    description: 'A moderated discussion with local authors exploring storytelling and place.',
    location: 'Downtown Library Reading Room',
    category: 'library',
    tags: ['library', 'kids', 'arts'],
    organizer: 'Downtown Library Association'
  }),
  createEvent('music-1', 12, 20, 0, 90, {
    title: 'Moonlit Music on the Green',
    description: 'Open-air performances from local ensembles with projection art and light installations.',
    location: 'Harborview Amphitheater',
    category: 'music',
    tags: ['music', 'arts', 'rec'],
    organizer: 'Sound & Shore Collective'
  })
];

const sanitizeTags = (tags = [], category) => {
  const normalized = new Set(category ? [category, ...tags] : tags);
  return Array.from(normalized).filter((tagId) => typeof tagIndexById[tagId] === 'number');
};

export const mockEvents = baseEvents.map((event) => {
  const tags = sanitizeTags(event.tags, event.category);
  return {
    ...event,
    tags,
    tagMask: buildTagMask(tags),
    categoryMeta: tagMetaById[event.category] ?? null
  };
});

export const getEventCategoryMeta = (category) => tagMetaById[category] ?? null;
