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
  createEvent('rec-2', 3, 16, 0, 90, {
    title: 'Evening Yoga in the Park',
    description: 'Gentle flow yoga session suitable for all levels, held outdoors in the park.',
    location: 'Riverside Park Plaza',
    category: 'rec',
    tags: ['rec'],
    organizer: 'City Parks & Wellness'
  }),
  createEvent('civic-2', 6, 10, 0, 60, {
    title: 'Community Coffee Hour',
    description: 'Informal gathering to discuss neighborhood concerns and meet your neighbors.',
    location: 'Community Center Lobby',
    category: 'civic',
    tags: ['civic'],
    organizer: '5th Ward Council'
  }),
  createEvent('tech-2', 12, 14, 30, 90, {
    title: 'Afternoon Coding Workshop',
    description: 'Hands-on session for beginners to learn web development basics.',
    location: 'Innovation Hub, 2nd Floor Classroom',
    category: 'tech',
    tags: ['tech'],
    organizer: 'Midtown Tech Guild'
  }),
  createEvent('music-1', 12, 20, 0, 90, {
    title: 'Moonlit Music on the Green',
    description: 'Open-air performances from local ensembles with projection art and light installations.',
    location: 'Harborview Amphitheater',
    category: 'music',
    tags: ['music', 'arts', 'rec'],
    organizer: 'Sound & Shore Collective'
  }),
  createEvent('arts-1', 5, 19, 0, 120, {
    title: 'Community Art Gallery Opening',
    description: 'Celebrate local artists with refreshments and live demonstrations.',
    location: 'Downtown Arts Center',
    category: 'arts',
    tags: ['arts', 'rec'],
    organizer: 'Downtown Arts Collective'
  }),
  createEvent('kids-1', 8, 10, 30, 90, {
    title: 'Storytime & Crafts for Kids',
    description: 'Interactive storytelling followed by a themed craft activity for children ages 4-10.',
    location: 'Downtown Library Children\'s Room',
    category: 'library',
    tags: ['library', 'kids'],
    organizer: 'Downtown Library Association'
  }),
  createEvent('volunteer-2', 10, 9, 0, 180, {
    title: 'Beach Cleanup Day',
    description: 'Join fellow volunteers to clean up the shoreline and protect local wildlife.',
    location: 'Harborview Beach',
    category: 'volunteer',
    tags: ['volunteer', 'rec'],
    organizer: 'Coastal Conservation Group'
  }),
  createEvent('market-2', 17, 8, 0, 180, {
    title: 'Artisan Craft Market',
    description: 'Local artisans showcase handmade jewelry, pottery, textiles, and more.',
    location: 'Historic Market Square',
    category: 'market',
    tags: ['market', 'arts'],
    organizer: 'Artisan Market Guild'
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
