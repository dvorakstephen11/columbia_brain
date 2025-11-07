const TAGS = [
  'market',
  'civic',
  'tech',
  'rec',
  'volunteer',
  'maker',
  'library',
  'kids',
  'music',
  'arts'
];

const tagMetaById = {
  market: {
    id: 'market',
    label: 'Market',
    color: '#dbeafe',
    textColor: '#1d4ed8',
    ringColor: 'rgba(29, 78, 216, 0.24)'
  },
  civic: {
    id: 'civic',
    label: 'Civic',
    color: '#fef3c7',
    textColor: '#b45309',
    ringColor: 'rgba(180, 83, 9, 0.2)'
  },
  tech: {
    id: 'tech',
    label: 'Tech',
    color: '#ede9fe',
    textColor: '#6d28d9',
    ringColor: 'rgba(109, 40, 217, 0.22)'
  },
  rec: {
    id: 'rec',
    label: 'Recreation',
    color: '#dcfce7',
    textColor: '#047857',
    ringColor: 'rgba(4, 120, 87, 0.22)'
  },
  volunteer: {
    id: 'volunteer',
    label: 'Volunteer',
    color: '#fee2e2',
    textColor: '#b91c1c',
    ringColor: 'rgba(185, 28, 28, 0.22)'
  },
  maker: {
    id: 'maker',
    label: 'Maker',
    color: '#fff1f2',
    textColor: '#be123c',
    ringColor: 'rgba(190, 18, 60, 0.18)'
  },
  library: {
    id: 'library',
    label: 'Library',
    color: '#fdf2f8',
    textColor: '#a21caf',
    ringColor: 'rgba(162, 28, 175, 0.2)'
  },
  kids: {
    id: 'kids',
    label: 'Kids & Family',
    color: '#fef9c3',
    textColor: '#854d0e',
    ringColor: 'rgba(133, 77, 14, 0.24)'
  },
  music: {
    id: 'music',
    label: 'Music',
    color: '#e0f2fe',
    textColor: '#0369a1',
    ringColor: 'rgba(3, 105, 161, 0.22)'
  },
  arts: {
    id: 'arts',
    label: 'Arts',
    color: '#fce7f3',
    textColor: '#9d174d',
    ringColor: 'rgba(157, 23, 77, 0.2)'
  }
};

const tagIndexById = TAGS.reduce((acc, tagId, index) => {
  acc[tagId] = index;
  return acc;
}, {});

const buildTagMask = (tags, indexMap = tagIndexById) => {
  if (!Array.isArray(tags)) return 0;
  let mask = 0;
  tags.forEach((tagId) => {
    const tagIndex = indexMap[tagId];
    if (typeof tagIndex === 'number') {
      mask |= 1 << tagIndex;
    }
  });
  return mask;
};

const getTagIndicesFromMask = (mask) => {
  if (!mask) return [];
  const indices = [];
  let bitIndex = 0;
  let value = mask;
  while (value > 0) {
    if ((value & 1) === 1) {
      indices.push(bitIndex);
    }
    value >>= 1;
    bitIndex += 1;
  }
  return indices;
};

export { TAGS, tagMetaById, tagIndexById, buildTagMask, getTagIndicesFromMask };
