import React, { useId } from 'react';

import { tagIndexById } from '@/data/tags';

const MATCH_OPTIONS = [
  { value: 'any', label: 'Match ANY' },
  { value: 'all', label: 'Match ALL' }
];

const TagFilterBar = ({
  tags,
  tagMetaById,
  monthTotalsByTag,
  selectedMask,
  matchMode,
  onToggleTag,
  onClearAll,
  onSetMatchMode
}) => {
  const headingId = useId();

  return (
    <section className="tag-filter-bar">
      <div
        className="tag-filter-bar__toolbar"
        role="toolbar"
        aria-labelledby={headingId}
        aria-controls="calendar"
      >
        <h3 id={headingId} className="tag-filter-bar__heading">
          Filter by tags
        </h3>
        <div className="tag-filter-bar__pills">
          {tags.map((tagId) => {
            const meta = tagMetaById[tagId];
            const tagIndex = tagIndexById[tagId];
            const isSelected =
              typeof tagIndex === 'number' ? (selectedMask & (1 << tagIndex)) !== 0 : false;
            const count =
              typeof tagIndex === 'number' && monthTotalsByTag ? monthTotalsByTag[tagIndex] ?? 0 : 0;
            const ariaLabelParts = [
              meta?.label ?? tagId,
              `${count} event${count === 1 ? '' : 's'} this month`
            ];
            if (isSelected) {
              ariaLabelParts.push('active filter');
            }
            const customProperties = {
              '--tag-pill-bg': meta?.color,
              '--tag-pill-text': meta?.textColor,
              '--tag-pill-ring': meta?.ringColor,
              '--tag-pill-indicator-color': meta?.textColor
            };
            return (
              <button
                key={tagId}
                type="button"
                className={`tag-pill${isSelected ? ' tag-pill--selected' : ''}`}
                style={customProperties}
                aria-pressed={isSelected}
                aria-label={ariaLabelParts.join(', ')}
                onClick={() => onToggleTag(tagId)}
              >
                <span className="tag-pill__indicator" aria-hidden="true">
                  {isSelected ? (
                    <svg className="tag-pill__check" viewBox="0 0 12 12" focusable="false">
                      <path d="M10.28 3.22a.75.75 0 0 0-1.06-1.06L4.75 6.63 3.28 5.16a.75.75 0 0 0-1.06 1.06l2 2a.75.75 0 0 0 1.08-.02l5-5Z" />
                    </svg>
                  ) : (
                    <span className="tag-pill__dot" />
                  )}
                </span>
                <span className="tag-pill__label">{meta?.label ?? tagId}</span>
                <span className="tag-pill__count">{count}</span>
              </button>
            );
          })}
        </div>
        <div className="tag-filter-bar__actions">
          <div className="match-toggle" role="radiogroup" aria-label="Filter match mode">
            {MATCH_OPTIONS.map((option) => {
              const isActive = option.value === matchMode;
              return (
                <button
                  key={option.value}
                  type="button"
                  className={`match-toggle__button${
                    isActive ? ' match-toggle__button--active' : ''
                  }`}
                  role="radio"
                  aria-checked={isActive}
                  onClick={() => onSetMatchMode(option.value)}
                >
                  {option.label}
                </button>
              );
            })}
          </div>
          {selectedMask !== 0 && (
            <button
              type="button"
              className="tag-filter-bar__clear"
              onClick={onClearAll}
              aria-label="Clear selected tags"
            >
              Clear
            </button>
          )}
        </div>
      </div>
    </section>
  );
};

export default React.memo(TagFilterBar);
