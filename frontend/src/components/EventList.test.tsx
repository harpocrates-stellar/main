import React from 'react';
import { render, screen } from '@testing-library/react';
import {} from 'vitest';
import EventList, { Event } from './EventList';

describe('EventList', () => {
  it('renders the ISO string for a valid claimed time', () => {
    const events: Event[] = [
      {
        id: 'valid',
        title: 'Valid event',
        time_attestation: {
          claimedTime: { unixMs: 1700000000000 },
          observedTime: { unixMs: 1700000000000 },
        },
      },
    ];

    render(<EventList events={events} />);

    const expected = new Date(1700000000000).toISOString();
    expect(screen.getAllByText(expected).length).toBe(2);
  });

  it('renders a placeholder for a non-finite claimed time', () => {
    const events: Event[] = [
      {
        id: 'invalid',
        title: 'Invalid event',
        time_attestation: {
          claimedTime: { unixMs: NaN },
          observedTime: null,
        },
      },
    ];

    render(<EventList events={events} />);

    expect(screen.getByText('invalid time')).toBeTruthy();
  });
});
