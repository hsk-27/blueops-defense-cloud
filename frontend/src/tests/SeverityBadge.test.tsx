import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';

describe('SOC Badges', () => {
  it('renders critical severity badge correctly', () => {
    render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText('CRITICAL')).toBeDefined();
  });

  it('renders status badge correctly', () => {
    render(<StatusBadge status="INVESTIGATING" />);
    expect(screen.getByText('INVESTIGATING')).toBeDefined();
  });
});
