import React from 'react';
import { Box, TextField, Typography, Autocomplete } from '@mui/material';
import { TimeFilter, TimeUnitOption } from '../types/query';
import { timeUnits } from '../data/queryTemplates';

interface TimeFilterSectionProps {
  timeFilter: TimeFilter;
  onTimeFilterChange: (timeFilter: TimeFilter) => void;
}

const TimeFilterSection: React.FC<TimeFilterSectionProps> = ({
  timeFilter,
  onTimeFilterChange
}) => {
  const handleValueChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    onTimeFilterChange({
      ...timeFilter,
      value: Number(event.target.value)
    });
  };

  const handleUnitChange = (_event: React.SyntheticEvent, newValue: TimeUnitOption | null) => {
    if (newValue) {
      onTimeFilterChange({
        ...timeFilter,
        unit: newValue.value
      });
    }
  };

  const handleEnabledChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    onTimeFilterChange({
      ...timeFilter,
      enabled: event.target.checked
    });
  };

  return (
    <Box sx={{ mb: 3 }}>
      <Typography variant="subtitle1" gutterBottom>
        Time Filter
      </Typography>
      <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <input
            type="checkbox"
            checked={timeFilter.enabled}
            onChange={handleEnabledChange}
            style={{ marginRight: '8px' }}
          />
          <Typography variant="body2">Enable time filter</Typography>
        </Box>
        <TextField
          type="number"
          label="Time Value"
          value={timeFilter.value}
          onChange={handleValueChange}
          disabled={!timeFilter.enabled}
          sx={{ width: 120 }}
        />
        <Autocomplete<TimeUnitOption, false>
          options={timeUnits}
          getOptionLabel={(option) => option.label}
          value={timeUnits.find(unit => unit.value === timeFilter.unit) || null}
          onChange={handleUnitChange}
          disabled={!timeFilter.enabled}
          sx={{ width: 120 }}
          renderInput={(params) => (
            <TextField {...params} label="Unit" />
          )}
        />
      </Box>
    </Box>
  );
};

export default TimeFilterSection;
