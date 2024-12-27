import React from 'react';
import { Box, TextField, Button, Autocomplete } from '@mui/material';
import { Filter } from '../types/query';
import { operators } from '../data/queryTemplates';

interface FilterSectionProps {
  filters: Filter[];
  availableFields: string[];
  onFilterChange: (filters: Filter[]) => void;
}

const FilterSection: React.FC<FilterSectionProps> = ({
  filters,
  availableFields,
  onFilterChange
}) => {
  const handleFilterFieldChange = (index: number) => (
    _event: React.SyntheticEvent,
    value: string | null
  ) => {
    const newFilters = [...filters];
    newFilters[index] = {
      ...newFilters[index],
      field: value || ''
    };
    onFilterChange(newFilters);
  };

  const handleFilterOperatorChange = (index: number) => (
    _event: React.SyntheticEvent,
    value: string | null
  ) => {
    const newFilters = [...filters];
    newFilters[index] = {
      ...newFilters[index],
      operator: value || '=='
    };
    onFilterChange(newFilters);
  };

  const handleFilterValueChange = (index: number) => (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const newFilters = [...filters];
    newFilters[index] = {
      ...newFilters[index],
      value: event.target.value
    };
    onFilterChange(newFilters);
  };

  const addFilter = () => {
    onFilterChange([...filters, { field: '', operator: '==', value: '' }]);
  };

  const removeFilter = (index: number) => {
    onFilterChange(filters.filter((_, i) => i !== index));
  };

  return (
    <>
      {filters.map((filter, index) => (
        <Box key={index} sx={{ display: 'flex', gap: 1, mb: 2, alignItems: 'center' }}>
          <Autocomplete
            options={availableFields}
            value={filter.field}
            onChange={handleFilterFieldChange(index)}
            renderInput={(params) => (
              <TextField {...params} label="Field" sx={{ width: 200 }} />
            )}
          />
          <Autocomplete
            options={operators}
            value={filter.operator}
            onChange={handleFilterOperatorChange(index)}
            renderInput={(params) => (
              <TextField {...params} label="Operator" sx={{ width: 150 }} />
            )}
          />
          <TextField
            label="Value"
            value={filter.value}
            onChange={handleFilterValueChange(index)}
            sx={{ flexGrow: 1 }}
          />
          <Button
            variant="outlined"
            color="error"
            onClick={() => removeFilter(index)}
          >
            Remove
          </Button>
        </Box>
      ))}

      <Button variant="contained" onClick={addFilter} sx={{ mb: 2 }}>
        Add Filter
      </Button>
    </>
  );
};

export default FilterSection;
