import React from 'react';
import { Box, Typography, TextField, Chip, Autocomplete } from '@mui/material';

interface FieldSelectorProps {
  availableFields: string[];
  selectedFields: string[];
  onFieldSelection: (event: React.SyntheticEvent, value: string[]) => void;
}

const FieldSelector: React.FC<FieldSelectorProps> = ({
  availableFields,
  selectedFields,
  onFieldSelection
}) => {
  return (
    <Box sx={{ mb: 3 }}>
      <Typography variant="subtitle1" gutterBottom>
        Fields to Include
      </Typography>
      <Autocomplete
        multiple
        options={availableFields}
        value={selectedFields}
        onChange={onFieldSelection}
        renderInput={(params) => (
          <TextField
            {...params}
            variant="outlined"
            placeholder="Select fields to include"
          />
        )}
        renderTags={(value, getTagProps) =>
          value.map((option, index) => (
            <Chip
              variant="outlined"
              label={option}
              {...getTagProps({ index })}
            />
          ))
        }
      />
    </Box>
  );
};

export default FieldSelector;
