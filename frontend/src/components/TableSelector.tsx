import React from 'react';
import { Autocomplete, TextField, Card, CardContent, Typography, Box, Chip } from '@mui/material';
import { KQLTable } from '../types/query';

interface TableSelectorProps {
  tables: KQLTable[];
  selectedTable: KQLTable | null;
  onTableChange: (table: KQLTable | null) => void;
  onFieldClick?: (field: string) => void;
}

const TableSelector: React.FC<TableSelectorProps> = ({
  tables,
  selectedTable,
  onTableChange,
  onFieldClick
}) => {
  const handleChange = (_event: any, newValue: KQLTable | null) => {
    onTableChange(newValue);
  };

  return (
    <>
      <Autocomplete
        fullWidth
        options={tables}
        getOptionLabel={(option) => option.TableName}
        value={selectedTable}
        onChange={handleChange}
        renderInput={(params) => (
          <TextField
            {...params}
            label="Select Table"
            margin="normal"
          />
        )}
      />

      {selectedTable && (
        <Card sx={{ mb: 2, mt: 2 }}>
          <CardContent>
            <Typography variant="subtitle1" color="primary" gutterBottom>
              Table Information
            </Typography>
            <Typography variant="body2" gutterBottom>
              <strong>Purpose:</strong> {selectedTable.Purpose}
            </Typography>
            <Typography variant="body2" gutterBottom>
              <strong>Key Scenarios:</strong>
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
              {selectedTable.KeyScenarios.map((scenario, index) => (
                <Chip key={index} label={scenario} size="small" />
              ))}
            </Box>
            <Typography variant="body2" gutterBottom>
              <strong>Available Fields:</strong>
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {selectedTable.Fields.map((field, index) => (
                <Chip
                  key={index}
                  label={field}
                  size="small"
                  variant="outlined"
                  onClick={() => onFieldClick?.(field)}
                />
              ))}
            </Box>
          </CardContent>
        </Card>
      )}
    </>
  );
};

export default TableSelector;
