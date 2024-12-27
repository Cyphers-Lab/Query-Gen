import React from 'react';
import { Paper, Typography, TextField } from '@mui/material';

interface QueryOutputProps {
  query: string;
}

const QueryOutput: React.FC<QueryOutputProps> = ({ query }) => {
  if (!query) return null;

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        Generated Query
      </Typography>
      <TextField
        fullWidth
        value={query}
        multiline
        rows={4}
        InputProps={{
          readOnly: true,
        }}
      />
    </Paper>
  );
};

export default QueryOutput;
