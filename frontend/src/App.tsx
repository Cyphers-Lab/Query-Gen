import React from 'react';
import { Box, Container, Typography } from '@mui/material';
import QueryGenerator from './components/QueryGenerator';

const App: React.FC = () => {
  return (
    <Container maxWidth="lg">
      <Box sx={{ my: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom align="center">
          KQL Query Generator
        </Typography>
        <QueryGenerator />
      </Box>
    </Container>
  );
};

export default App;
