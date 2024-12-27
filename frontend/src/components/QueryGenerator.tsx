import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  TextField,
  Button,
  Paper,
  Grid,
  Typography
} from '@mui/material';
import kqlData from '../queryLangs.json';
import { QueryState, KQLTable, QueryTemplate } from '../types/query';
import TableSelector from './TableSelector';
import TimeFilterSection from './TimeFilterSection';
import FilterSection from './FilterSection';
import TemplateSection from './TemplateSection';
import QueryOutput from './QueryOutput';
import FieldSelector from './FieldSelector';

const QueryGenerator: React.FC = () => {
  const [queryState, setQueryState] = useState<QueryState>({
    table: null,
    timeFilter: {
      enabled: false,
      value: 7,
      unit: 'd'
    },
    filters: [],
    customQuery: '',
    sortBy: {
      field: 'TimeGenerated',
      order: 'desc'
    },
    selectedFields: []
  });

  const [tables, setTables] = useState<KQLTable[]>([]);
  const [generatedQuery, setGeneratedQuery] = useState<string>('');

  useEffect(() => {
    setTables(kqlData.KQLtables);
  }, []);

  const handleTableChange = (newTable: KQLTable | null) => {
    setQueryState(prev => ({
      ...prev,
      table: newTable,
      selectedFields: []
    }));
  };

  const handleTimeFilterChange = (timeFilter: typeof queryState.timeFilter) => {
    setQueryState(prev => ({
      ...prev,
      timeFilter
    }));
  };

  const handleFilterChange = (filters: typeof queryState.filters) => {
    setQueryState(prev => ({
      ...prev,
      filters
    }));
  };

  const handleFieldSelection = (_event: React.SyntheticEvent, value: string[]) => {
    setQueryState(prev => ({
      ...prev,
      selectedFields: value,
    }));
  };

  const outputRef = useRef<HTMLDivElement>(null);

  const handleTemplateSelect = (template: QueryTemplate) => {
    setQueryState(prev => ({
      ...prev,
      customQuery: template.query,
    }));
    setGeneratedQuery(template.query);
    setTimeout(() => {
      outputRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  const handleCustomQueryChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setQueryState(prev => ({
      ...prev,
      customQuery: event.target.value,
    }));
  };

  const generateQuery = () => {
    if (queryState.customQuery) {
      setGeneratedQuery(queryState.customQuery);
      return;
    }

    let query = queryState.table?.TableName || '';

    // Add time filter
    if (queryState.timeFilter.enabled) {
      query += `\n| where TimeGenerated > ago(${queryState.timeFilter.value}${queryState.timeFilter.unit})`;
    }

    // Add filters
    queryState.filters.forEach(filter => {
      if (filter.field && filter.operator && filter.value) {
        query += `\n| where ${filter.field} ${filter.operator} ${filter.value.includes('"') ? filter.value : `"${filter.value}"`}`;
      }
    });

    // Add field projection
    if (queryState.selectedFields.length > 0) {
      query += `\n| project ${queryState.selectedFields.join(', ')}`;
    }

    // Add sorting
    if (queryState.sortBy.field) {
      query += `\n| sort by ${queryState.sortBy.field} ${queryState.sortBy.order}`;
    }

    setGeneratedQuery(query);
  };

  return (
    <Box sx={{ mt: 3 }}>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Query Builder
            </Typography>

            <TableSelector
              tables={tables}
              selectedTable={queryState.table}
              onTableChange={handleTableChange}
              onFieldClick={() => {
                if (queryState.filters.length === 0) {
                  handleFilterChange([{ field: '', operator: '==', value: '' }]);
                }
              }}
            />

            <TemplateSection onTemplateSelect={handleTemplateSelect} />

            <TimeFilterSection
              timeFilter={queryState.timeFilter}
              onTimeFilterChange={handleTimeFilterChange}
            />

            {queryState.table && (
              <FieldSelector
                availableFields={queryState.table.Fields}
                selectedFields={queryState.selectedFields}
                onFieldSelection={handleFieldSelection}
              />
            )}

            <FilterSection
              filters={queryState.filters}
              availableFields={queryState.table?.Fields || []}
              onFilterChange={handleFilterChange}
            />

            <TextField
              fullWidth
              label="Custom Query (Optional)"
              value={queryState.customQuery}
              onChange={handleCustomQueryChange}
              margin="normal"
              multiline
              rows={3}
              helperText="Enter a custom query or use the builder above"
            />

            <Button
              variant="contained"
              color="primary"
              onClick={generateQuery}
              fullWidth
              sx={{ mt: 2 }}
            >
              Generate Query
            </Button>
          </Paper>
        </Grid>

        <Grid item xs={12} ref={outputRef}>
          <QueryOutput query={generatedQuery} />
        </Grid>
      </Grid>
    </Box>
  );
};

export default QueryGenerator;
