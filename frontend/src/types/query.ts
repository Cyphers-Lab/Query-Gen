export interface KQLTable {
  TableName: string;
  Purpose: string;
  KeyScenarios: string[];
  Fields: string[];
}

export interface TimeFilter {
  enabled: boolean;
  value: number;
  unit: TimeUnit;
}

export interface Filter {
  field: string;
  operator: string;
  value: string;
}

export interface QueryState {
  table: KQLTable | null;
  timeFilter: TimeFilter;
  filters: Filter[];
  customQuery: string;
  sortBy: {
    field: string;
    order: 'asc' | 'desc';
  };
  selectedFields: string[];
}

export type TimeUnit = 'h' | 'd' | 'm';

export interface TimeUnitOption {
  value: TimeUnit;
  label: string;
}

export interface QueryTemplate {
  name: string;
  query: string;
  category: string;
  description?: string;
}
