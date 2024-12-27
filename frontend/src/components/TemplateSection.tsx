import React from 'react';
import { Box, Typography, Chip } from '@mui/material';
import { QueryTemplate } from '../types/query';
import { commonTemplates } from '../data/queryTemplates';

interface TemplateSectionProps {
  onTemplateSelect: (template: QueryTemplate) => void;
}

const TemplateSection: React.FC<TemplateSectionProps> = ({ onTemplateSelect }) => {
  // Get unique categories
  const categories = Array.from(new Set(commonTemplates.map(t => t.category)));

  return (
    <Box sx={{ mb: 3 }}>
      <Typography variant="subtitle1" gutterBottom>
        Query Templates
      </Typography>
      {categories.map(category => (
        <Box key={category} sx={{ mb: 2 }}>
          <Typography variant="subtitle2" color="primary" gutterBottom sx={{ mt: 2 }}>
            {category}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            {commonTemplates
              .filter(t => t.category === category)
              .map((template, index) => (
                <Chip
                  key={index}
                  label={template.name}
                  onClick={() => onTemplateSelect(template)}
                  variant="outlined"
                  sx={{ mb: 1 }}
                  title={template.description}
                />
              ))}
          </Box>
        </Box>
      ))}
    </Box>
  );
};

export default TemplateSection;
