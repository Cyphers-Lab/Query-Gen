# KQL Query Generator

A powerful web-based tool for generating Kusto Query Language (KQL) queries, designed specifically for security analysts and IT professionals working with Azure Monitor, Log Analytics, and Microsoft 365 Defender.

## Features

### 🎯 Interactive Query Building
- **Table Selection**: Choose from 20+ pre-configured tables covering various security domains
- **Field Selection**: Easily select relevant columns with detailed field descriptions
- **Time Filtering**: Add time-based filters with flexible units (minutes, hours, days)
- **Custom Filters**: Build complex filters with support for multiple operators
- **Sort & Order**: Control result ordering with customizable sort fields

### 📚 Pre-built Query Templates
40+ built-in query templates across multiple categories:
- Authentication & Sign-in Analysis
- Privileged Account Monitoring
- Suspicious Activity Detection
- Endpoint Security
- Network Security
- Data Protection
- Advanced Log Correlation
- Anomaly Detection
- Threat Hunting

### 🔍 Supported Data Sources
- Security Events (Windows logs)
- Azure Active Directory logs
- Microsoft 365 audit logs
- Azure Security Center alerts
- Network traffic logs
- DNS queries
- Endpoint security events
- And many more...

## Getting Started

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Query-Gen.git
cd Query-Gen/frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

The application will be available at `http://localhost:3000`

## Usage

1. **Select a Table**: Choose from available data sources like SecurityEvent, SignInLogs, etc.
2. **Choose Fields**: Select the columns you want in your query results
3. **Add Filters**:
   - Set time range (last X minutes/hours/days)
   - Add custom filters using available operators
4. **Use Templates**: Browse pre-built queries for common security scenarios
5. **Generate & Copy**: Get your KQL query and copy it to clipboard

## Technical Details

### Built With
- React 18
- TypeScript
- Material UI
- Axios for API calls

### Project Structure
```
frontend/
├── src/
│   ├── components/         # React components
│   ├── types/             # TypeScript interfaces
│   ├── data/              # Static data & templates
│   └── App.tsx            # Main application
```

### Key Components
- `TableSelector`: Data source selection with metadata
- `FieldSelector`: Column selection interface
- `FilterSection`: Custom filter builder
- `TimeFilterSection`: Time-based filtering
- `TemplateSection`: Pre-built query browser
- `QueryOutput`: Query display and copy functionality

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

- Built for security professionals working with Microsoft security products
- Inspired by the need for faster, more efficient KQL query creation
- Designed to support common security operations and threat hunting workflows
