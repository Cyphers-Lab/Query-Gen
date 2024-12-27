import React, { useState, useEffect } from 'react';
import {
  Box,
  TextField,
  Button,
  Paper,
  Grid,
  Typography,
  Autocomplete,
  Chip,
  Card,
  CardContent,
} from '@mui/material';
import kqlData from '../queryLangs.json';

interface KQLTable {
  TableName: string;
  Purpose: string;
  KeyScenarios: string[];
  Fields: string[];
}

interface TimeFilter {
  enabled: boolean;
  value: number;
  unit: 'h' | 'd' | 'm';
}

interface Filter {
  field: string;
  operator: string;
  value: string;
}

interface QueryState {
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

const operators = [
  '==', '!=', '>', '<', '>=', '<=', 'contains', 'startswith', 'endswith', 'in', 'matches regex'
];

type TimeUnit = 'h' | 'd' | 'm';

interface TimeUnitOption {
  value: TimeUnit;
  label: string;
}

const timeUnits: TimeUnitOption[] = [
  { value: 'h', label: 'Hours' },
  { value: 'd', label: 'Days' },
  { value: 'm', label: 'Minutes' }
];

interface QueryTemplate {
  name: string;
  query: string;
  category: string;
  description?: string;
}

const commonTemplates: QueryTemplate[] = [
  // Authentication and Sign-In Logs
  {
    name: 'Failed Login Attempts',
    category: 'Authentication',
    description: 'Shows all failed login attempts with details',
    query: 'SigninLogs\n| where ResultType != "0"\n| project TimeGenerated, UserPrincipalName, ResultType, IPAddress, Location\n| sort by TimeGenerated desc'
  },
  {
    name: 'Multiple Failed Logins from IP',
    category: 'Authentication',
    description: 'Detects multiple failed login attempts from the same IP',
    query: 'SigninLogs\n| where ResultType != "0"\n| summarize FailureCount = count() by IPAddress, bin(TimeGenerated, 1h)\n| where FailureCount > 10'
  },
  {
    name: 'Suspicious Countries Login',
    category: 'Authentication',
    description: 'Shows logins from suspicious countries',
    query: 'SigninLogs\n| where Location in ("Russia", "North Korea", "Iran")'
  },
  {
    name: 'Failed MFA Attempts',
    category: 'Authentication',
    description: 'Shows failed multi-factor authentication attempts',
    query: 'SigninLogs\n| where ConditionalAccessStatus == "Failure"'
  },
  {
    name: 'First Time Logins',
    category: 'Authentication',
    description: 'Identifies first-time login for each user',
    query: 'SigninLogs\n| summarize FirstLogin = min(TimeGenerated) by UserPrincipalName'
  },
  
  // Privileged Account Activity
  {
    name: 'Privileged Role Changes',
    category: 'Privileged Access',
    description: 'Monitors privileged role assignments',
    query: 'AuditLogs\n| where OperationName == "Add member to role"\n| project TimeGenerated, InitiatedBy, TargetResources, IPAddress'
  },
  {
    name: 'Admin Activities',
    category: 'Privileged Access',
    description: 'Shows all admin account activities',
    query: 'SigninLogs\n| where UserPrincipalName endswith "@admin.yourdomain.com"'
  },
  {
    name: 'Password Resets',
    category: 'Privileged Access',
    description: 'Shows all password reset activities',
    query: 'AuditLogs\n| where OperationName == "Reset user password"'
  },
  {
    name: 'Service Principal Activity',
    category: 'Privileged Access',
    description: 'Monitors service principal sign-ins',
    query: 'AADServicePrincipalSignInLogs\n| where AppDisplayName has "Microsoft Graph"'
  },
  
  // Suspicious Activity
  {
    name: 'Impossible Travel',
    category: 'Suspicious Activity',
    description: 'Detects logins from different locations in short time',
    query: 'SigninLogs\n| extend PreviousLocation = prev(Location, 1)\n| extend TravelTime = datetime_diff("minute", TimeGenerated, prev(TimeGenerated, 1))\n| where TravelTime > 60 and PreviousLocation != Location'
  },
  {
    name: 'Brute Force Detection',
    category: 'Suspicious Activity',
    description: 'Identifies potential brute force attempts',
    query: 'SigninLogs\n| where ResultType != "0"\n| summarize Attempts = count() by UserPrincipalName\n| where Attempts > 50'
  },
  {
    name: 'Multiple Country Logins',
    category: 'Suspicious Activity',
    description: 'Detects logins from multiple countries',
    query: 'SigninLogs\n| summarize CountryCount = dcount(Location) by UserPrincipalName, bin(TimeGenerated, 1h)\n| where CountryCount > 2'
  },
  {
    name: 'Unusual Login Hours',
    category: 'Suspicious Activity',
    description: 'Identifies logins during unusual hours',
    query: 'SigninLogs\n| summarize LoginCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)\n| where LoginCount > 1 and bin(TimeGenerated, 1h) not between (datetime(8:00:00) .. datetime(18:00:00))'
  },
  
  // Endpoint Security
  {
    name: 'Malware Detection',
    category: 'Endpoint Security',
    description: 'Shows detected malware across endpoints',
    query: 'SecurityEvent\n| where EventID == 1116'
  },
  {
    name: 'Suspicious PowerShell',
    category: 'Endpoint Security',
    description: 'Detects suspicious PowerShell executions',
    query: 'SecurityEvent\n| where EventID == 4688 and NewProcessName has "powershell.exe"\n| project TimeGenerated, Computer, User, NewProcessName, CommandLine'
  },
  {
    name: 'Disabled Antivirus',
    category: 'Endpoint Security',
    description: 'Detects when antivirus is disabled',
    query: 'SecurityEvent\n| where EventID == 5004'
  },
  {
    name: 'Unusual Process Count',
    category: 'Endpoint Security',
    description: 'Identifies unusual number of processes',
    query: 'SecurityEvent\n| where EventID == 4688\n| summarize ProcessCount = count() by Computer, bin(TimeGenerated, 1h)\n| where ProcessCount > 100'
  },
  
  // Network Security
  {
    name: 'Port Scanning Detection',
    category: 'Network Security',
    description: 'Identifies potential port scanning activity',
    query: 'NetworkEvents\n| summarize PortCount = dcount(DestinationPort) by SourceIP, bin(TimeGenerated, 1h)\n| where PortCount > 50'
  },
  {
    name: 'Unusual Outbound Traffic',
    category: 'Network Security',
    description: 'Shows unusual outbound network traffic',
    query: 'NetworkEvents\n| where DestinationIP !startswith "10."\n| summarize TrafficVolume = sum(BytesSent) by Computer'
  },
  {
    name: 'Rare DNS Queries',
    category: 'Network Security',
    description: 'Identifies queries to rare domains',
    query: 'DnsEvents\n| summarize QueryCount = count() by DomainName\n| where QueryCount < 3'
  },
  {
    name: 'High DNS Request Volume',
    category: 'Network Security',
    description: 'Shows systems with high DNS request volume',
    query: 'DnsEvents\n| summarize RequestCount = count() by Computer\n| where RequestCount > 1000'
  },
  
  // Data Protection
  {
    name: 'Large File Uploads',
    category: 'Data Protection',
    description: 'Detects large file upload activities',
    query: 'AuditLogs\n| where OperationName == "Upload"\n| summarize FileSizeSum = sum(FileSize) by UserPrincipalName\n| where FileSizeSum > 50000000'
  },
  {
    name: 'External Sharing',
    category: 'Data Protection',
    description: 'Monitors external document sharing',
    query: 'SharePointAuditLogs\n| where OperationName == "ExternalSharing"'
  },
  {
    name: 'External Email Forwards',
    category: 'Data Protection',
    description: 'Detects email forwarding to external addresses',
    query: 'ExchangeAuditLogs\n| where OperationName == "Set-Mailbox"\n| where ModifiedProperties has "ForwardingSMTPAddress"'
  },
  {
    name: 'Personal Storage Usage',
    category: 'Data Protection',
    description: 'Monitors usage of personal storage services',
    query: 'AuditLogs\n| where AppDisplayName has "Dropbox" or AppDisplayName has "Google Drive"'
  },

  // Endpoint Monitoring
  {
    name: 'Unsigned Executables',
    category: 'Endpoint Monitoring',
    description: 'Detects execution of unsigned executable files',
    query: 'SecurityEvent\n| where EventID == 4688 and NewProcessName endswith ".exe"\n| where SignatureStatus == "Unsigned"'
  },
  {
    name: 'New Service Installation',
    category: 'Endpoint Monitoring',
    description: 'Monitors newly installed services on endpoints',
    query: 'SecurityEvent\n| where EventID == 7045'
  },
  {
    name: 'High CPU Usage',
    category: 'Endpoint Monitoring',
    description: 'Alerts on instances of high CPU utilization',
    query: 'Perf\n| where CounterName == "% Processor Time"\n| where CounterValue > 90'
  },
  {
    name: 'Rare Port Access',
    category: 'Endpoint Monitoring',
    description: 'Identifies access to rarely used network ports',
    query: 'NetworkEvents\n| summarize PortAccessCount = count() by DestinationPort\n| where PortAccessCount < 5'
  },
  {
    name: 'Temp Folder Execution',
    category: 'Endpoint Monitoring',
    description: 'Detects processes running from temporary folders',
    query: 'SecurityEvent\n| where NewProcessName startswith "C:\\\\Users\\\\" and NewProcessName contains "\\\\Temp\\\\"'
  },

  // Advanced Log Correlation
  {
    name: 'Login and File Access Correlation',
    category: 'Advanced Log Correlation',
    description: 'Correlates login events with file access logs within 15 minutes',
    query: 'let LoginEvents = SigninLogs\n| where ResultType == "0"\n| project LoginTime = TimeGenerated, UserPrincipalName, IPAddress;\n\nlet FileAccessLogs = FileAuditLogs\n| project AccessTime = TimeGenerated, UserPrincipalName, FilePath, OperationName, IPAddress;\n\nLoginEvents\n| join kind=inner (FileAccessLogs) on UserPrincipalName\n| where abs(datetime_diff("minute", AccessTime, LoginTime)) < 15'
  },
  {
    name: 'Admin Lateral Movement',
    category: 'Advanced Log Correlation',
    description: 'Identifies potential lateral movement using admin accounts',
    query: 'let AdminLogins = SigninLogs\n| where UserPrincipalName in (admin_accounts_list)\n| project AdminIP = IPAddress, TimeGenerated;\n\nlet TargetLogons = SecurityEvent\n| where EventID == 4624 and LogonType == 3\n| project TargetIP = Computer, User, TimeGenerated;\n\nAdminLogins\n| join kind=inner (TargetLogons) on $left.AdminIP == $right.TargetIP'
  },
  {
    name: 'Abnormal User Activity',
    category: 'Advanced Log Correlation',
    description: 'Detects abnormal user activity across multiple systems',
    query: 'let UserSessions = SigninLogs\n| summarize LoginCount = count(), SystemsAccessed = dcount(DeviceDetail) by UserPrincipalName, bin(TimeGenerated, 1d)\n| where LoginCount > 50 or SystemsAccessed > 5;\n\nlet AdminActions = AuditLogs\n| summarize ActionCount = count() by UserPrincipalName, bin(TimeGenerated, 1d)\n| where ActionCount > 10;\n\nUserSessions\n| join kind=inner (AdminActions) on UserPrincipalName'
  },

  // Anomaly Detection
  {
    name: 'Login Pattern Deviation',
    category: 'Anomaly Detection',
    description: 'Detects unusual deviations in user login patterns',
    query: 'SigninLogs\n| summarize TotalLogins = count() by UserPrincipalName, bin(TimeGenerated, 1d)\n| extend AnomalyScore = log(abs(TotalLogins - avg(TotalLogins) over ())) / stdev(TotalLogins) over ()\n| where AnomalyScore > 3'
  },
  {
    name: 'Network Traffic Spikes',
    category: 'Anomaly Detection',
    description: 'Identifies network traffic spikes based on historical baselines',
    query: 'NetworkEvents\n| summarize TrafficVolume = sum(BytesTransferred) by bin(TimeGenerated, 1h)\n| join kind=inner (\n    NetworkEvents\n    | summarize Baseline = avg(BytesTransferred) by bin(TimeGenerated, 1d)\n) on $left.TimeGenerated == $right.TimeGenerated\n| extend Deviation = (TrafficVolume - Baseline) / Baseline\n| where Deviation > 0.5'
  },
  {
    name: 'Rare Process Execution',
    category: 'Anomaly Detection',
    description: 'Identifies rarely executed processes',
    query: 'SecurityEvent\n| where EventID == 4688\n| summarize ExecutionCount = count() by NewProcessName, bin(TimeGenerated, 1d)\n| where ExecutionCount < 5'
  },

  // Threat Hunting
  {
    name: 'Golden Ticket Detection',
    category: 'Threat Hunting',
    description: 'Detects potential Kerberos golden ticket attacks',
    query: 'SecurityEvent\n| where EventID == 4769\n| extend TGTValidation = tostring(parse_json(ExtendedProperties)["Ticket Encryption Type"])\n| where TGTValidation == "0x17"'
  },
  {
    name: 'High Volume DNS',
    category: 'Threat Hunting',
    description: 'Identifies suspiciously high volume of DNS requests',
    query: 'DnsEvents\n| summarize RequestCount = count() by ClientIP, DomainName, bin(TimeGenerated, 1h)\n| where RequestCount > 500'
  },
  {
    name: 'Credential Dumping Tools',
    category: 'Threat Hunting',
    description: 'Tracks usage of known credential dumping tools',
    query: 'SecurityEvent\n| where EventID == 4688 and CommandLine has_any("mimikatz", "proc_dump", "lsass")'
  },
  {
    name: 'New Startup Services',
    category: 'Threat Hunting',
    description: 'Monitors new service installations for persistence',
    query: 'SecurityEvent\n| where EventID == 7045\n| where ServiceName !contains "Microsoft"'
  },

  // Data Exfiltration
  {
    name: 'Unusual Outbound Traffic',
    category: 'Data Exfiltration',
    description: 'Detects unusual volume of outbound network traffic',
    query: 'NetworkEvents\n| summarize OutboundTraffic = sum(BytesTransferred) by SourceIP, bin(TimeGenerated, 1h)\n| extend Anomaly = OutboundTraffic > avg(OutboundTraffic) + 2 * stdev(OutboundTraffic)\n| where Anomaly'
  },
  {
    name: 'High Email Attachments',
    category: 'Data Exfiltration',
    description: 'Identifies high volume of email attachments',
    query: 'ExchangeAuditLogs\n| where OperationName == "Send"\n| summarize TotalAttachments = sum(AttachmentSize) by UserPrincipalName, bin(TimeGenerated, 1d)\n| where TotalAttachments > 100000000'
  },
  {
    name: 'Sensitive File Transfers',
    category: 'Data Exfiltration',
    description: 'Monitors sensitive file transfers to external recipients',
    query: 'FileAuditLogs\n| where FilePath contains "Sensitive"\n| where RecipientEmail endswith "@external.com"'
  },
  {
    name: 'Abnormal Downloads',
    category: 'Data Exfiltration',
    description: 'Detects abnormal file download patterns',
    query: 'FileAuditLogs\n| summarize TotalDownloads = count() by UserPrincipalName, bin(TimeGenerated, 1h)\n| extend DownloadDeviation = TotalDownloads - avg(TotalDownloads) over ()\n| where DownloadDeviation > 10'
  },

  // Malware Detection
  {
    name: 'Ransomware Behavior',
    category: 'Malware Detection',
    description: 'Identifies potential ransomware activity',
    query: 'SecurityEvent\n| where EventID == 4663 and ObjectName endswith ".key" or ObjectName endswith ".crypt"\n| summarize ModificationCount = count() by Computer, bin(TimeGenerated, 1h)\n| where ModificationCount > 1000'
  },
  {
    name: 'Suspicious Scripts',
    category: 'Malware Detection',
    description: 'Detects suspicious script execution patterns',
    query: 'SecurityEvent\n| where EventID == 4688 and (CommandLine has "base64" or CommandLine has "obfuscation")'
  },
  {
    name: 'Critical File Changes',
    category: 'Malware Detection',
    description: 'Monitors modifications to critical files',
    query: 'FileAuditLogs\n| where FilePath contains "Critical" and OperationName == "Modify"'
  },
  {
    name: 'Temp Folder Malware',
    category: 'Malware Detection',
    description: 'Detects malware execution from temporary folders',
    query: 'SecurityEvent\n| where EventID == 4688\n| where NewProcessName startswith "C:\\\\Users\\\\" and NewProcessName contains "\\\\Temp\\\\"'
  },

  // Multi-Event Correlation
  {
    name: 'Malicious DNS with Network Traffic',
    category: 'Multi-Event Correlation',
    description: 'Correlates malicious DNS queries with outbound network traffic within 5 minutes',
    query: 'let MaliciousDNS = DnsEvents\n| where DomainName in (known_malicious_domains)\n| project TimeGenerated, ClientIP, DomainName;\n\nlet OutboundTraffic = NetworkEvents\n| where Direction == "Outbound"\n| project TimeGenerated, SourceIP, DestinationIP, BytesTransferred;\n\nMaliciousDNS\n| join kind=inner (OutboundTraffic) on $left.ClientIP == $right.SourceIP\n| where abs(datetime_diff("minute", TimeGenerated, $right.TimeGenerated)) < 5\n| project TimeGenerated, ClientIP, DomainName, DestinationIP, BytesTransferred'
  },
  {
    name: 'Coordinated Login Attempts',
    category: 'Multi-Event Correlation',
    description: 'Detects coordinated login attempts across multiple accounts',
    query: 'SigninLogs\n| where ResultType != "0"\n| summarize LoginAttempts = count(), UniqueIPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)\n| where UniqueIPs > 3 and LoginAttempts > 10'
  },
  {
    name: 'Login and File Access Link',
    category: 'Multi-Event Correlation',
    description: 'Links unusual file access patterns to login activity',
    query: 'let LoginAnomalies = SigninLogs\n| summarize TotalLogins = count() by UserPrincipalName, bin(TimeGenerated, 1h)\n| where TotalLogins > 50;\n\nlet FileAccess = FileAuditLogs\n| where OperationName == "Access"\n| project TimeGenerated, UserPrincipalName, FilePath, IPAddress;\n\nLoginAnomalies\n| join kind=inner (FileAccess) on UserPrincipalName\n| where abs(datetime_diff("minute", TimeGenerated, $right.TimeGenerated)) < 15'
  },

  // Temporal Anomaly Detection
  {
    name: 'Login Time Anomalies',
    category: 'Temporal Anomaly Detection',
    description: 'Detects anomalous login times using historical baselines',
    query: 'let UserLogins = SigninLogs\n| summarize LoginsPerHour = count() by UserPrincipalName, hour_of_day = hourofday(TimeGenerated);\n\nlet HistoricalBaseline = UserLogins\n| summarize AverageLogins = avg(LoginsPerHour) by UserPrincipalName, hour_of_day;\n\nUserLogins\n| join kind=inner (HistoricalBaseline) on UserPrincipalName, hour_of_day\n| extend Deviation = LoginsPerHour - AverageLogins\n| where abs(Deviation) > 2'
  },
  {
    name: 'Network Traffic Anomalies',
    category: 'Temporal Anomaly Detection',
    description: 'Detects abnormal spikes in network traffic',
    query: 'NetworkEvents\n| summarize TotalTraffic = sum(BytesTransferred) by bin(TimeGenerated, 1h)\n| extend BaselineTraffic = avg(TotalTraffic) over (hsliding_window(7d, 1h))\n| where TotalTraffic > BaselineTraffic * 1.5'
  },
  {
    name: 'Privileged Role Growth',
    category: 'Temporal Anomaly Detection',
    description: 'Detects unusual growth in privileged role assignments',
    query: 'AuditLogs\n| where OperationName == "Add member to role"\n| summarize RoleChanges = count() by RoleName, bin(TimeGenerated, 1d)\n| extend Baseline = avg(RoleChanges) over (hsliding_window(30d, 1d))\n| where RoleChanges > Baseline * 2'
  },

  // Advanced Threat Detection
  {
    name: 'Ransomware File Patterns',
    category: 'Advanced Threat Detection',
    description: 'Detects ransomware-like behavior through file encryption patterns',
    query: 'FileAuditLogs\n| where FilePath endswith ".key" or FilePath endswith ".crypt"\n| summarize EncryptionAttempts = count() by UserPrincipalName, bin(TimeGenerated, 1h)\n| where EncryptionAttempts > 100'
  },
  {
    name: 'Suspicious Process Chain',
    category: 'Advanced Threat Detection',
    description: 'Detects suspicious process chains indicative of malware execution',
    query: 'SecurityEvent\n| where EventID == 4688\n| extend ParentProcess = tostring(parse_json(CommandLine)["ParentProcessName"])\n| where ParentProcess has "explorer.exe" and NewProcessName has_any ("powershell.exe", "cmd.exe", "wscript.exe")'
  },
  {
    name: 'Credential Harvesting',
    category: 'Advanced Threat Detection',
    description: 'Detects potential credential harvesting tools',
    query: 'SecurityEvent\n| where EventID == 4688\n| where CommandLine has_any ("dump", "extract", "hash", "credentials")'
  },

  // Complex Multi-Table Joins
  {
    name: 'Lateral Movement Tracking',
    category: 'Complex Multi-Table Joins',
    description: 'Tracks lateral movement across endpoints with process correlation',
    query: 'let LateralMovement = SecurityEvent\n| where EventID == 4624 and LogonType == 3\n| summarize LogonCount = count() by TargetComputer, SourceComputer, User, bin(TimeGenerated, 1h)\n| where LogonCount > 3;\n\nlet SuspiciousProcesses = SecurityEvent\n| where EventID == 4688\n| where CommandLine has_any ("PsExec", "WMIC", "RDP")\n| project TimeGenerated, Computer, ProcessName, User;\n\nLateralMovement\n| join kind=inner (SuspiciousProcesses) on TargetComputer == Computer\n| where abs(datetime_diff("minute", TimeGenerated, $right.TimeGenerated)) < 10'
  },
  {
    name: 'Unified Security Analysis',
    category: 'Complex Multi-Table Joins',
    description: 'Unifies DNS, network, and endpoint activity for advanced threat hunting',
    query: 'let DNSLogs = DnsEvents\n| project TimeGenerated, ClientIP, DomainName;\n\nlet NetworkTraffic = NetworkEvents\n| project TimeGenerated, SourceIP, DestinationIP, BytesTransferred;\n\nlet EndpointProcesses = SecurityEvent\n| where EventID == 4688\n| project TimeGenerated, Computer, ProcessName, User;\n\nDNSLogs\n| join kind=inner (NetworkTraffic) on $left.ClientIP == $right.SourceIP\n| join kind=inner (EndpointProcesses) on $left.ClientIP == $right.Computer'
  },

  // Advanced User Behavior Analysis
  {
    name: 'Failed Logins and Downloads',
    category: 'Advanced User Behavior Analysis',
    description: 'Correlates failed login attempts with data downloads',
    query: 'let FailedLogins = SigninLogs | where ResultType != "0";\nlet DataDownloads = FileAuditLogs | where OperationName == "Download";\nFailedLogins\n| join kind=inner (DataDownloads) on UserPrincipalName'
  },
  {
    name: 'Privilege Escalations',
    category: 'Advanced User Behavior Analysis',
    description: 'Identifies unusual privilege escalation patterns',
    query: 'AuditLogs\n| where OperationName == "Add member to role"\n| summarize RoleCount = count() by UserPrincipalName, RoleName\n| where RoleName in ("Global Admin", "Security Admin") and RoleCount > 2'
  },
  {
    name: 'Dormant Account Activity',
    category: 'Advanced User Behavior Analysis',
    description: 'Monitors previously dormant accounts becoming active',
    query: 'SigninLogs\n| summarize LastSeen = max(TimeGenerated) by UserPrincipalName\n| where LastSeen < ago(90d)'
  },
  {
    name: 'Confidential Site Access',
    category: 'Advanced User Behavior Analysis',
    description: 'Detects high access to confidential SharePoint sites',
    query: 'SharePointAuditLogs\n| where SiteUrl contains "Confidential"\n| summarize AccessCount = count() by UserPrincipalName\n| where AccessCount > 50'
  }
];

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

  const handleTableChange = (_event: any, newValue: KQLTable | null) => {
    setQueryState((prev) => ({
      ...prev,
      table: newValue,
    }));
  };

  const handleFilterFieldChange = (index: number) => (
    _event: React.SyntheticEvent,
    value: string | null
  ) => {
    const newFilters = [...queryState.filters];
    newFilters[index] = {
      ...newFilters[index],
      field: value || ''
    };
    setQueryState((prev) => ({
      ...prev,
      filters: newFilters,
    }));
  };

  const handleFilterOperatorChange = (index: number) => (
    _event: React.SyntheticEvent,
    value: string | null
  ) => {
    const newFilters = [...queryState.filters];
    newFilters[index] = {
      ...newFilters[index],
      operator: value || '=='
    };
    setQueryState((prev) => ({
      ...prev,
      filters: newFilters,
    }));
  };

  const handleFilterValueChange = (index: number) => (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const newFilters = [...queryState.filters];
    newFilters[index] = {
      ...newFilters[index],
      value: event.target.value
    };
    setQueryState((prev) => ({
      ...prev,
      filters: newFilters,
    }));
  };

  const addFilter = () => {
    setQueryState((prev) => ({
      ...prev,
      filters: [...prev.filters, { field: '', operator: '==', value: '' }],
    }));
  };

  const removeFilter = (index: number) => {
    setQueryState((prev) => ({
      ...prev,
      filters: prev.filters.filter((_, i) => i !== index),
    }));
  };

  const handleTimeFilterValueChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setQueryState((prev) => ({
      ...prev,
      timeFilter: {
        ...prev.timeFilter,
        value: Number(event.target.value),
      },
    }));
  };

  const handleTimeUnitChange = (_event: React.SyntheticEvent, newValue: TimeUnitOption | null) => {
    if (newValue) {
      setQueryState(prev => ({
        ...prev,
        timeFilter: { ...prev.timeFilter, unit: newValue.value }
      }));
    }
  };

  const handleSortChange = (field: string) => {
    setQueryState((prev) => ({
      ...prev,
      sortBy: {
        field,
        order: prev.sortBy.field === field && prev.sortBy.order === 'desc' ? 'asc' : 'desc',
      },
    }));
  };

  const handleFieldSelection = (_event: React.SyntheticEvent, value: string[]) => {
    setQueryState((prev) => ({
      ...prev,
      selectedFields: value,
    }));
  };

  const applyTemplate = (template: typeof commonTemplates[0]) => {
    setQueryState((prev) => ({
      ...prev,
      customQuery: template.query,
    }));
    setGeneratedQuery(template.query);
  };

  const handleCustomQueryChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setQueryState((prev) => ({
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
            <Autocomplete
              fullWidth
              options={tables}
              getOptionLabel={(option) => option.TableName}
              value={queryState.table}
              onChange={handleTableChange}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Select Table"
                  margin="normal"
                />
              )}
            />

            {queryState.table && (
              <Card sx={{ mb: 2, mt: 2 }}>
                <CardContent>
                  <Typography variant="subtitle1" color="primary" gutterBottom>
                    Table Information
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    <strong>Purpose:</strong> {queryState.table.Purpose}
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    <strong>Key Scenarios:</strong>
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                    {queryState.table.KeyScenarios.map((scenario, index) => (
                      <Chip key={index} label={scenario} size="small" />
                    ))}
                  </Box>
                  <Typography variant="body2" gutterBottom>
                    <strong>Available Fields:</strong>
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {queryState.table.Fields.map((field, index) => (
                      <Chip
                        key={index}
                        label={field}
                        size="small"
                        variant="outlined"
                        onClick={() => {
                          if (queryState.filters.length === 0) {
                            addFilter();
                          }
                        }}
                      />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            )}
            
            <Box sx={{ mb: 3 }}>
              <Typography variant="subtitle1" gutterBottom>
                Query Templates
              </Typography>
              {Array.from(new Set(commonTemplates.map(t => t.category))).map(category => (
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
                          onClick={() => applyTemplate(template)}
                          variant="outlined"
                          sx={{ mb: 1 }}
                          title={template.description}
                        />
                    ))}
                  </Box>
                </Box>
              ))}
            </Box>

            <Box sx={{ mb: 3 }}>
              <Typography variant="subtitle1" gutterBottom>
                Time Filter
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <input
                    type="checkbox"
                    checked={queryState.timeFilter.enabled}
                    onChange={(e) => {
                      setQueryState(prev => ({
                        ...prev,
                        timeFilter: {
                          ...prev.timeFilter,
                          enabled: e.target.checked
                        }
                      }));
                    }}
                    style={{ marginRight: '8px' }}
                  />
                  <Typography variant="body2">Enable time filter</Typography>
                </Box>
                <TextField
                  type="number"
                  label="Time Value"
                  value={queryState.timeFilter.value}
                  onChange={handleTimeFilterValueChange}
                  disabled={!queryState.timeFilter.enabled}
                  sx={{ width: 120 }}
                />
                <Autocomplete<TimeUnitOption, false>
                  options={timeUnits}
                  getOptionLabel={(option) => option.label}
                  value={timeUnits.find(unit => unit.value === queryState.timeFilter.unit) || null}
                  onChange={handleTimeUnitChange}
                  disabled={!queryState.timeFilter.enabled}
                  sx={{ width: 120 }}
                  renderInput={(params) => (
                    <TextField {...params} label="Unit" />
                  )}
                />
              </Box>
            </Box>

            {queryState.table && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="subtitle1" gutterBottom>
                  Fields to Include
                </Typography>
                <Autocomplete
                  multiple
                  options={queryState.table.Fields}
                  value={queryState.selectedFields}
                  onChange={handleFieldSelection}
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
            )}

            {queryState.filters.map((filter, index) => (
              <Box key={index} sx={{ display: 'flex', gap: 1, mb: 2, alignItems: 'center' }}>
                <Autocomplete
                  options={queryState.table?.Fields || []}
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

        {generatedQuery && (
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Generated Query
              </Typography>
              <TextField
                fullWidth
                value={generatedQuery}
                multiline
                rows={4}
                InputProps={{
                  readOnly: true,
                }}
              />
            </Paper>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default QueryGenerator;
