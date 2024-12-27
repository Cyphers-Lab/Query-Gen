import { QueryTemplate } from '../types/query';

export const commonTemplates: QueryTemplate[] = [
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
  }
];

export const operators = [
  '==', '!=', '>', '<', '>=', '<=', 'contains', 'startswith', 'endswith', 'in', 'matches regex'
];

export const timeUnits = [
  { value: 'h' as const, label: 'Hours' },
  { value: 'd' as const, label: 'Days' },
  { value: 'm' as const, label: 'Minutes' }
];
