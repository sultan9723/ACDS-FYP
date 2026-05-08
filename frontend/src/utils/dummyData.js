export const initialStats = {
  totalThreats: 125,
  activeThreats: 5,
  autoResolvedThreats: 61,
  accuracy: 92,
};

export const threatsOverTimeData = [
  { time: "0", value: 4 },
  { time: "2", value: 5 },
  { time: "4", value: 7 },
  { time: "6", value: 6 },
  { time: "8", value: 8 },
  { time: "10", value: 9 },
  { time: "12", value: 8 },
  { time: "14", value: 11 },
  { time: "16", value: 10 },
];

export const threatTypesData = [
  { name: "Credential Theft", value: 15 },
  { name: "Malicious Link", value: 8 },
  { name: "Malicious Attachment", value: 2 },
];

export const accuracyOverTimeData = [
  { time: "0", value: 70 },
  { time: "2", value: 75 },
  { time: "4", value: 82 },
  { time: "6", value: 85 },
  { time: "8", value: 88 },
  { time: "10", value: 92 },
];

export const confusionMatrixData = {
  tp: 108,
  fp: 9,
  fn: 7,
  tn: 98,
};

export const initialThreats = [
  {
    id: 1,
    time: "10:54:21",
    type: "Credential Theft",
    sourceIp: "192.152.0.5",
    user: "user@bank.com",
    confidence: 82,
    status: "Active",
  },
  {
    id: 2,
    time: "02:15:47",
    type: "Malicious Link",
    sourceIp: "192.198.14.2",
    user: "workstation1",
    confidence: 76,
    status: "Active",
  },
  {
    id: 3,
    time: "02:15:47",
    type: "Malicious Attachment",
    sourceIp: "209.0.115.42",
    user: "ceo@bank.com",
    confidence: 92,
    status: "Active",
  },
  {
    id: 4,
    time: "02:15",
    type: "Credential Theft",
    sourceIp: "203.0.715.43",
    user: "hr@bank.com",
    confidence: 75,
    status: "Active",
  },
  {
    id: 5,
    time: "10:15:47",
    type: "Malicious Link",
    sourceIp: "198.186.100",
    user: "admin",
    confidence: 92,
    status: "Active",
  },
  {
    id: 6,
    time: "02:15:47",
    type: "Credential Theft",
    sourceIp: "198.51.100.9",
    user: "staff1",
    confidence: 100,
    status: "Resolved",
  },
];

export const incidentDetails = {
  dateTime: "2025-03-02 14:12",
  description: "Credential Theft",
  sourceIp: "202.122.44.18",
  targetAccount: "customer127@bank.com",
  confidence: 96,
  explanation:
    "The email contained a deceptive domain and login access om which matches 17 prior phishing cases",
  action: "Account temporarily locked\nSource IP blocked (Firewall)",
  status: "A ticket logged for SOC analyst",
};

export const modelPerformanceLogs = [
  {
    id: 1,
    date: "2025-03-02",
    type: "Credential Theft",
    decision: "True Positive",
    action: "Account Lock",
    modelVersion: "v2",
  },
  {
    id: 2,
    date: "2025-04-28",
    type: "Malicious Link",
    decision: "True Positive",
    action: "Account Lock",
    modelVersion: "v1",
  },
  {
    id: 3,
    date: "2025-04-28",
    type: "Malicious Attachment",
    decision: "True Positive",
    action: "Account",
    modelVersion: "v1",
  },
];
