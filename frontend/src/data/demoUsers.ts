export interface DemoUser {
  username: string;
  name: string;
  role: 'IO' | 'SO' | 'Legal Reviewer' | 'Auditor';
  displayRole: string;
}

export const demoUsers: DemoUser[] = [
  { username: 'docspector.io', name: 'Investigation Officer', role: 'IO', displayRole: 'Investigating Officer (IO)' },
  { username: 'docspector.so', name: 'Supervising Officer', role: 'SO', displayRole: 'Supervising Officer (SO)' },
  { username: 'docspector.legal', name: 'Legal Reviewer', role: 'Legal Reviewer', displayRole: 'Legal Reviewer' },
  { username: 'docspector.auditor', name: 'Audit Officer', role: 'Auditor', displayRole: 'Auditor' },
];
