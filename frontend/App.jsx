import React, { useState, useEffect } from 'react';
import './App.css';
import AlertIngestor from './components/AlertIngestor';
import IncidentViewer from './components/IncidentViewer';
import Statistics from './components/Statistics';
import MitreMapping from './components/MitreMapping';
import CorrelationRules from './components/CorrelationRules';

function App() {
  const [activeTab, setActiveTab] = useState('ingest');
  const [stats, setStats] = useState(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    fetchStats();
  }, [refreshTrigger]);

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/stats');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const handleAlertsIngested = () => {
    setRefreshTrigger(prev => prev + 1);
  };

  return (
    <div className="app">
      <header className="header">
        <div className="header-content">
          <h1>⚠️ SIEM Alert Tuning & Correlation</h1>
          <p>Reduce False Positives | Correlate Incidents | Map MITRE ATT&CK</p>
        </div>
      </header>

      <nav className="nav-tabs">
        <button
          className={`tab ${activeTab === 'ingest' ? 'active' : ''}`}
          onClick={() => setActiveTab('ingest')}
        >
          Ingest Alerts
        </button>
        <button
          className={`tab ${activeTab === 'incidents' ? 'active' : ''}`}
          onClick={() => setActiveTab('incidents')}
        >
          Correlated Incidents
        </button>
        <button
          className={`tab ${activeTab === 'mitre' ? 'active' : ''}`}
          onClick={() => setActiveTab('mitre')}
        >
          MITRE ATT&CK Mapping
        </button>
        <button
          className={`tab ${activeTab === 'stats' ? 'active' : ''}`}
          onClick={() => setActiveTab('stats')}
        >
          Statistics
        </button>
        <button
          className={`tab ${activeTab === 'rules' ? 'active' : ''}`}
          onClick={() => setActiveTab('rules')}
        >
          Correlation Rules
        </button>
      </nav>

      <main className="main-content">
        {activeTab === 'ingest' && (
          <AlertIngestor onAlertsIngested={handleAlertsIngested} />
        )}
        
        {activeTab === 'incidents' && <IncidentViewer />}
        
        {activeTab === 'mitre' && <MitreMapping />}
        
        {activeTab === 'stats' && <Statistics stats={stats} />}
        
        {activeTab === 'rules' && <CorrelationRules />}
      </main>

      <footer className="footer">
        <p>Project #23: SIEM Alert Tuning & Correlation Engine | Built for Enterprise SOC Operations</p>
        <p>GitHub: <a href="https://github.com/Korir555/siem-alert-correlation" target="_blank">Korir555/siem-alert-correlation</a></p>
      </footer>
    </div>
  );
}

export default App;
