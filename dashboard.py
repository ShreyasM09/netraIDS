def create_dashboard_html():
    """Create a simple HTML dashboard"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>🛡 AI-IDS Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f0f2f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                     color: white; padding: 20px; border-radius: 10px; text-align: center; }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                         gap: 20px; margin: 20px 0; }
            .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
            .alerts-section { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .alert-item { padding: 10px; border-left: 4px solid #e74c3c; margin: 10px 0; 
                         background: #fdf2f2; border-radius: 4px; }
            .alert-high { border-left-color: #e74c3c; }
            .alert-medium { border-left-color: #f39c12; }
            .alert-low { border-left-color: #f1c40f; }
            .controls { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            button { background: #667eea; color: white; border: none; padding: 10px 20px; 
                    border-radius: 5px; cursor: pointer; margin: 5px; }
            button:hover { background: #5a67d8; }
            .status-indicator { display: inline-block; width: 12px; height: 12px; 
                              border-radius: 50%; margin-right: 8px; }
            .status-active { background-color: #27ae60; }
            .status-inactive { background-color: #e74c3c; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡 AI-Powered Intrusion Detection System</h1>
                <p>Real-time Network Security Monitoring & Threat Detection</p>
            </div>
            
            <div class="controls">
                <h3>System Controls</h3>
                <button onclick="startMonitoring()">🚀 Start Monitoring</button>
                <button onclick="stopMonitoring()">🛑 Stop Monitoring</button>
                <button onclick="trainSystem()">🎯 Train System</button>
                <button onclick="refreshStats()">🔄 Refresh Stats</button>
                <span class="status-indicator status-inactive" id="statusIndicator"></span>
                <span id="statusText">System Inactive</span>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>📊 Packets Processed</h3>
                    <div class="stat-number" id="totalPackets">0</div>
                </div>
                <div class="stat-card">
                    <h3>🚨 Security Alerts</h3>
                    <div class="stat-number" id="totalAlerts">0</div>
                </div>
                <div class="stat-card">
                    <h3>⚡ Alert Rate</h3>
                    <div class="stat-number" id="alertRate">0.0%</div>
                </div>
                <div class="stat-card">
                    <h3>🎯 System Status</h3>
                    <div class="stat-number" id="systemStatus">Ready</div>
                </div>
            </div>
            
            <div class="alerts-section">
                <h3>🚨 Recent Security Alerts</h3>
                <div id="alertsList">
                    <p>No alerts yet. System monitoring will display alerts here.</p>
                </div>
            </div>
            
            <div class="alerts-section">
                <h3>📈 System Logs</h3>
                <div id="systemLogs" style="height: 200px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace;">
                    <p>System initialized. Waiting for commands...</p>
                </div>
            </div>
        </div>
        
        <script>
            let monitoring = false;
            let alertCount = 0;
            let packetCount = 0;
            
            function addLog(message) {
                const logs = document.getElementById('systemLogs');
                const timestamp = new Date().toLocaleTimeString();
                logs.innerHTML += `<br>[${timestamp}] ${message}`;
                logs.scrollTop = logs.scrollHeight;
            }
            
            function updateStatus(active) {
                const indicator = document.getElementById('statusIndicator');
                const text = document.getElementById('statusText');
                
                if (active) {
                    indicator.className = 'status-indicator status-active';
                    text.textContent = 'System Active - Monitoring';
                } else {
                    indicator.className = 'status-indicator status-inactive';
                    text.textContent = 'System Inactive';
                }
            }
            
            function startMonitoring() {
                if (!monitoring) {
                    monitoring = true;
                    updateStatus(true);
                    addLog('🚀 Starting intrusion detection monitoring...');
                    document.getElementById('systemStatus').textContent = 'Monitoring';
                    
                    // Simulate monitoring activity
                    startSimulation();
                } else {
                    addLog('⚠️ System is already monitoring');
                }
            }
            
            function stopMonitoring() {
                if (monitoring) {
                    monitoring = false;
                    updateStatus(false);
                    addLog('🛑 Monitoring stopped');
                    document.getElementById('systemStatus').textContent = 'Stopped';
                } else {
                    addLog('⚠️ System is not currently monitoring');
                }
            }
            
            function trainSystem() {
                addLog('🎯 Training ML models with network traffic data...');
                document.getElementById('systemStatus').textContent = 'Training';
                
                // Simulate training progress
                setTimeout(() => {
                    addLog('✅ Model training completed successfully');
                    document.getElementById('systemStatus').textContent = 'Trained';
                }, 3000);
            }
            
            function refreshStats() {
                document.getElementById('totalPackets').textContent = packetCount;
                document.getElementById('totalAlerts').textContent = alertCount;
                const rate = packetCount > 0 ? ((alertCount / packetCount) * 100).toFixed(2) : '0.00';
                document.getElementById('alertRate').textContent = rate + '%';
                addLog('🔄 Statistics refreshed');
            }
            
            function generateAlert() {
                if (!monitoring) return;
                
                const alertTypes = [
                    'Port Scan Detected',
                    'Potential DDoS Attack', 
                    'Brute Force Attack',
                    'Suspicious Network Activity',
                    'Malware Communication',
                    'Data Exfiltration Attempt'
                ];
                
                const severities = ['HIGH', 'MEDIUM', 'LOW'];
                const srcIPs = ['203.0.113.10', '198.51.100.25', '192.0.2.100', '10.0.0.50'];
                const dstIPs = ['192.168.1.10', '192.168.1.25', '10.0.0.100'];
                
                const alert = {
                    timestamp: new Date().toLocaleString(),
                    type: alertTypes[Math.floor(Math.random() * alertTypes.length)],
                    severity: severities[Math.floor(Math.random() * severities.length)],
                    srcIP: srcIPs[Math.floor(Math.random() * srcIPs.length)],
                    dstIP: dstIPs[Math.floor(Math.random() * dstIPs.length)],
                    port: Math.floor(Math.random() * 65535)
                };
                
                alertCount++;
                
                const alertsList = document.getElementById('alertsList');
                if (alertCount === 1) {
                    alertsList.innerHTML = ''; // Clear initial message
                }
                
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert-item alert-${alert.severity.toLowerCase()}`;
                alertDiv.innerHTML = `
                    <strong>${alert.type}</strong><br>
                    <small>
                        📅 ${alert.timestamp} | 
                        🔴 ${alert.severity} | 
                        🌐 ${alert.srcIP} → ${alert.dstIP}:${alert.port}
                    </small>
                `;
                
                alertsList.insertBefore(alertDiv, alertsList.firstChild);
                
                // Keep only last 10 alerts
                while (alertsList.children.length > 10) {
                    alertsList.removeChild(alertsList.lastChild);
                }
                
                addLog(`🚨 ${alert.severity} Alert: ${alert.type} from ${alert.srcIP}`);
            }
            
            function simulateTraffic() {
                if (!monitoring) return;
                
                // Simulate packet processing
                packetCount += Math.floor(Math.random() * 20) + 1;
                
                // Generate alerts occasionally
                if (Math.random() < 0.15) { // 15% chance of alert
                    generateAlert();
                }
                
                // Auto-refresh stats
                refreshStats();
            }
            
            function startSimulation() {
                const interval = setInterval(() => {
                    if (!monitoring) {
                        clearInterval(interval);
                        return;
                    }
                    simulateTraffic();
                }, 2000); // Every 2 seconds
            }
            
            // Initialize dashboard
            addLog('🛡 AI-IDS Dashboard initialized');
            addLog('📋 Ready to start network monitoring');
        </script>
    </body>
    </html>
    """
    
    with open("ids_dashboard.html", "w") as f:
        f.write(html_content)
    
    print("✅ Dashboard created: ids_dashboard.html")
