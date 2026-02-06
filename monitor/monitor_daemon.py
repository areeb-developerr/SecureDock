#!/usr/bin/env python3
"""
Security Monitor Daemon
Runs in background and monitors container activities
"""

import sys
import time
import signal
from pathlib import Path
from real_time_monitor import RealTimeMonitor
from real_time_monitor_stderr import RealTimeMonitorStderr

# Configuration
FALCO_LOG = Path(__file__).parent.parent / "falco-logs" / "output.log"
REPORT_DIR = Path(__file__).parent.parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

class MonitorDaemon:
    def __init__(self):
        # Use stderr monitor since Falco writes to stderr
        self.monitor = RealTimeMonitorStderr(container_name='falco-monitor-vulnerable', window_size=10)
        self.running = False
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\n[*] Shutting down monitor...")
        self.monitor.stop_monitoring()
        self.running = False
        
        # Save final report
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = REPORT_DIR / f"monitoring_report_{timestamp}.json"
        self.monitor.save_report(str(report_file))
        
        sys.exit(0)
    
    def run(self):
        """Run the monitoring daemon"""
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        print("="*60)
        print("SECURITY MONITOR DAEMON")
        print("="*60)
        print(f"Monitoring: {FALCO_LOG}")
        print(f"Window Size: 10 seconds")
        print(f"Reports: {REPORT_DIR}")
        print("\nPress Ctrl+C to stop and generate report\n")
        
        # Start monitoring
        self.monitor.start_monitoring()
        self.running = True
        
        # Run monitoring loop in main thread
        try:
            self.monitor.monitor_loop()
        except KeyboardInterrupt:
            self.signal_handler(None, None)

if __name__ == "__main__":
    daemon = MonitorDaemon()
    daemon.run()

