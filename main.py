from .idsCore import RealTimeIDS
from .dashboard import create_dashboard_html

def main():
    print("🛡 AI-Powered Intrusion Detection System")
    print("=" * 50)
    
    ids = RealTimeIDS()
    
    while True:
        print("\n📋 IDS Menu:")
        print("1. 🎯 Train System")
        print("2. 🚀 Start Monitoring")
        print("3. 📊 View Statistics")
        print("4. 📋 Export Alerts")
        print("5. 🌐 Create Dashboard")
        print("6. 🔧 Load Models")
        print("7. 🔄 Generate Sample Attack Traffic")
        print("8. ❌ Exit")
        
        choice = input("\nSelect option (1-8): ").strip()
        
        if choice == "1":
            ids.train_system()
        elif choice == "2":
            duration = int(input("Duration (s, default 60): ") or 60)
            iface = input("Interface (blank=simulate): ") or None
            ids.start_monitoring(interface=iface, duration=duration)
        elif choice == "3":
            print(ids.get_statistics())
        elif choice == "4":
            fname = input("Filename (default alerts.json): ") or "alerts.json"
            ids.export_alerts(fname)
        elif choice == "5":
            create_dashboard_html()
        elif choice == "6":
            ids.anomaly_detector.load_models()
        elif choice == "7":
            print("🔄 Sample attacks...")
            # (print examples like before)
        elif choice == "8":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid option.")

if __name__ == "__main__":
    main()
