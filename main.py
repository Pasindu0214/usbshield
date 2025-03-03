# main.py
import sys
import os
from PyQt5.QtWidgets import QApplication

def main():
    # Create necessary directories if they don't exist
    os.makedirs('data/quarantine', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Import modules inside function to avoid circular imports
    from gui.main_window import MainWindow
    from core.config import Config
    from utils.logger import setup_logger
    
    # Set up logger
    logger = setup_logger()
    logger.info("Starting USBShield application")
    
    # Load configuration
    config = Config()
    config.load_config()
    
    # Start the GUI application
    app = QApplication(sys.argv)
    app.setApplicationName("USBShield")
    app.setStyle("Fusion")
    
    window = MainWindow(config, logger)
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to continue...")