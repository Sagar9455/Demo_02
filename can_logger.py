import os
import can
import logging
import threading
from datetime import datetime
from can.io.asc import ASCWriter

# Setup logging format
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

# Allowed arbitration IDs to log and capture
ALLOWED_IDS = {0x716, 0x71E}

class CANLogger:
    class _CaptureListener:
        """Listener class to capture CAN messages for the CANLogger."""
        def __init__(self, logger):
            self.logger = logger

        def on_message_received(self, msg):
            self.logger._capture_message(msg)

    class _FilteredWriter:
        """Wrapper around ASCWriter to log only allowed CAN IDs."""
        def __init__(self, writer):
            self.writer = writer

        def on_message_received(self, msg):
            if msg.arbitration_id in ALLOWED_IDS:
                self.writer.on_message_received(msg)

    def __init__(self, channel='can0', interface='socketcan', can_fd=False,
                 log_dir='/home/mobase/UDS_Tool_Raspberry_Pi/MKBD/udsoncan/output/can_logs'):
        self.channel = channel
        self.interface = interface
        self.can_fd = can_fd
        self.log_dir = log_dir

        self.bus = None
        self.notifier = None
        self.writer = None
        self.file = None
        self.log_path = None
        self.test_start_time = None
        self.captured_frames = []
        self.lock = threading.Lock()

        self.capture_listener = self._CaptureListener(self)

    def start(self, filename=None):
        """Start CAN bus logging with ASCWriter and capture listener."""
        if self.notifier or self.writer:
            self.stop()

        os.makedirs(self.log_dir, exist_ok=True)

        # Use timestamp if no filename provided
        if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(self.log_dir, f"can_log_{timestamp}.asc")
        self.log_path = os.path.join(self.log_dir, filename)

        try:
            # Open log file for writing
            self.file = open(self.log_path, 'w')

            # Create CAN bus interface
            self.bus = can.interface.Bus(channel=self.channel, bustype=self.interface)

            # Attach ASCWriter to bus via Notifier
            self.writer = ASCWriter(self.file)
            #self.notifier = can.Notifier(self.bus, [self.writer])
            # Notifier with ASC writer and capture listener
            self.test_start_time = datetime.now().timestamp()
            with self.lock:
                self.captured_frames.clear()
                
            self.notifier = can.Notifier(self.bus, [self.writer, self.capture_listener.on_message_received])
            
            

            logging.info(f"CAN logging started: {self.log_path}")

        except Exception as e:
            logging.error(f"[CANLogger] Failed to start: {e}")

    def _capture_message(self, msg):
        """Store only allowed CAN messages for report generation."""
        if msg.arbitration_id in ALLOWED_IDS:
            with self.lock:
                self.captured_frames.append(msg)
            # Optional debug log
            # logging.debug(f"[CANLogger] Captured ID: {hex(msg.arbitration_id)}")

    def stop(self):
        """Stop logging and finalize log file."""
        try:
            if self.notifier:
                self.notifier.stop()
            if self.writer:
                self.writer.stop()
            if self.file:
                self.file.flush()
                self.file.write('end of logfile\n')
                self.file.close()

            logging.info(f"CAN logging stopped: {self.log_path}")
            print(f"[CANLogger] Log file saved to: {self.log_path}")

        except Exception as e:
            logging.error(f"[CANLogger] Error during stop: {e}")

        # Reset objects
        self.bus = None
        self.notifier = None
        self.writer = None
        self.file = None

    
    def get_start_time(self):
        """Return test start timestamp."""
        return self.test_start_time

    def get_recent_frames(self, limit=20):
        """Return last 'limit' captured CAN frames."""
        with self.lock:
            return self.captured_frames[-limit:]

    def get_relative_timestamp(self, msg):
        """Return message timestamp relative to test start."""
        if not self.test_start_time or not hasattr(msg, 'timestamp'):
            return 0.0
        return msg.timestamp - self.test_start_time

    def get_log_path(self):
        """Return the current log file path."""
        return self.log_path
