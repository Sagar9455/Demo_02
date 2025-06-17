import can
import socket
import shutil 
import os
import isotp
import time
import logging
from datetime import datetime
from udsoncan.client import Client
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.configs import default_client_config
from drivers.Parse_handler import load_testcases
from drivers.can_logger import CANLogger
from udsoncan import AsciiCodec
from drivers.report_generator import generate_report 
from udsoncan.services import WriteDataByIdentifier

class SafeAsciiCodec(AsciiCodec):
    def decode(self, data):
        try:
            return data.decode('ascii')
        except UnicodeDecodeError:
            return data.hex()
class UDSClient:
    def __init__(self, config):
        can_cfg = config["uds"]["can"]
        isotp_cfg = config["uds"]["isotp"]
        timing_cfg = config["uds"]["timing"]
       
        self.uds_config = config["uds"]
        print("UDS Config loaded:", self.uds_config)
        
        self.tx_id = int(can_cfg["tx_id"], 16)
        self.rx_id = int(can_cfg["rx_id"], 16)
        is_extended = can_cfg.get("is_extended", False)
        
        if is_extended:
            addr_mode = isotp.AddressingMode.Normal_29bits
        else:
            addr_mode = isotp.AddressingMode.Normal_11bits
        
        address = isotp.Address(
            addr_mode,
            txid=self.tx_id,
            rxid=self.rx_id
        )
        
        self.bus = can.interface.Bus(
            channel=can_cfg["channel"],
            bustype=can_cfg["interface"],
            fd=can_cfg.get("can_fd", True),
            can_filters=[{"can_id": self.rx_id, "can_mask": 0x7FF, "extended": False}]
        )
        
        self.stack = isotp.CanStack(
            bus=self.bus,
            address=address,
            params=isotp_cfg
        )
        
        self.conn = PythonIsoTpConnection(self.stack)
        
        self.client_config = default_client_config.copy()
        self.client_config["p2_timeout"] = timing_cfg["p2_client"] / 1000.0
        self.client_config["p2_star_timeout"] = timing_cfg["p2_extended_client"] / 1000.0
        self.client_config["s3_client_timeout"] = timing_cfg["s3_client"] / 1000.0
        self.client_config["exception_on_negative_response"] = False
        self.client_config["exception_on_unexpected_response"] = False
        self.client_config["exception_on_invalid_response"] = False
        self.client_config["use_server_timing"] = False
        
        
        
        self.info_dids = self.uds_config.get("ecu_information_dids", {})
        self.decode_dids = self.uds_config.get("decoding_dids", {})
        self.write_data_dict = self.uds_config.get("write_data", {})
        
        # Convert hex strings to int keys
        self.client_config["data_identifiers"] = {
            int(did_str, 16): SafeAsciiCodec(length)
            for did_str, length in self.decode_dids.items()
        }
        self.client_config["write_data"] = {
            int(did_str, 16): data_str
            for did_str, data_str in self.write_data_dict.items()
        }


        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..' , '..'))
        log_dir = os.path.join(self.project_root, 'output', 'can_logs')
        self.can_logger = CANLogger(channel=can_cfg["channel"], interface=can_cfg["interface"],log_dir=log_dir)
        self.allowed_ids = { self.tx_id, self.rx_id }
        
    
    def check_disk_space(self, min_required_mb=50):
            total, used, free = shutil.disk_usage("/")
            free_mb = free // (1024 * 1024)  # Convert to MB
            return (free_mb >= min_required_mb, free_mb)
            
   
    def start_logging(self, log_name_suffix=""):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"CANLog_{log_name_suffix}_{timestamp}.asc"
            self.can_logger.start(filename=filename)
        
    def stop_logging(self):
        self.can_logger.stop()
        
    def timestamp_log(self):
        timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3]   

    def check_memory(self,oled):
        min_required = 50
        enough_space, free_mb = self.check_disk_space(min_required_mb=min_required)
        
        if not enough_space:
            warning_msg = f"Low Storage!\nOnly {free_mb}MB left.\nNeed {min_required}MB."
            oled.display_centered_text(warning_msg)
            logging.warning(warning_msg)
            time.sleep(4)
            return
        
        oled.display_centered_text(f"Storage OK\nFree: {free_mb} MB")
        logging.info(f"Storage check passed: {free_mb} MB available")
        time.sleep(2)   
    
    
    def get_ecu_information(self, oled):
        self.check_memory(oled) 
        #ecu_log_filename = f"ECU_Info_{int(time.time())}.asc"
        #can_logger.start(filename=ecu_log_filename)
             
        self.start_logging(log_name_suffix="ECU_Info")
        session_default = int(self.uds_config["default_session"], 16)
        session_extended = int(self.uds_config["extended_session"], 16)
        
        with Client(self.conn, request_timeout=2, config=self.client_config) as client:
            try:
                client.change_session(session_default)
                time.sleep(0.2)
                client.change_session(session_extended)
                time.sleep(0.2)
            except Exception as e:
                oled.display_centered_text(f"Session Error:\n{str(e)}")
                logging.error(f"Session change failed: {e}")
                self.stop_logging()
                return
        
            for did_hex, info in self.info_dids.items():
                label = info["label"]
                did = int(did_hex, 16)
        
                try:
                    response = client.read_data_by_identifier(did)
                    if response.positive:
                            values = response.service_data.values[did]
                            if isinstance(values, (bytes, bytearray)):
                                hex_str = ' '.join(f"{b:02X}" for b in values)
                            elif isinstance(values, str):
                                hex_str = values
                            else:
                                hex_str = str(values)
                            
                            display_text = f"{label}\n{hex_str}"
                            oled.display_centered_text(display_text)
                            logging.info(f"[ECU Info] {label} ({did_hex}) = {hex_str}")
                    else:
                        nrc = hex(response.code)
                        oled.display_centered_text(f"{label}\nNRC: {nrc}")
                        logging.warning(f"[ECU Info] {label} - Negative Response Code: {nrc}")
                except Exception as e:
                    error_msg = str(e)[:40]
                    oled.display_centered_text(f"{label}\nError: {error_msg}")
                    logging.error(f"[ECU Info] {label} - Exception: {e}")
        
                time.sleep(3)  
        self.stop_logging()

    def run_testcase(self, oled):
        
        self.check_memory(oled) 
        self.start_logging(log_name_suffix="Testcase")
        grouped_cases = load_testcases() 
               
        with Client(self.conn, request_timeout=2, config=self.client_config) as client:
            context = {}
            write_data_dict = self.client_config.get('write_data', {})
            print(dir(client))
            print("Effective UDS Client Config:")
            for key,val in self.client_config.items():
                    print(f":{key}:{val}")
            for tc_id, steps in grouped_cases.items():
                logging.info(f"Running Test Case: {tc_id}")
                for step in steps:
                    _, step_desc, service, subfunc, expected = step
                    try:
                        service_int = int(service, 16)
                        subfunc_int = int(subfunc, 16)
                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                        logging.info(f"{tc_id} - {step_desc}: SID={service}, Sub={subfunc}, Expected={expected_bytes}")

                        response = None
                        if service_int == 0x10:  # DiagnosticSessionControl
                            raw_request = bytes([0x10, subfunc_int])
                            self.stack.send(raw_request)
                            response_data = self.stack.recv()
                        elif service_int == 0x11:  # ECU Reset
                            raw_request = bytes([0x11, subfunc_int])
                            self.stack.send(raw_request)
                            response_data = self.stack.recv()
                        elif service_int == 0x22:  # ReadDataByIdentifier
                            did_hi = (subfunc_int >> 8) & 0xFF
                            did_lo = subfunc_int & 0xFF
                            raw_request = bytes([0x22, did_hi, did_lo])
                            self.stack.send(raw_request)
                            response_data = self.stack.recv()
                        elif service_int == 0x2E:  # WriteDataByIdentifier
                            did_hi = (subfunc_int >> 8) & 0xFF
                            did_lo = subfunc_int & 0xFF
                            data_to_write = write_data_dict.get(subfunc_int)
                            if data_to_write is None:
                             raise ValueError(f"No write data configured for DID {hex(subfunc_int)}")
                        elif service_int == 0x19:  # ReadDTCInformation
                            # Status mask 0xFF is typically used, but you can customize this
                            status_mask = 0xFF
                            raw_request = bytes([0x19, subfunc_int, status_mask])
                            self.stack.send(raw_request)
                            response_data = self.stack.recv()
                            
                        elif service_int == 0x14:  # ClearDiagnosticInformation
                            # 0x14 SID + 3-byte GroupOfDTC (e.g., FFFFFFFF)
                            dtc_group_bytes = [(subfunc_int >> shift) & 0xFF for shift in (16, 8, 0)]
                            raw_request = bytes([0x14] + dtc_group_bytes)
                            self.stack.send(raw_request)
                            response_data = self.stack.recv()
                            
                        elif service_int == 0x3E:  # TesterPresent
                            raw_request = bytes([0x3E, 0x00])
                            self.stack.send(raw_request)
                            response_data = self.stack.recv()
                            
                        elif service_int == 0x85:  # ControlDTCSetting
                             raw_request = bytes([0x85, subfunc_int])
                             self.stack.send(raw_request)
                             response_data = self.stack.recv()
                        
                        elif service_int == 0x27:
                             if subfunc_int % 2 == 1:  # Request Seed
                                 raw_request = bytes([0x27, subfunc_int])
                                 self.stack.send(raw_request)
                                 response_data = self.stack.recv()
                                 if not response.positive:
                                     #failure_reason = f"NRC (seed): {hex(response.code)}"
                                     #logging.warning(f"{tc_id} {step_desc} -> FAIL - {failure_reason}")
                                     raise Exception(failure_reason)
                                 
                                 seed = response.service_data.seed
                                 context[f"seed_{subfunc_int}"] = seed
                                 logging.info(f"Received Seed (subfunc {hex(subfunc_int)}): {seed.hex()}")
                                 time.sleep(0.5)
                             
                                 # Send seed to PC and get key
                                 udp_ip = "192.168.10.220"
                                 udp_port = 5005
                                 max_retries = 3
                                 retry_delay = 1.0
                                 #expected_key_length = 8  
                             
                                 sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                 sock.settimeout(5)
                             
                                 try:
                                     for attempt in range(1, max_retries + 1):
                                         try:
                                             logging.info(f"Attempt {attempt}: Sending seed to PC...")
                                             sock.sendto(seed.hex().encode(), (udp_ip, udp_port))
                                             key, _ = sock.recvfrom(1024)
                                             key = key.strip()
                             
                                             if not key:
                                                 raise Exception("Received empty key from PC")
                                            # if len(key) != expected_key_length:
                                            #     raise Exception(f"Invalid key length: expected {expected_key_length}, got {len(key)}")
                                             
                                             context[f"key_{subfunc_int+1}"] = key  # store key using subfunc 0x02/0x12
                                             logging.info(f"Received Key (for subfunc {hex(subfunc_int+1)}): {key}")
                                             break
                                         except socket.timeout:
                                             logging.warning(f"Attempt {attempt} - Timeout waiting for key.")
                                             if attempt < max_retries:
                                                 time.sleep(retry_delay)
                                             else:
                                                 raise Exception(f"Timeout after {max_retries} retries waiting for key from PC")
                                         except Exception as e:
                                             logging.exception(f"Attempt {attempt} - Error occurred:")
                                             if attempt == max_retries:
                                                 raise
                                 finally:
                                     sock.close()
                             
                             elif subfunc_int % 2 == 0:  
                                 key = context.get(f"key_{subfunc_int}")
                                 if not key:
                                     raise Exception(f"No key available for subfunction {hex(subfunc_int)}. Ensure seed request precedes key send.")
                                 
                                 response = client.send_key(subfunc_int, key)
                                 if not response.positive:
                                     #failure_reason = f"NRC (key): {hex(response.code)}"
                                     #logging.warning(f"{tc_id} {step_desc} -> FAIL - {failure_reason}")
                                     raise Exception(failure_reason)
                             else:
                                 raise ValueError(f"Unsupported subfunction for service 0x27: {hex(subfunc_int)}")
                              
                        elif service_int == 0x28:  # CommunicationControl
    # Example: subfunc_int = 0x01 (EnableRxAndTx), 0x02 (EnableRxAndDisableTx), etc.
    # Note: CommunicationType is typically 1 byte (e.g., 0x00 = Normal, 0x01 = Network Management)
    # If your test case has a separate byte for CommunicationType, you must extract it

    # For now, assume just subfunc_int means controlType (you can adjust as needed)
                            communication_type = 0x00  # Default communication type if not provided separately
                            raw_request = bytes([0x28, subfunc_int, communication_type])
                            self.stack.send(raw_request)
                            response_data = self.stack.recv()
                       
                        else:
                            raise ValueError(f"Unsupported service: {service}")                          
                        
                    except Exception as e:
                        response_time = datetime.now() 
                        
                        #logging.error(f"{tc_id} {step_desc} -> EXCEPTION - {failure_reason}")
                    oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                    time.sleep(2)
               
        # Determine report output folder and filename dynamically
   
        self.stop_logging()
        #oled.display_text("Log Generated!\n")
        #self.stop_logging()

        # Wait to ensure file is written to disk
        time.sleep(1.5)
        
        # Get the full log file path and confirm existence
        full_log_path = self.can_logger.get_log_path() or "N/A"
        can_log_file = os.path.basename(full_log_path)
        
        # Extra: Confirm file is there
        if not os.path.isfile(full_log_path):
            logging.error(f"❌ File not found after logging stopped: {full_log_path}")
            oled.display_text("Log Error!\nFile Missing.")
            return  # or handle error gracefully
        else:
            logging.info(f"✅ Log file found: {full_log_path}")
            oled.display_text("Log Generated!\n")

        report_dir = os.path.join(self.project_root, 'output', 'html_reports')
        os.makedirs(report_dir, exist_ok=True)
        report_filename = f"UDS_Report_{int(time.time())}.html"
        report_path = os.path.join(report_dir, report_filename)

        # Get dynamic metadata for report:
        full_log_path=self.can_logger.get_log_path() or "N/A"
        can_log_file = os.path.basename(full_log_path)
        report_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"Full path:{full_log_path}")
        print(f"File name:{can_log_file}")
        # Wait until the log file becomes visible on the filesystem (max 3 seconds)
        for _ in range(6):  # Retry every 0.5s up to 3s
           if os.path.exists(full_log_path):
                   print(f"✅ Log file found: {full_log_path}")
                   break
           else:
                   print(f"⏳ Waiting for log file to appear: {full_log_path}")
                   time.sleep(0.5)
        else:
                print(f"❌ File not found: {can_log_file}")
        
        
        
        generate_report(
             input_asc_file=full_log_path,
            output_html_file=report_path,
            allowed_ids=self.allowed_ids
        )
        
        oled.display_text("Report Done!\n" + report_filename[:16])
        logging.info(f"Test report saved: {report_filename}")
        
