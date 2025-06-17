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
from drivers.report_generator import generate_report, convert_report, ReportGenerator
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
        
        
        
        self.info_dids = self.uds_config["ecu_information_dids"]
        self.decode_dids = self.uds_config["decoding_dids"]
        self.client_config["data_identifiers"] = {
            int(did_str, 16): SafeAsciiCodec(length)
            for did_str, length in self.decode_dids.items()
        }

      
        self.can_logger = CANLogger(channel=can_cfg["channel"], interface=can_cfg["interface"])
    
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
        report_entries = []
       
        run_start = datetime.now()

        start_time = datetime.now()
        first_request_time = None
        last_response_time = None
        
        with Client(self.conn, request_timeout=2, config=self.client_config) as client:
            client.config['p2_timeout']=6.0
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
                        #subfunc_int = int(subfunc, 16)
                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                        logging.info(f"{tc_id} - {step_desc}: SID={service}, Sub={subfunc}, Expected={expected_bytes}")

                        request_time = datetime.now()
                        data=0xE0
                        response = None
                        if service_int == 0x10:
                            if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                response = client.change_session(subfunc_int)
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                            elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)
                        elif service_int == 0x11:
                              if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                response = client.ecu_reset(subfunc_int)
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                              elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)
                            
                        elif service_int == 0x22:
                              if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                response = client.read_data_by_identifier(subfunc_int)
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                              elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)
                        elif service_int == 0x2E:  # WriteDataByIdentifier
                            if (subfunc_int == 0xF193)or(subfunc_int == 0xF191)or(subfunc_int == 0xF195):
                               if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                response = client.write_data_by_identifier(subfunc_int,"a8123")
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                               elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)
                            if (subfunc_int == 0xF1A1)or(subfunc_int == 0xF197)or(subfunc_int ==0xF18B):
                               if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                response = client.write_data_by_identifier(subfunc_int,"a812")
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                               elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2) 
                                    
                                    
                                    
                               
                            if (subfunc_int == 0xF18C)or(subfunc_int == 0xF1C1):
                               if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                response = client.write_data_by_identifier(subfunc_int,"a8112345a8112345a8112345a8112345")
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                               elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2) 
                               
                            if (subfunc_int == 0xF187):
                               if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                response = client.write_data_by_identifier(subfunc_int,"a8123a8123")
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                               elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)
                                    
                               
                               
                        elif service_int == 0x19:  # ReadDTCInformation
                              if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                response = client.read_dtc_information(subfunc_int,status_mask=0xFF)
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                              elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)   
                            
                            
                        elif service_int == 0x14:  # ClearDiagnosticInformation
                              if subfunc != "":  
                                subfunc_int = int(subfunc, 16)
                                group_of_dtc = subfunc_int
                                response = client.clear_dtc((group_of_dtc))
                              elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)  
                                
                            
                            
                        elif service_int == 0x3E:  # TesterPresent
                              if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                
                                response = response = client.tester_present()
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                              elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)
                            
                            
                        elif service_int == 0x85:
                              if subfunc != "":
                                print("$$$$$$$$$$$UDS Client Config:")   
                                subfunc_int = int(subfunc, 16)
                                
                                response = client.control_dtc_setting(subfunc_int)
                                print("@@@@@@@@@@@ UDS Client Config:")                          
                              elif subfunc == "":
                                 try:
                                       # service_int = int(service, 16)
                                        print("############Effective UDS Client Config:")
                                        subfunc_clean = subfunc.strip()
                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                        self.stack.send(bytes(raw_request))
                                        time.sleep(0.2)
                                        response_data = self.stack.recv()
                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                        # Validate response
                                        if response_data[0] == expected_bytes[0]:
                                            logging.info(f"{tc_id} - {step_desc} -> PASS")
                                        else:
                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                 except Exception as e:
                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                        time.sleep(2)
                                 oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                 time.sleep(2)
                            
                        
                        elif service_int == 0x27: 
                                if subfunc_int  == 0x11:
                                        if subfunc != "":
                                                print("$$$$$$$$$$$UDS Client Config:")   
                                                subfunc_int = int(subfunc, 16)
                                                response = client.request_seed(subfunc_int)
                                                print("@@@@@@@@@@@ UDS Client Config:")    
                                                        
                                                
                                        
                                                time.sleep(0.1)
                                                seed = response.service_data.seed
                                                
                                                logging.info(f"Received Seed: {seed.hex()}")
                                                time.sleep(0.5)
                                                # 2. Send seed to PC via UDP
                                                
                                                udp_ip = "192.168.10.220"
                                                udp_port = 5005
                                                max_retries = 3
                                                retry_delay = 1.0  # seconds
                                                expected_key_length = 8  # Change as needed
                                                
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
                                                                if len(key) != expected_key_length:
                                                                        raise Exception(f"Invalid key length: expected {expected_key_length}, got {len(key)}")
                                                        
                                                                logging.info(f"Received Key: {key}")
                                                                break  # Success
                                                                
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
                                                                                        
                                                # 3. Send Key
                                                key_subfunc = 0x12
                                                response = client.send_key(key_subfunc, key)
                                                #if not response.positive:
                                                # failure_reason = f"NRC (seed): {hex(response.code)}"
                                                #logging.warning(f"{tc_id} {step_desc} -> FAIL - {failure_reason}")
                                                #raise Exception(failure_reason)
                                        elif subfunc == "":
                                                try:
                                                # service_int = int(service, 16)
                                                        print("############Effective UDS Client Config:")
                                                        subfunc_clean = subfunc.strip()
                                                        subfunc_bytes = bytes.fromhex(subfunc_clean) if subfunc_clean else b''
                                                        expected_bytes = [int(b, 16) for b in expected.strip().split()]
                                                        raw_request = bytearray([service_int]) + subfunc_bytes
                                                        logging.info(f"{tc_id} - {step_desc}: Sending {raw_request.hex().upper()}")
                                                        self.stack.send(bytes(raw_request))
                                                        time.sleep(0.2)
                                                        response_data = self.stack.recv()
                                                        logging.info(f"{tc_id} - Received: {response_data.hex().upper()}")
                                                        # Validate response
                                                        if response_data[0] == expected_bytes[0]:
                                                                logging.info(f"{tc_id} - {step_desc} -> PASS")
                                                        else:
                                                                failure_reason = f"Unexpected SID: {response_data[0]:02X}"
                                                                logging.warning(f"{tc_id} - {step_desc} -> FAIL - {failure_reason}")
                                                except Exception as e:
                                                        logging.error(f"{tc_id} - Exception: {type(e).__name__} - {str(e)}")
                                                        oled.display_centered_text(f"{tc_id}\nError: {str(e)[:16]}")
                                                        time.sleep(2)
                                                oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}")
                                                time.sleep(2)   
                              
                                                  

                        response_time = datetime.now()
                        
                        if first_request_time is None:
                                first_request_time = request_time
                                last_response_time = response_time
                        
                        status = "Fail"
                        failure_reason = "-"
                        #if response.positive:
                        actual = list(response.original_payload)
                        if actual[:len(expected_bytes)] == expected_bytes:
                                status = "Pass"
                                logging.info(f"{tc_id} {step_desc} -> PASS")
                        else:
                                failure_reason = f"Expected {expected_bytes}, got {actual}"
                                logging.warning(f"{tc_id} {step_desc} -> FAIL - {failure_reason}")
                        #else:
                           # failure_reason = f"NRC: {hex(response.code)}"
                           # logging.warning(f"{tc_id} {step_desc} -> FAIL - {failure_reason}")
                    except Exception as e:
                        response_time = datetime.now() 
                        status = "Fail"                        
                        failure_reason = str(e)
                        
                        # Sample UDS request: WriteDataByIdentifier (0x2E), DID = 0xF190, 8 bytes of data
                        uds_payload = bytes([
                            service_int,  # Service ID
                            subfunc_int  # Data to write
                        ])
                        
                        # Send UDS message via ISO-TP
                        #stack.send(uds_payload)
                        print("Sent UDS multi-frame request...")
                        
                        
                        logging.error(f"{tc_id} {step_desc} -> EXCEPTION - {failure_reason}")

                    oled.display_centered_text(f"{tc_id}\n{step_desc[:20]}\n{status}")
                    time.sleep(2)
                    
                    relative_request_time = f"{(request_time - start_time).total_seconds():.6f}"
                    relative_response_time = f"{(response_time - start_time).total_seconds():.6f}"
                    
                    report_entries.append({
                        "id": tc_id,
                        "timestamp": relative_request_time,
                        "response_timestamp": relative_response_time,
                        "description": step_desc,
                        "type": "Request Sent",
                        "status": status,
                        "failure_reason": failure_reason
                    })

        run_end = datetime.now() 

        wall_duration = (run_end - run_start).total_seconds()
                
        # Determine report output folder and filename dynamically
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..' , '..'))
        report_dir = os.path.join(project_root, 'output', 'html_reports')
        os.makedirs(report_dir, exist_ok=True)
        report_filename = f"UDS_Report_{int(time.time())}.html"
        report_path = os.path.join(report_dir, report_filename)

        # Convert the report entries for HTML generation
        html_report = convert_report(report_entries)

        # Get dynamic metadata for report:
        full_log_path=self.can_logger.get_log_path() or "N/A"
        can_log_file = os.path.basename(full_log_path)
        report_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"Full path:{full_log_path}")
        print(f"File name:{can_log_file}")
        
        generate_report(
            test_cases=html_report,
            filename=report_path,
            log_filename=can_log_file,
            generated_time=report_timestamp,
            total_duration=wall_duration
        )
        
        oled.display_text("Report Done!\n" + report_filename[:16])
        logging.info(f"Test report saved: {report_filename}")
        self.stop_logging()
        oled.display_text("Log Generated!\n")
