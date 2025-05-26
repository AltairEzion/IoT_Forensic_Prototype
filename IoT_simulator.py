import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import time
import random
import json
from datetime import datetime

"""
This code generate temperature reading by random number
then encrypt temperature and current time with AES-CBC cipher
and send to MQTT broker
"""

##### Declare variables #####
# setting for test cases
use_enc = True
spike_chance = 0.001
publish_interval = 5
pub_limit = None

# Pre-shared key - 16 bytes: 128 bit key = AES-128
enc_key = b'16byteaeskey1234'  

# MQTT protocol config
broker = "localhost" 
port = 1884
user = "test_access_device1"
pwd = "test_password_device1"
topic = "devices/temperature/t_Thermostat"

# (for test case) function to let user change behaviour of the program
def config():
    print("===== IoT Sensor Simulator Configuration =====\n\n###Leave blank for default###")
    global use_enc, spike_chance, publish_interval, pub_limit
    
    # 1. Send data as encrypted text or plain text
    ans = input("Use encryption? (y/n) [default: y]: ").strip().lower()
    if ans != "":
        if ans in ["n", "no"]:
            use_enc = False
        elif ans in ["y", "yes"]:
            use_enc = True
        else:
            print("Invalid input, using default.")
    
    # 2. change probability to generate anomalies data
    try:    
        ans = float(input("Anomaly (spike) chance as a percentage (e.g., 10 for 10%) [default: 0.01]: ").strip())
        if ans != "":
            spike_chance = float(float(ans)/100)
            print(spike_chance)
    except ValueError:
        print("Invalid input, using default.")

    # 3. set frequency of the main loop
    try:
        ans = int(input("Publish interval in seconds [default: 5]: ").strip())
    
        if ans != "" and ans >= 0:
            publish_interval = int(ans)
        if ans == 0:
            print("##### WARNING! Publish data with no delay. #####")
            
            # 3.1 if has no publish interval, ask for number of message to be sent
            try:
                ans = int(input("pleas set number of packages to send [default: 100]: ").strip())
                if ans > 0:
                    pub_limit = int(ans)  
                else:
                        pub_limit = 100
            except ValueError:
                print("Invalid input, using default.")
                pub_limit = 100    
    except ValueError:
        print("Invalid input, using default.")
    
    # 4. display summary of program settings
    print(
f"""\n  ++++++ Settings ++++++
- Use Encryption: {use_enc}
- Anomaly chance: {spike_chance*100}%
- Publish interval: {publish_interval} second
- Publish limit: {pub_limit if pub_limit else 'Unlimited'}   \n""")
      
# Function to print message when successfully connect to MQTT broker
def on_connect(client, userdata, flags, reasonCode, properties):
    if reasonCode != 0:
        print(f"MQTT Connect failed: {reasonCode}")
    else:    
        print("Connected to MQTT")

# Function to encrypt data with AES Cipher Block Chaining mode
def encrypt_data(data, enc_key):
    """Encrypts data using AES with a random IV."""
    iv = Random.get_random_bytes(16)  # gen random IV for each encryption session 
    cipher = AES.new(enc_key, AES.MODE_CBC, iv) # create AES cipher object
    padded_data = pad(data.encode(), AES.block_size) # add padding to make it multiple of its block size(16 bytes)
    encrypted_bytes = iv + cipher.encrypt(padded_data)  # Prepend IV to encrypted data
    return base64.b64encode(encrypted_bytes).decode()

# Function to random number (with 2 decimals) to use as temperature reading
def get_temperature(normal_temp, fluctuation, spike_chance): 
    """Simulate temperature readings with occasional spikes."""
    
    # case 1, default minor chance to create spike, add 10-30 to normal temperature(25)
    if random.random() < spike_chance:
        return round(normal_temp + random.uniform(10, 30), 2)  # Simulate a spike
    
    # case 2, normal temperature random between 22-28 (25 +-3)
    return round(normal_temp + random.uniform(-fluctuation, fluctuation), 2)


# Main program
def main():
    # 1. call function to ask user for settings to change program behaviours (for testing purpose only)
    config()
    
    # 2. connect to MQTT broker as publisher using username and password
    client = mqtt.Client(protocol=mqtt.MQTTv5, callback_api_version=CallbackAPIVersion.VERSION2)
    client.username_pw_set(user, pwd)
    client.on_connect = on_connect
    try:
        client.connect(broker, port, 60) # connect to broker and set keepalive interval(60 sec) 
    except Exception as e:
            # Capture the full error traceback
            error_details = f"{type(e).__name__}: {str(e)}"
            print(f"Failed to connect to MQTT broker: {error_details}")
            exit(1) # If fail to connect, stop the program  
    client.loop_start()

    try:
        c = 0 # counter for test case (to send a set number of messages)
        
        # 3. Main function that loop forever until interrupted, act as iot device
        while True:
            # 3.1 get current time in format [year-month-day hour:minutue:second:millisecond]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            
            # 3.2 simulate sensor reading - random sensor value 25 +-3 
            # with set chance to increase suddenly as anomaly event of forensic interest
            temperature = get_temperature(25.0, 3, spike_chance)
            
            # 3.3 Create and convert the value to JSON JavaScript object
            payload = {
                "temperature": str(temperature),
                "timestamp": timestamp
            }
            
            # 3.4 Encrypt prepared payload with AES-CBC algorithm
            encrypted = encrypt_data(json.dumps(payload), enc_key)
            
            # (for test case) send plaintext instead of encrypt text if encryption is set to not used 
            if not use_enc:
                encrypted = json.dumps(payload)
                
            # 3.5 Public encrypted text to MQTT broker 
            # - SOC server will subscribe to the same topic to receive the message    
            client.publish(topic, encrypted, qos=1)
            
            # 3.6 display the generated temperature+timestamp and encrypted format for troubleshoot
            print(f"\nraw data: {payload}")
            print(f"Published: {encrypted}")
            
            # (for test case) limit number of publication
            if pub_limit is not None:
                c += 1
                if c >= pub_limit:
                    print(f"\n\nSent {pub_limit} messages. Stopping.")
                    break
                
            # 3.7 delay X seconds before publishing again
            time.sleep(publish_interval) 
    
    # 3.8 stop the program (press ctrl+c to exit program)
    except KeyboardInterrupt:
        print("Disconnecting...")
        client.loop_stop()
        client.disconnect()

# only run if the script is execute directly
if __name__ == "__main__":
    main()