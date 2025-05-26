import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime
import asyncpg
import asyncio
import hashlib
import base64
import json

"""
This program act as sensor reading receiver in SOC server
It receive data from iot device then store raw encrypted data
along with hash and timestamp to be able to verify data integrity
then decrypt data and standardise sensor reading format before send
to data visualiser module( Thingsboard)

This script utilise asyncio for concurrent interaction with PostgreSQL
while MQTT clients run in background threads

It connect to:
- MQTT | IOT broker (subscriber)       | to receive sensor data from iot device
- MQTT | Thingsboard broker (publisher)| to send decrypted data to visualised
- Postgres | Database to store data    | store raw data/error for forensic analysis
"""

##### Declare variables #####
# pre-shared Encryption key
enc_key = b'16byteaeskey1234'

# IoT MQTT config - to receive data from IOT
i_broker = "localhost"
i_port = 1884
user = "test_access_device1"
pwd = "test_password_device1"
i_topic = "devices/temperature/t_Thermostat" # same topic as iot device

# ThingsBoard MQTT config - to send data to Thingsboard
tb_broker = "localhost"
tb_port = 1883
access_token = "WbVeIxCkfl3PRRsEeqse"
tb_topic = "v1/devices/me/telemetry"

# Postgres database config - to save data as evidence
PG_config = {
    'user': 'postgres',
    'password': 'postgres',
    'database': 'IoT_Sensor_Backup',
    'host': '127.0.0.1',
    'port': 5432
}

# Function to decrypt AES-CBC cipher with pre-shared key
def decrypt_data(enc_b64_data, enc_key):
    """Decrypts AES-encrypted base64 string with IV prepended."""
    encrypted_bytes = base64.b64decode(enc_b64_data) # Change strings into bytes format
    iv = encrypted_bytes[:16]  # Extract the first 16 bytes as IV
    ciphertext = encrypted_bytes[16:] # Extract the ciphertext

    # decrypt and unpad the ciphertext
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted_data = unpad(decrypted_padded, AES.block_size)
    
    return decrypted_data.decode() # convert bytes to string before return

# Function to insert data into PostgreSQL DB
async def insert_to_db(pgSQL, raw: str, time: str,error=None):
    try:
        async with pgSQL.acquire() as conn:

            # CASE 1: store normally includes:
            #     - hash (SHA-256 of timestamp + raw data)
            #     - raw encrypted data from iot 
            #     - original timestamp (from decrypted message)  
            #     - received time( auto assigned in DB)  
            if error is None:
                # Successful decryption case
                
                # format time string to be same as DB's
                time_obj = datetime.strptime(time, "%Y-%m-%d %H:%M:%S.%f")
                # calculate hash
                hash_value = hashlib.sha256(f"{time}{raw}".encode()).hexdigest()
                # insert to DB
                await conn.execute(
                    "INSERT INTO forensic_log (hash, raw_data, generated_time) VALUES ($1, $2, $3)",
                    hash_value, raw, time_obj
                )
                print(f"Saved to DB. Hash: {hash_value}")
                
            # CASE 2: store error text includesL:
            #     - raw encrypted data from iot
            #     - error log that occur during decrypt/normalise process
            #     received time( auto assigned in DB)
            else:
                # Error case - store raw data with error message
                await conn.execute(
                    "INSERT INTO forensic_log (raw_data, error) VALUES ($1, $2)",
                    raw, error
                )
                print(f"Saved error to DB: {error}.")
    except Exception as e:
        print("DB insert error:", e)

# Function to connect to MQTT and listen to selected topic
def on_connect(client, userdata, flags, reasonCode, properties):
    if reasonCode != 0:
        print(f"MQTT Connect failed: {reasonCode}")
    else:
        print("Connected to MQTT")
        client.subscribe(i_topic, qos=1)

# Function called when successfully subscribe to topic
def on_subscribe(client, userdata, mid, reasonCodes, properties):
    print(f"Subscribed to {i_topic}, RC: {reasonCodes}")

# Function to run routine eveytime message from iot arrive
# This include: Decrypt message, store data into DB, and send data to Visualiser
def on_message(client, userdata, msg):
    """run for each message receive from iot MQTT broker"""
    
    # 5.1 get message content as string
    raw = msg.payload.decode()
    print(f"\nTopic: {msg.topic} \nReceive: {raw}")
    
    # 5.2 declare variables for accessibility
    tb_client = userdata['tb_client']
    loop = userdata['loop']
    
    # 5.3 reset necessary variables
    temperature = None
    time = None
    
    # 5.4 decide whether data is corrupted or not
    try:
        # 5.4.1 try decrypt AES cipher
        decrypted_json = decrypt_data(raw, enc_key)
        
        # 5.4.2 convert decrypted JSON-format string into Python dictionary
        data = json.loads(decrypted_json) 
        temperature = data["temperature"] # extract each field of dict into variable
        time = data["timestamp"]
        
        print(f"Decrypted data: Temp: {temperature}, Time: {time}")
        
        # 5.4.3 store successful decryption
        asyncio.run_coroutine_threadsafe(
            insert_to_db(userdata['pgSQL'], raw, time),
            loop
        )
    # If any error occur during 5.4, store the Error log to DB 
    # along with raw cipher text that can't be decrypted
    except Exception as e:
        # Capture the full error traceback
        error_details = f"{type(e).__name__}: {str(e)}"
        print(f"Failed to decrypt or parse: {error_details}")
        
        # Store error in database for forensic purposes
        asyncio.run_coroutine_threadsafe(
            insert_to_db(userdata['pgSQL'], raw, None, error_details),
            loop
        )
    
    # 5.5 publish extracted sensor reading to Thingsboard MQTT broker
    # with set template
    # temperature is None when program fails to decode message from iot device
    # in that case, error is stored along with the problemetic raw content
    if temperature is not None:
        # Forward to ThingsBoard
        payload_to_tb = f"{{temperature:{temperature}}}"
        tb_client.publish(tb_topic, payload_to_tb, qos=1)
        print(f"Forwarded to ThingsBoard: {payload_to_tb}")
    

# Core task of the program
async def receiver():
    # 1. Get current asynchronous event( to manage later)
    loop = asyncio.get_running_loop()
    
    # 2. Connect to Thingsboard MQTT broker as publisher using access token 
    tb_client = mqtt.Client(protocol=mqtt.MQTTv5, callback_api_version=CallbackAPIVersion.VERSION2)
    tb_client.username_pw_set(access_token)
    try:
        tb_client.connect(tb_broker, tb_port, 60)
    except Exception as e:
        error_details = f"{type(e).__name__} - {str(e)}"
        print(f"Cannot connect to Thingsboard(MQTT): {error_details}")
        exit(1) # Stop the program if can't connect to MQTT broker
    tb_client.loop_start()
     
    # Declare dummy variables just in case the connection fails
    pgSQL = None
    subscriber = None
    
    try:
        # 3. Connect to PostgreSQL
        print("Connecting to PostgreSQL...")
        pgSQL = await asyncpg.create_pool(**PG_config)
        
        # 4. Connect to IoT MQTT client as subscriber using username, password
        subscriber = mqtt.Client(protocol=mqtt.MQTTv5, callback_api_version=CallbackAPIVersion.VERSION2)
        subscriber.username_pw_set(user, pwd)
        subscriber.user_data_set({  # user data for passing to other function
                    'pgSQL': pgSQL,
                    'tb_client': tb_client,
                    'loop': loop
                })
    
        subscriber.on_connect = on_connect
        subscriber.on_message = on_message
        subscriber.on_subscribe = on_subscribe
    
        subscriber.connect(i_broker, i_port, 60)
        subscriber.loop_start()
    
        # 5. keep the program alive while MQTT and DB run in bg threads
        # The program is now idle,
        # waiting for incoming MQTT message (subscriber.on_message())
        while True:
            await asyncio.sleep(1)
    # 6. stop the program if canceled/interrupted
    except asyncio.CancelledError:
        print("Main task canceled.")
    except Exception as e:
        print("Error occurred:", e)
    finally:
        print("Shutting down...")
        if subscriber:
            subscriber.disconnect()
            subscriber.loop_stop()
        if tb_client:
            tb_client.disconnect()
            tb_client.loop_stop()
        if pgSQL:
            await pgSQL.close()

# Program entry point
def main():
    # Create a new asynchronous event 
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Schedule the receiver() function as a main task on the async event
    task = loop.create_task(receiver())
    
    try:
        # Start the async event until interrupted
        loop.run_until_complete(task)
    except KeyboardInterrupt:
        print("Interrupted. Cleaning up...")
        # stop the task but let current task finish to prevent program flow interrupt
        task.cancel() 
        loop.run_until_complete(task)
    finally:
        loop.close()

# only run if the script is execute directly
if __name__ == "__main__":
    main()