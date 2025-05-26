import asyncpg
import asyncio
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, timezone
from tqdm import tqdm
import json

"""
This program used for re-verify integrity of the data stored in DB

It retrieves forensic logs within (user input) time range 
and examine each record to:
- Decrypt stored cipher text
- Calculate hash of message and compare with stored hash
- Compare generated and received timestamps
- Log any decryption or integrity issues
- Retrieves error message if exists

The results are written as text file report with the summary of
Valid Records, Decryption Errors, and Hash Mismatches counts
"""

# Preshared 128-bit AES key
enc_key = b'16byteaeskey1234' 

# Postgres DB Configuration 
PG_config = {
    'user': 'postgres',
    'password': 'postgres',
    'database': 'IoT_Sensor_Backup',
    'host': '127.0.0.1',
    'port': 5432
}

# Function decrypt AES-CBC
def decrypt_data(enc_b64_data, enc_key):
    encrypted_bytes = base64.b64decode(enc_b64_data)
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted_data = unpad(decrypted_padded, AES.block_size)
    return decrypted_data.decode()

# Function to calculate SHA-256 hash of timestamp+raw encryptecd message
def calculate_hash(generated_time, raw):
    combined = (generated_time + raw).encode()
    return hashlib.sha256(combined).hexdigest()


async def analyzer(start_dt, end_dt, output_file):
    try:
        # 1. connect to PostgreSQL
        pool = await asyncpg.create_pool(**PG_config)
    except Exception as e:
        print(f"Database connection error: {e}")
        return

    async with pool.acquire() as conn:
        # 2. query data within selected period
        rows = await conn.fetch("""
            SELECT id, raw_data, generated_time, received_time, hash, error
            FROM forensic_log
            WHERE received_time BETWEEN $1 AND $2
            ORDER BY received_time ASC;
            """, start_dt, end_dt)
        print(f"Queried {len(rows)} records between {start_dt} and {end_dt}")
        # 2.1 if no record is found in the selected range, stop the program
        if not rows:
            print("No records found in that time range. Skipping analysis.")
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("=== Summary ===\n")
                f.write("No records found in the specified time period.\n")
            return

        # 3. create file for storing the analysis log
        with open(output_file, "w", encoding="utf-8") as f:
            # counter for summary
            valid_count = 0
            error_count = 0
            hash_fail_count = 0

            # 4. loop through each record queried with progress bar
            for row in tqdm(rows, desc="Analyzing", unit="record"):
                record_id = row['id']
                raw_data_enc = row['raw_data']
                generated_time = row['generated_time']
                received_time = row['received_time']
                stored_hash = row['hash']
                error_msg = row['error']

                f.write(f"\n===== Record ID {record_id} =====\n")

                # 4.1 if there's error message
                if error_msg:
                    error_count += 1
                    f.write(f"Received Time   : {received_time}\n")
                    f.write(f"Error Logged    : {error_msg}\n")
                    f.write(f"Raw Data        : {raw_data_enc}\n")
                
                # 4.2 normal record( no error message stored)
                else:
                    try:
                        # decrypt AES-CBC
                        decrypted_json = decrypt_data(raw_data_enc, enc_key)
                        original_time = json.loads(decrypted_json)["timestamp"]
                        
                        # re-calculate hash of time+raw
                        recomputed_hash = calculate_hash(original_time, raw_data_enc)
                    
                        # compare stored hash with new hash
                        hash_valid = (recomputed_hash == stored_hash)
                        if not hash_valid:
                            hash_fail_count += 1
                        else:
                            valid_count += 1

                        # compare original and time database receive the record
                        generated_time_utc = generated_time.replace(tzinfo=timezone.utc)
                        time_diff_sec = (received_time - generated_time_utc).total_seconds()

                        # write down all content+analysis of the record
                        f.write(f"Generated Time  : {generated_time}\n")
                        f.write(f"Received Time   : {received_time}\n")
                        f.write(f"Time Difference : {time_diff_sec * 1000:.3f} ms\n")
                        f.write(f"Hash Valid      : {hash_valid}\n")
                        f.write(f"Decrypted Data  : {decrypted_json}\n")
                    # 4.3 if there's error during decryption or analysis
                    except Exception as e:
                        error_count += 1
                        f.write(f"Received Time   : {received_time}\n")
                        f.write(f"Decryption Error: {e}\n")
                        f.write(f"Raw Data        : {raw_data_enc}\n")
                        
                f.write("===============================\n")

            # 5. print summary of all record types
            f.write(f"\n=== Summary ===\n")
            f.write(f"Valid Records      : {valid_count}\n")
            f.write(f"Decryption Errors  : {error_count}\n")
            f.write(f"Hash Mismatches    : {hash_fail_count}\n")

    await pool.close()

# Function to get user input and run analysis
def main():
    start_input = input("Enter start datetime (DD/MM/YYYY HH:MM:SS): ").strip()
    end_input = input("Enter end datetime (DD/MM/YYYY HH:MM:SS): ").strip()

    try:
        start_dt = datetime.strptime(start_input, "%d/%m/%Y %H:%M:%S")
        end_dt = datetime.strptime(end_input, "%d/%m/%Y %H:%M:%S")
    except ValueError:
        print("Invalid datetime format.")
        return

    output_file = f"logs/analysis_{start_dt.strftime('%Y%m%d_%H%M%S')}_to_{end_dt.strftime('%Y%m%d_%H%M%S')}.txt"

    asyncio.run(analyzer(start_dt, end_dt, output_file))
   
# only run if the script is execute directly
if __name__ == "__main__":
    main()
