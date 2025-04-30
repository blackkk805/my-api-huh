import json
import time
import requests
from threading import Thread
from flask import Flask, jsonify, Response, request
import aiohttp
import asyncio
from protobuf_decoder.protobuf_decoder import Parser  # تأكد من تثبيت المكتبة
import json
import time
import random
import aiohttp
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import player_info_pb2
import mymessage_pb2

app = Flask(__name__)

key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

accounts = json.load(open("accs.json"))
tokens = []

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()


def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == "string":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
            result_dict[result.field] = field_data
    return result_dict
def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)
def get_available_(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return parsed_results_dict 
def GetToken():
    global tokens
    while True:
        tokens.clear()
        for u, p in accounts.items():
            try:
                response = requests.get(f"https://web-production-b99dc.up.railway.app/GeneRate-Jwt?Uid={u}&Pw={p}")
                text = response.text
                token_start = text.find("eyJ")
                if token_start != -1:
                    token = text[token_start:text.find('\n', token_start)]
                    if token:
                        tokens.append({"token": token})  # الهيكل: [{"token": "..."}, ...]
            except Exception as e:
                print(f"Error fetching token for {u}: {e}")

        time.sleep(12000)

async def get_tokens(session):
    # تُرجع التوكنات المُدارة مسبقًا في القائمة tokens
    return tokens

def get_jwt():
    try:
        # استخدم التوكن الأول من القائمة (يمكنك اختيار توكن آخر حسب الحاجة)
        if tokens:
            return tokens[0]["token"]
        else:
            return None
    except Exception as e:
        print(f"Error getting JWT: {e}")
        return None
    
def ShuffleTokens():
    global tokens
    while True:
        # إعادة ترتيب التوكنات عشوائيًا بعد الـ 100 توكن الأولى كل 10 دقائق (600 ثانية)
        if len(tokens) > 200:
            tokens[200:] = random.sample(tokens[200:], len(tokens[200:]))
        
        time.sleep(600)

# تشغيل الخيوط
Thread(target=GetToken, daemon=True).start()
Thread(target=ShuffleTokens, daemon=True).start()

@app.route("/tokens", methods=["GET"])
def get_token():
    return jsonify(tokens)
    
def create_protobuf(uid_value, action_type):
    message = uid_generator_pb2.uid_generator()
    message.uid = uid_value      # بدلاً من mahmoud
    message.action_type = action_type  # بدلاً من mahmoud2
    return message.SerializeToString()

def encrypt_message(field2_value):
    encrypted_id = Encrypt_ID(field2_value)  # استخدم الدالة الجديدة
    message = mymessage_pb2.MyMessage()
    message.field1 = 9797549324
    message.field2 = int(encrypted_id, 16)  # تأكد من التحويل الصحيح
    message.field3 = 22

    serialized_message = message.SerializeToString()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(serialized_message, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    hex_encrypted_data = binascii.hexlify(encrypted_message).decode('utf-8')
    print(f"hex {hex_encrypted_data}")
    return hex_encrypted_data
    
def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def encrypt_aes(hex_data, key, iv):
    key = key[:16]
    iv = iv[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def hex_to_binary(hex_string):
    return bytes.fromhex(hex_string)

def verify_key(api_key):
    # تأكد من أن المفتاح مطابق للمفتاح السري الخاص بك
    return api_key == "a"
   
def decode_protobuf(binary_data):
    info_response = player_info_pb2.Info()
    info_response.ParseFromString(binary_data)
    return info_response
    
def format_to_txt(parsed_data, uid):
    try:
        account_info = parsed_data.get(1, {}).get("data", {})
        guild_info = parsed_data.get(6, {}).get("data", {})
        main_info = parsed_data.get(9, {}).get("data", {})

        data_map = {
            "AccountName": account_info.get(3, {}).get("data", "N/A"),
            "AccountLevel": account_info.get(6, {}).get("data", "N/A"),
            "AccountEXP": account_info.get(7, {}).get("data", "N/A"),
            "AccountLikes": account_info.get(21, {}).get("data", "N/A"),
            "AccountRegion": account_info.get(5, {}).get("data", "N/A"),
            "AccountSignature": main_info.get(9, {}).get("data", "N/A"),
            "EquippedTittle": account_info.get(15, {}).get("data", "N/A"),
            "EquippedWeapon": account_info.get(16, {}).get("data", []),
            "ReleaseVersion": account_info.get(50, {}).get("data", "N/A"),
            "BrRank": account_info.get(22, {}).get("data", "N/A"),
            "CsRank": account_info.get(23, {}).get("data", "N/A"),
            "AccountCreateTime": account_info.get(44, {}).get("data", "N/A"),
            "AccountLastLogin": account_info.get(45, {}).get("data", "N/A"),
            "GuildName": guild_info.get(2, {}).get("data", "N/A"),
            "GuildID": guild_info.get(1, {}).get("data", "N/A"),
            "GuildOwner": guild_info.get(3, {}).get("data", "N/A"),
            "GuildLevel": guild_info.get(4, {}).get("data", "N/A"),
            "GuildCapacity": guild_info.get(6, {}).get("data", "N/A"),
            "GuildMember": guild_info.get(5, {}).get("data", "N/A"),
        }

        txt_output = []
        txt_output.append(f"- PLayer Id InFo > {uid}\n")
        txt_output.append("─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ")
        txt_output.append("[1] - ProFile InFo : \n")
        txt_output.append(f" - Name > {data_map['AccountName']}")
        txt_output.append(f" - Uid > {uid}")
        txt_output.append(f" - Level > {data_map['AccountLevel']} [Exp : {data_map['AccountEXP']}]")
        txt_output.append(f" - Likes > {data_map['AccountLikes']}")
        txt_output.append(f" - Region > {data_map['AccountRegion']}")
        txt_output.append(f" - Bio > {data_map['AccountSignature']}")
        txt_output.append("\n─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ")
        txt_output.append("[2] - Guild InFo : \n")
        txt_output.append(f" - Guild Name > {data_map['GuildName']}")
        txt_output.append(f" - Guild Uid > {data_map['GuildID']}")
        txt_output.append(f" - Guild Owner Uid > {data_map['GuildOwner']}")
        txt_output.append(f" - Guild Level > {data_map['GuildLevel']}")
        txt_output.append(f" - Guild Capacity > {data_map['GuildCapacity']}")
        txt_output.append(f" - Guild Members > {data_map['GuildMember']}")
        txt_output.append("\n─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ")
        txt_output.append("[3] - Equipped Items InFo : \n")
        txt_output.append(f" - Equipped Title Uid > {data_map['EquippedTittle']}")
        weapon_data = data_map['EquippedWeapon']
        if not isinstance(weapon_data, list):
            weapon_data = [weapon_data]
        txt_output.append(f" - Equipped Weapons > {', '.join(map(str, weapon_data))}")
        txt_output.append("\n─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─")
        txt_output.append("[4] - Status InFo : \n")
        txt_output.append(f" - Release Version > {data_map['ReleaseVersion']}")
        txt_output.append(f" - Br RanK Pointes > {data_map['BrRank']}")
        txt_output.append(f" - Cs RanN Pointes > {data_map['CsRank']}")
        txt_output.append(f" - Created At > {format_timestamp(data_map['AccountCreateTime'])}")
        txt_output.append(f" - Last Login At > {format_timestamp(data_map['AccountLastLogin'])}")
        txt_output.append("\n─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ")
        txt_output.append("[5] - C4 Team ContaCt InFo : \n")
        txt_output.append(" - Tg ChAnnel > @C4_Team_Officiel")
        txt_output.append(" - Tg Chat > @C4_Team_Chat")
        txt_output.append(" - Officiel Website > https://c4teampro.free.bg")

        return "\n".join(txt_output)

    except Exception as e:
        return f"Error formatting data: {str(e)}"

def format_timestamp(timestamp):
    from datetime import datetime
    try:
        return datetime.utcfromtimestamp(int(timestamp)).strftime('%d %B %Y at %H:%M:%S')
    except Exception:
        return "N/A"

async def fetch_player_info(encrypted_uid, token):
    url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    payload = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Authorization': f"Bearer {token}",
        'X--Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers) as response:
            hex_output = await response.read()
            return hex_output.hex()
        

async def sendlike(encrypted_uid, count):
    async with aiohttp.ClientSession() as session:
        # جلب الإعجابات قبل
        info_before_hex = await fetch_player_info(encrypted_uid, session)
        parsed_info_before = json.loads(get_available_room(info_before_hex))
        likes_before = parsed_info_before.get("1", {}).get("data", {}).get("21", {}).get("data", 0)
        
        # إرسال اللايكات
        tasks = []
        for token_data in tokens[:count]:
            tasks.append(send_like_request(session, token_data["token"], encrypted_uid))
        results = await asyncio.gather(*tasks)
        success = sum(1 for res in results if res)
        
        # جلب الإعجابات بعد
        info_after_hex = await fetch_player_info(encrypted_uid, session)
        parsed_info_after = json.loads(get_available_room(info_after_hex))
        likes_after = parsed_info_after.get("1", {}).get("data", {}).get("21", {}).get("data", likes_before)
        
        return {
            "likes_before": likes_before,
            "likes_after": likes_after,
            "success": success
        }

async def send_like_request(session, token, encrypted_uid):
    url = "https://clientbp.ggblueshark.com/LikeProfile"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }
    try:
        async with session.post(url, headers=headers, data=bytes.fromhex(encrypted_uid)) as response:
            return response.status == 200
    except:
        return False
    
@app.route('/info', methods=['GET'])
async def info():
    uid = request.args.get('uid')
    keyy = request.args.get('key')
    if not uid or not keyy or keyy != 'a':
        return Response("Invalid request", mimetype='text/plain', status=400)
    jwt_token = get_jwt()
    if not jwt_token:
        return Response("No tokens available!", mimetype='text/plain', status=500)
    try:
        encrypted_id = Encrypt_ID(uid)
        plain_text = f"08{encrypted_id}1007"
        encrypted_data = encrypt_api(plain_text)
    except Exception as e:
        return Response(f"Encryption error: {str(e)}", mimetype='text/plain', status=500)

    url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {jwt_token}',  
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=bytes.fromhex(encrypted_data)) as response:
                hex_response = await response.read()
                hex_response = hex_response.hex()
                print(hex_response)
                parsed_data = get_available_(hex_response)
                print(parsed_data)
                txt_output = format_to_txt(parsed_data, uid)
                return Response(txt_output, mimetype='text/plain')
    except Exception as e:
        return Response(f"API error: {str(e)}", mimetype='text/plain', status=500)

@app.route('/spam', methods=['GET'])
def friend_spam():
    uid = request.args.get('uid')
    keyy = request.args.get('key')
    if not uid:
        return Response(" - PLease Add Uid !", mimetype='text/plain')
    if not keyy:
        return Response(" - PLease Add Key !", mimetype='text/plain')   
    if keyy != 'a':
        return Response(" - Bad Key !", mimetype='text/plain')     
    try:
        uid_int = int(uid)
    except ValueError:
        return Response(" - Error : Uid Bad !", mimetype='text/plain')

    hex_encrypted_data = encrypt_message(uid_int)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    response_messages = loop.run_until_complete(send_requests(tokens, hex_encrypted_data, "spam"))
    
    return Response(response_messages, mimetype='text/plain')

  
@app.route('/visit', methods=['GET'])
def visitm():
    uid = request.args.get('uid')
    keyy = request.args.get('key')
    if not uid:
        return Response(" - PLease Add Uid !", mimetype='text/plain')
    if not keyy:
        return Response(" - PLease Add Key !", mimetype='text/plain')   
    if keyy != 'a':
        return Response(" - Bad Key !", mimetype='text/plain')     
    try:
        uid_int = int(uid)
    except ValueError:
        return Response(" - Error : Uid Bad !", mimetype='text/plain')

    hex_encrypted_data = encrypt_message(uid_int)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    response_messages = loop.run_until_complete(send_requests(tokens, hex_encrypted_data, "visit"))
    
    return Response(response_messages, mimetype='text/plain')


from datetime import datetime, timedelta
import time

last_like_time = {}

async def send_parallel_requests(tokens, encrypted_uid, count):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for token_data in tokens[:count]:
            token = token_data["token"]
            tasks.append(send_request(session, token, encrypted_uid))
        results = await asyncio.gather(*tasks)
        return results

@app.route('/like', methods=['GET'])
def like_endpoint():
    uid = request.args.get('uid')
    keyy = request.args.get('key')
    count = int(request.args.get('count', 99))
    
    if not uid or not keyy or keyy != "a":
        return Response("Invalid request", mimetype='text/plain', status=400)
    
    try:
        encrypted_id = Encrypt_ID(uid)
        plain_text = f"08{encrypted_id}1007"
        encrypted_uid = encrypt_api(plain_text)

        result = asyncio.run(sendlike(encrypted_uid, count))
        
        return Response(
            f"- تم إرسال {count} لايك! ✅\n"
            f"- الإعجابات قبل: {result['likes_before']}\n"
            f"- الإعجابات بعد: {result['likes_after']}\n"
            f"- الطلبات الناجحة: {result['success']}",
            mimetype='text/plain'
        )
    
    except Exception as e:
        return Response(f"Error: {str(e)}", mimetype='text/plain', status=500)
    
async def send_request(session, token, hex_encrypted_data, url, semaphore):
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'Authorization': f"Bearer {token}",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }

    edata = bytes.fromhex(hex_encrypted_data)
    ##print(headers)
    async with semaphore:
        try:
            async with session.post(url, data=edata, headers=headers) as response:
                return response
        except Exception as e:
            print(f"Error sending request with token {token}: {e}")
            return None
            
async def send_requests(tokens, hex_encrypted_data, request_type):
    if request_type == "spam":
        url = "https://clientbp.ggblueshark.com/RequestAddingFriend"
    elif request_type == 'visit':
    	url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    else:
        return ["Invalid request type"]
        
    max_concurrent_requests = 200
    semaphore = asyncio.Semaphore(max_concurrent_requests)

    async with aiohttp.ClientSession(conn_timeout=5, read_timeout=5) as session:
        tasks = []
        if request_type == 'spam':
        	h = tokens[:100]
        elif request_type == 'visit':
        	h = tokens[:200]
        ##print(h)
        for token in h:
            tasks.append(send_request(session, token["token"], hex_encrypted_data, url, semaphore))

        responses = await asyncio.gather(*tasks)

        successful_requests = sum(1 for response in responses if response and response.status == 200)

    return f" - Successfuly Send {request_type} !"
    

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
