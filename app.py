import os
import json
import uuid
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
from datetime import timedelta, datetime
import requests
from duckduckgo_search import DDGS

# Try to load env but don't fail if missing (it will be missing on Vercel)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.getenv("SESSION_SECRET", "bolt-ai-persistence-key-8812")
app.permanent_session_lifetime = timedelta(days=30)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHATS_FILE = os.path.join(BASE_DIR, "chats.json")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@bolt.io")

def load_json(filename, default={}):
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = json.load(f)
                return content if isinstance(content, type(default)) else default
        except:
            return default
    return default

def save_json(filename, data):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Warning: Could not save to {filename}: {e}")

@app.route("/health")
def health():
    return "Synapse Nominal", 200

@app.route("/")
def home():
    if "user" not in session:
        return redirect(url_for("login_page"))
    if session["user"]["email"] == ADMIN_EMAIL:
        return redirect(url_for("admin_panel"))
    return render_template("index.html", 
                           username=session["user"]["name"], 
                           is_admin=(session["user"]["email"] == ADMIN_EMAIL))

@app.route("/login")
def login_page():
    if "user" in session:
        return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/admin")
def admin_panel():
    if "user" not in session or session["user"]["email"] != ADMIN_EMAIL:
        return redirect(url_for("home"))
    return render_template("admin.html")

@app.route("/api/admin/stats")
def admin_stats():
    if "user" not in session or session["user"]["email"] != ADMIN_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401
    users = load_json(USERS_FILE, default={})
    chats = load_json(CHATS_FILE, default={})
    config = load_json(CONFIG_FILE, default={"system_prompt": "You are Bolt, a fluid and helpful AI assistant."})
    
    user_list = []
    for email, u in users.items():
        user_list.append({
            "email": email,
            "name": u["name"],
            "password": u.get("password", "****"),
            "ip": u.get("ip", "N/A"),
            "banned": u.get("banned", False)
        })

    return jsonify({
        "total_users": len(users),
        "total_chats": sum(len(c) for c in chats.values()) if isinstance(chats, dict) else 0,
        "users": user_list,
        "system_prompt": config["system_prompt"]
    })

@app.route("/api/admin/update_config", methods=["POST"])
def update_config():
    if "user" not in session or session["user"]["email"] != ADMIN_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    config = load_json(CONFIG_FILE, default={})
    config["system_prompt"] = data.get("system_prompt")
    save_json(CONFIG_FILE, config)
    return jsonify({"success": True})

@app.route("/api/admin/update_user", methods=["POST"])
def update_user():
    if "user" not in session or session["user"]["email"] != ADMIN_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    email = data.get("email")
    new_password = data.get("password")
    users = load_json(USERS_FILE, default={})
    if email in users:
        users[email]["password"] = new_password
        save_json(USERS_FILE, users)
        return jsonify({"success": True})
    return jsonify({"error": "User not found"}), 404

@app.route("/api/admin/ban_user", methods=["POST"])
def ban_user():
    if "user" not in session or session["user"]["email"] != ADMIN_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401
    email = request.json.get("email")
    users = load_json(USERS_FILE, default={})
    if email in users:
        users[email]["banned"] = not users[email].get("banned", False)
        save_json(USERS_FILE, users)
        return jsonify({"success": True, "banned": users[email]["banned"]})
    return jsonify({"error": "User not found"}), 404

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    
    users = load_json(USERS_FILE, default={})
    if email in users:
        return jsonify({"error": "User already exists"}), 400
        
    users[email] = {
        "name": name, 
        "password": password, 
        "ip": request.headers.get('X-Forwarded-For', request.remote_addr),
        "banned": False
    }
    if "," in str(users[email]["ip"]): users[email]["ip"] = users[email]["ip"].split(",")[0].strip()
    save_json(USERS_FILE, users)
    
    session.permanent = True
    session["user"] = {"email": email, "name": name}
    return jsonify({"success": True})

@app.route("/api/login", methods=["POST"])
def login_api():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    
    users = load_json(USERS_FILE, default={})
    user = users.get(email)
    
    if user:
        if user.get("banned", False):
            return jsonify({"error": "Your account has been banned."}), 403
        
        if user["password"] == password:
            # Update IP on login
            user["ip"] = request.headers.get('X-Forwarded-For', request.remote_addr)
            if "," in str(user["ip"]): user["ip"] = user["ip"].split(",")[0].strip()
            
            # Initialize search stats if not present
            if "search_count" not in user:
                user["search_count"] = 0
                user["last_search_date"] = ""
                
            save_json(USERS_FILE, users)
            
            session.permanent = True
            session["user"] = {"email": email, "name": user["name"]}
            return jsonify({"success": True})
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login_page"))

@app.route("/api/delete_chat", methods=["POST"])
def delete_chat():
    if "user" not in session: return jsonify({"error": "Unauthorized"}), 401
    chat_id = request.json.get("chat_id")
    user_email = session["user"]["email"]
    all_chats = load_json(CHATS_FILE, default={})
    if user_email in all_chats:
        all_chats[user_email] = [c for c in all_chats[user_email] if c['id'] != chat_id]
        save_json(CHATS_FILE, all_chats)
        return jsonify({"success": True})
    return jsonify({"error": "Chat not found"}), 404

@app.route("/api/rename_chat", methods=["POST"])
def rename_chat():
    if "user" not in session: return jsonify({"error": "Unauthorized"}), 401
    chat_id = request.json.get("chat_id")
    new_title = request.json.get("title")
    user_email = session["user"]["email"]
    all_chats = load_json(CHATS_FILE, default={})
    if user_email in all_chats:
        for c in all_chats[user_email]:
            if c['id'] == chat_id:
                c['title'] = new_title
                break
        save_json(CHATS_FILE, all_chats)
        return jsonify({"success": True})
    return jsonify({"error": "Chat not found"}), 404

@app.route("/get_chats", methods=["GET"])
def get_chats():
    if "user" not in session:
        return jsonify([]), 401
    
    if session["user"]["email"] == ADMIN_EMAIL:
        return jsonify({"error": "Admin cannot access chat history"}), 403
    
    user_email = session["user"]["email"]
    all_chats = load_json(CHATS_FILE, default={})
    user_chats = all_chats.get(user_email, [])
    return jsonify(user_chats)


@app.route("/chat", methods=["POST"])
def chat():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    if session["user"]["email"] == ADMIN_EMAIL:
        return jsonify({"error": "Admin cannot send chat messages"}), 403
        
    user_email = session["user"]["email"]
    user_input = request.json.get("prompt")
    history = request.json.get("history", [])
    chat_id = request.json.get("chat_id")
    image_data = request.json.get("image") # Base64 image
    use_search = request.json.get("use_search", False)
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": os.getenv("SITE_URL", "http://localhost:3000"),
        "X-Title": os.getenv("SITE_NAME", "Bolt AI"),
        "Content-Type": "application/json"
    }

    config = load_json(CONFIG_FILE, default={"system_prompt": f"You are Bolt, a fluid and helpful AI assistant. Addressing the user as {session['user']['name']}."})
    system_prompt = config["system_prompt"]
    
    messages = [{"role": "system", "content": system_prompt}]
    for msg in history:
        messages.append(msg)

    # Handle Search Integration with Brave
    search_context = ""
    if use_search:
        # Check usage limit
        today = datetime.now().strftime("%Y-%m-%d")
        users = load_json(USERS_FILE, default={})
        user = users.get(user_email)
        
        if user:
            # Reset count if new day
            if user.get("last_search_date") != today:
                user["search_count"] = 0
                user["last_search_date"] = today
            
            if user.get("search_count", 0) >= 10:
                # Limit reached
                return jsonify({"error": "Daily web search limit reached (10/10)."}), 403
            
            # Increment count
            user["search_count"] = user.get("search_count", 0) + 1
            save_json(USERS_FILE, users)
            
            # Perform DuckDuckGo Search
            try:
                with DDGS() as ddgs:
                    results = [r for r in ddgs.text(user_input, max_results=5)]
                    if results:
                        search_context = "\n\nWeb Search Results:\n" + "\n".join([f"- {r['title']}: {r['body']} ({r['href']})" for r in results])
            except Exception as e:
                print(f"DuckDuckGo Search Error: {e}")
    
    if search_context:
        messages[0]["content"] += f"\nRelevant context from web: {search_context}"

    # Core user message
    user_msg_content = []
    if image_data:
        user_msg_content.append({
            "type": "image_url",
            "image_url": {"url": image_data}
        })
    user_msg_content.append({"type": "text", "text": user_input})
    
    messages.append({"role": "user", "content": user_msg_content})

    def generate():
        ai_response_full = ""
        payload = {
            "model": "google/gemini-2.0-flash-001",
            "messages": messages,
            "stream": True
        }
        
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            stream=True
        )

        for line in response.iter_lines():
            if line:
                decoded_line = line.decode('utf-8')
                if decoded_line.startswith('data: '):
                    data_str = decoded_line[6:]
                    if data_str == '[DONE]':
                        break
                    try:
                        chunk = json.loads(data_str)
                        content = chunk['choices'][0]['delta'].get('content', '')
                        ai_response_full += content
                        yield f"data: {json.dumps({'content': content})}\n\n"
                    except:
                        continue
        
        # Save after stream ends
        save_current_chat(user_email, chat_id, user_input, ai_response_full)
        yield f"data: {json.dumps({'done': True, 'chat_id': last_save_id})}\n\n"

    return Response(generate(), mimetype='text/event-stream')

last_save_id = None

def save_current_chat(user_email, chat_id, user_input, ai_message):
    global last_save_id
    all_chats = load_json(CHATS_FILE, default={})
    user_chats = all_chats.get(user_email, [])
    
    if chat_id:
        for c in user_chats:
            if c['id'] == chat_id:
                c['messages'].append({"role": "user", "content": user_input})
                c['messages'].append({"role": "assistant", "content": ai_message})
                last_save_id = chat_id
                break
    else:
        # Generate Title
        title = user_input[:30]
        try:
            api_key = os.getenv("OPENROUTER_API_KEY")
            t_res = requests.post("https://openrouter.ai/api/v1/chat/completions", headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, json={
                "model": "google/gemini-2.0-flash-001",
                "messages": [{"role": "system", "content": "Title: 2 words max."}, {"role": "user", "content": user_input}]
            })
            title = t_res.json()['choices'][0]['message']['content'].strip().replace('"', '')
        except: pass
        
        new_id = str(uuid.uuid4())
        user_chats.insert(0, {
            "id": new_id,
            "title": title,
            "messages": [
                {"role": "user", "content": user_input},
                {"role": "assistant", "content": ai_message}
            ]
        })
        last_save_id = new_id
        
    all_chats[user_email] = user_chats
    save_json(CHATS_FILE, all_chats)

@app.errorhandler(401)
def unauthorized(e):
    return render_template("error.html", code=401, title="Identity Verification Required", 
                           message="You must be authenticated to access this neural pathway.", icon="fa-lock"), 401

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, title="Dimension Missing", 
                           message="The neural coordinates you requested do not exist in this reality.", icon="fa-ghost"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, title="Access Terminated", 
                           message="Your credentials have been flagged or access has been revoked by central intelligence.", icon="fa-user-shield"), 403

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, title="System Collapse", 
                           message="A critical error has occurred in the core logic. Rebooting neural buffers...", icon="fa-microchip"), 500

if __name__ == "__main__":
    app.run(debug=True, port=3000)
