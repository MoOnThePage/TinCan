import streamlit as st
import jwt
import datetime
import hashlib
import hmac
import os

########################################################################################################################
### Session Persistence
########################################################################################################################
# Initialize session state for persistence
def persist_session_state():
    """Persist critical session state across refreshes"""
    # Keys to persist
    persistent_keys = ["auth_token", "user", "last_login"]

    # Check if we have persisted data
    if 'persisted_data' not in st.session_state:
        st.session_state.persisted_data = {}

    # On page load, restore from persistence
    if not st.session_state.persisted_data:
        # Try to get from browser local storage via query params
        query_params = st.experimental_get_query_params()
        if "persisted" in query_params:
            import json
            import base64
            try:
                persisted = base64.b64decode(query_params["persisted"][0]).decode()
                st.session_state.persisted_data = json.loads(persisted)

                # Restore persisted keys to session state
                for key in persistent_keys:
                    if key in st.session_state.persisted_data:
                        st.session_state[key] = st.session_state.persisted_data[key]
            except:
                pass

    # On changes, update persistence
    for key in persistent_keys:
        if key in st.session_state:
            st.session_state.persisted_data[key] = st.session_state[key]

    # Save to query params (simulates local storage)
    if st.session_state.persisted_data:
        import json
        import base64
        persisted_str = json.dumps(st.session_state.persisted_data)
        encoded = base64.b64encode(persisted_str.encode()).decode()
        st.experimental_set_query_params(persisted=encoded)
########################################################################################################################
### EOF Session Persistence
########################################################################################################################

########################################################################################################################
### Authentication System
########################################################################################################################
class EnterpriseAuth:
    persist_session_state()
    def __init__(self):
        self.allowed_users = {
            "user1": {
                "id": "user_001",
                "email": "user1@company.com",
                "password_hash": st.secrets["users"]["user1_hash"],  # SHA-256 hash
                "role": "admin"
            },
            "user2": {
                "id": "user_002",
                "email": "user2@company.com",
                "password_hash": st.secrets["users"]["user2_hash"],
                "role": "user"
            }
        }
        self.jwt_secret = st.secrets["jwt"]["secret"]
        self.token_expiry = 3600 * 4  # 4 hour

    def verify_password(self, password, stored_hash):
        """Verify password against stored hash"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        # Use hmac.compare_digest for timing attack protection
        return hmac.compare_digest(password_hash, stored_hash)

    def generate_token(self, user_id):
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=self.token_expiry),
            'iat': datetime.datetime.utcnow()
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')

    def verify_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            st.error("Session expired. Please login again.")
            return None
        except jwt.InvalidTokenError:
            return None

    def login_form(self):
        """Display login form"""
        with st.form("login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")

            if submit:
                if username in self.allowed_users:
                    user = self.allowed_users[username]
                    if self.verify_password(password, user["password_hash"]):
                        token = self.generate_token(user["id"])
                        st.session_state["auth_token"] = token
                        st.session_state["user"] = user
                        st.rerun()
                    else:
                        st.error("Invalid password")
                else:
                    st.error("User not found")
        return False

    def check_auth(self):
        """Main authentication check"""
        # Check for token in session
        if "auth_token" in st.session_state:
            user_id = self.verify_token(st.session_state["auth_token"])
            if user_id:
                # Token valid, find user
                for username, user in self.allowed_users.items():
                    if user["id"] == user_id:
                        st.session_state["user"] = user
                        return True
            # Token invalid or expired
            if "auth_token" in st.session_state:
                del st.session_state["auth_token"]

        # Show login form
        st.title("🔒 Secure Login")
        return self.login_form()


# Usage
auth = EnterpriseAuth()
if not auth.check_auth():
    st.stop()

# Your app here - user is authenticated
user = st.session_state["user"]
st.sidebar.write(f"Welcome, {user['email']}")
########################################################################################################################
### EOF Authentication System
########################################################################################################################

st.sidebar.title("TinCAN - Work Space")
st.sidebar.image("img.png")
st.sidebar.divider()

# Where files are saved
UPLOAD_DIR = "shared_files"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

##################################################
#       Show files that can be downloaded        #
##################################################
files = os.listdir(UPLOAD_DIR)

if files:
    st.subheader("Download Files")

    # Display each file with download and delete buttons
    for filename in files:
        col1, col2, col3 = st.columns([3, 2, 1])

        with col1:
            st.write(f"**{filename}**")

        with col2:
            filepath = os.path.join(UPLOAD_DIR, filename)
            with open(filepath, "rb") as f:
                st.download_button(
                    label = "Download",
                    data = f,
                    file_name = filename,
                    key = f"dl_{filename}",
                )

        with col3:
            # Delete Button
            if st.button(f"🚮", key = f"del_{filename}"):
                os.remove(filepath)
                st.success(f"Deleted **{filename}**")
                st.rerun() # refresh to show updated list
else:
    st.info("No file is available yet")
st.divider()

##################################################
#               Upload a file                    #
##################################################
st.sidebar.subheader("Upload a File")
uploaded_file = st.sidebar.file_uploader("Choose a file to upload")

if uploaded_file is not None:
    # Simple save without
    filepath = os.path.join(UPLOAD_DIR, uploaded_file.name)

    # Check if the file is already exists
    if os.path.exists(filepath):
        st.warning(f"File **{uploaded_file.name}** already exists, Overwriting...")

    with open(filepath, "wb") as f:
        f.write(uploaded_file.getvalue())

    st.success(f"Uploaded **{uploaded_file.name}**")
    st.info(f"The other person can now download it. Refresh the page to see it in the list.")

    # Show download button immediately for the uploader too
    st.download_button(
        label = "Download File",
        data = uploaded_file.getvalue(),
        file_name = uploaded_file.name,
        key = "uploader_download"
    )

# Add a clear all files button (optional)
st.sidebar.divider()
if files:
    if st.sidebar.button("Clear All Files"):
        for filename in files:
            filepath = os.path.join(UPLOAD_DIR, filename)
            os.remove(filepath)
        st.success("All files deleted!")
        st.rerun()
else:
    st.info("Upload area above • Delete buttons appear next to each file")