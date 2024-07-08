import hashlib
import json
import os

class CertificationAuthority:
    def __init__(self, ca_key):
        self.ca_key = ca_key
        self.registered_users = {}
        self.registered_servers = {}
        self.load_registry()

    def load_registry(self):
        if os.path.exists("registry.json"):
            with open("registry.json", "r") as f:
                registry = json.load(f)
                self.registered_users = registry.get("users", {})
                self.registered_servers = registry.get("servers", {})

    def save_registry(self):
        with open("registry.json", "w") as f:
            json.dump({
                "users": self.registered_users,
                "servers": self.registered_servers
            }, f)

    def register_user(self, username, public_key):
        self.registered_users[username] = public_key
        self.save_registry()

    def register_server(self, servername, public_key):
        self.registered_servers[servername] = public_key
        self.save_registry()

    def verify_user(self, username, public_key):
        return self.registered_users.get(username) == public_key

    def verify_server(self, servername, public_key):
        return self.registered_servers.get(servername) == public_key

def generate_hash_key(password):
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    ca_key = generate_hash_key("ca_secret_password")
    ca = CertificationAuthority(ca_key)

    # Registering users and servers (example)
    ca.register_user("client1", "client1_public_key")
    ca.register_server("server1", "server1_public_key")

    # Verifying users and servers
    is_user_valid = ca.verify_user("client1", "client1_public_key")
    is_server_valid = ca.verify_server("server1", "server1_public_key")

    print(f"User valid: {is_user_valid}")
    print(f"Server valid: {is_server_valid}")

if __name__ == "__main__":
    main()
