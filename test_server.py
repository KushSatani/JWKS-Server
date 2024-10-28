import unittest
import json
import requests
import sqlite3
from http.server import HTTPServer
from threading import Thread
from main import MyServer, init_db, generate_and_store_keys, get_valid_key

class TestJWKSService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize database and start the server
        init_db()
        generate_and_store_keys()
        cls.server_thread = Thread(target=cls.start_server)
        cls.server_thread.start()

    @classmethod
    def start_server(cls):
        host_name = "localhost"
        server_port = 8080
        server = HTTPServer((host_name, server_port), MyServer)
        server.serve_forever()

    @classmethod
    def tearDownClass(cls):
        pass

    def test_auth_valid_jwt(self):
        response = requests.post("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 200)
        self.assertIn('ey', response.text)  # Check if JWT is in the response

    def test_auth_expired_jwt(self):
        response = requests.post("http://localhost:8080/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn('ey', response.text)  # Check if JWT is in the response

    def test_jwks_endpoint(self):
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        keys = json.loads(response.text)
        self.assertIn("keys", keys)
        self.assertGreater(len(keys["keys"]), 0)  # Ensure at least one key is returned

    def test_database_exists(self):
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()
        cursor.execute('SELECT count(*) FROM keys')
        count = cursor.fetchone()[0]
        conn.close()
        self.assertGreater(count, 0, "Database should have keys stored.")

if __name__ == "__main__":
    unittest.main()
