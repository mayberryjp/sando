import unittest
import requests

API_URL = "http://localhost:8044/api/localhosttags"
TEST_IP = "192.168.49.1"

class TestLocalhostTagsAPI(unittest.TestCase):
    def setUp(self):
        # Optionally, ensure the test IP exists in your database before running tests
        pass

    def test_add_tag(self):
        response = requests.put(f"{API_URL}/{TEST_IP}", json={"tag": "printer"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json().get("success"))
        self.assertIn("printer", response.json().get("message", ""))

    def test_add_multiple_tags(self):
        requests.put(f"{API_URL}/{TEST_IP}", json={"tag": "printer"})
        response = requests.put(f"{API_URL}/{TEST_IP}", json={"tag": "server"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json().get("success"))

    # def test_delete_tag(self):
    #     requests.delete(f"{API_URL}/{TEST_IP}", json={"tag": "printer"})
    #     response = requests.delete(f"{API_URL}/{TEST_IP}", json={"tag": "printer"})
    #     self.assertEqual(response.status_code, 200)
    #     self.assertTrue(response.json().get("success"))
    #     self.assertIn("removed", response.json().get("message", ""))

    # def test_delete_nonexistent_tag(self):
    #     response = requests.delete(f"{API_URL}/{TEST_IP}", json={"tag": "notag"})
    #     self.assertEqual(response.status_code, 200)
    #     self.assertTrue(response.json().get("success"))

if __name__ == "__main__":
    unittest.main()