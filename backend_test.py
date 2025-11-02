#!/usr/bin/env python3

import requests
import sys
import json
from datetime import datetime

class ConvoTalkAPITester:
    def __init__(self, base_url="https://convotalk-web.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.token = None
        self.user_id = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details="", expected_status=None, actual_status=None):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {details}")
            if expected_status and actual_status:
                print(f"   Expected status: {expected_status}, Got: {actual_status}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details,
            "expected_status": expected_status,
            "actual_status": actual_status
        })

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        test_headers = {'Content-Type': 'application/json'}
        
        if self.token:
            test_headers['Authorization'] = f'Bearer {self.token}'
        
        if headers:
            test_headers.update(headers)

        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        print(f"   Method: {method}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=test_headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers, timeout=10)

            success = response.status_code == expected_status
            
            if success:
                self.log_test(name, True)
                try:
                    return True, response.json()
                except:
                    return True, response.text
            else:
                self.log_test(name, False, f"Status code mismatch", expected_status, response.status_code)
                try:
                    error_detail = response.json()
                    print(f"   Response: {error_detail}")
                except:
                    print(f"   Response: {response.text}")
                return False, {}

        except requests.exceptions.Timeout:
            self.log_test(name, False, "Request timeout")
            return False, {}
        except requests.exceptions.ConnectionError:
            self.log_test(name, False, "Connection error")
            return False, {}
        except Exception as e:
            self.log_test(name, False, f"Exception: {str(e)}")
            return False, {}

    def test_api_root(self):
        """Test API root endpoint"""
        return self.run_test("API Root", "GET", "", 200)

    def test_register(self):
        """Test user registration"""
        timestamp = datetime.now().strftime('%H%M%S')
        test_user_data = {
            "username": f"testuser_{timestamp}",
            "email": f"test_{timestamp}@example.com",
            "password": "testpass123"
        }
        
        success, response = self.run_test("User Registration", "POST", "auth/register", 200, test_user_data)
        
        if success and 'token' in response:
            self.token = response['token']
            self.user_id = response['user']['id']
            print(f"   Registered user: {response['user']['username']}")
            return True
        return False

    def test_login(self):
        """Test user login with existing credentials"""
        # Try to login with a known user or create one
        login_data = {
            "email": "testuser123@example.com",
            "password": "testpass123"
        }
        
        success, response = self.run_test("User Login", "POST", "auth/login", 200, login_data)
        
        if success and 'token' in response:
            self.token = response['token']
            self.user_id = response['user']['id']
            print(f"   Logged in user: {response['user']['username']}")
            return True
        else:
            # If login fails, try to register first
            print("   Login failed, trying to register new user...")
            return self.test_register()

    def test_auth_me(self):
        """Test get current user info"""
        if not self.token:
            self.log_test("Get Current User", False, "No auth token available")
            return False
            
        return self.run_test("Get Current User", "GET", "auth/me", 200)

    def test_get_channels(self):
        """Test get channels"""
        if not self.token:
            self.log_test("Get Channels", False, "No auth token available")
            return False
            
        success, response = self.run_test("Get Channels", "GET", "channels", 200)
        
        if success and isinstance(response, list):
            print(f"   Found {len(response)} channels")
            for channel in response:
                print(f"   - {channel.get('name', 'Unknown')}")
        
        return success

    def test_get_online_users(self):
        """Test get online users"""
        if not self.token:
            self.log_test("Get Online Users", False, "No auth token available")
            return False
            
        success, response = self.run_test("Get Online Users", "GET", "users/online", 200)
        
        if success and isinstance(response, list):
            print(f"   Found {len(response)} online users")
        
        return success

    def test_send_message(self):
        """Test sending a message to general channel"""
        if not self.token:
            self.log_test("Send Message", False, "No auth token available")
            return False
        
        # First get channels to find general channel
        success, channels = self.run_test("Get Channels for Message", "GET", "channels", 200)
        if not success:
            return False
        
        general_channel = None
        for channel in channels:
            if channel.get('name') == 'general':
                general_channel = channel
                break
        
        if not general_channel:
            self.log_test("Send Message", False, "General channel not found")
            return False
        
        message_data = {
            "content": f"Test message from API test at {datetime.now().isoformat()}",
            "message_type": "text"
        }
        
        return self.run_test("Send Message", "POST", f"channels/{general_channel['id']}/messages", 200, message_data)

    def test_get_messages(self):
        """Test getting messages from general channel"""
        if not self.token:
            self.log_test("Get Messages", False, "No auth token available")
            return False
        
        # First get channels to find general channel
        success, channels = self.run_test("Get Channels for Messages", "GET", "channels", 200)
        if not success:
            return False
        
        general_channel = None
        for channel in channels:
            if channel.get('name') == 'general':
                general_channel = channel
                break
        
        if not general_channel:
            self.log_test("Get Messages", False, "General channel not found")
            return False
        
        success, response = self.run_test("Get Messages", "GET", f"channels/{general_channel['id']}/messages", 200)
        
        if success and isinstance(response, list):
            print(f"   Found {len(response)} messages")
        
        return success

    def test_logout(self):
        """Test user logout"""
        if not self.token:
            self.log_test("User Logout", False, "No auth token available")
            return False
            
        return self.run_test("User Logout", "POST", "auth/logout", 200)

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting ConvoTalk API Tests")
        print(f"📡 Base URL: {self.base_url}")
        print("=" * 50)

        # Test API availability
        self.test_api_root()
        
        # Test authentication flow
        self.test_login()  # This will register if login fails
        self.test_auth_me()
        
        # Test chat functionality
        self.test_get_channels()
        self.test_get_online_users()
        self.test_send_message()
        self.test_get_messages()
        
        # Test logout
        self.test_logout()

        # Print summary
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)
        print(f"Tests run: {self.tests_run}")
        print(f"Tests passed: {self.tests_passed}")
        print(f"Tests failed: {self.tests_run - self.tests_passed}")
        print(f"Success rate: {(self.tests_passed/self.tests_run)*100:.1f}%")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return 0
        else:
            print("❌ Some tests failed!")
            print("\nFailed tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  - {result['test']}: {result['details']}")
            return 1

def main():
    tester = ConvoTalkAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())