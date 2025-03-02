import unittest
import json
import os
import sys

# Add the current script's directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import NetworkEnumerationTool  # Now import should work

class TestNetworkEnumerationTool(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up test case with a dummy target"""
        cls.target = "192.168.1.74"  # Public test domain
        cls.tool = NetworkEnumerationTool(cls.target)

    def test_scan_ports(self):
        """Test port scanning functionality"""
        result = self.tool.scan_ports()
        self.assertIsInstance(result, dict, "Port scan should return a dictionary")

    def test_os_detection(self):
        """Test OS detection functionality"""
        result = self.tool.os_detection()
        self.assertIsInstance(result, dict, "OS detection should return a dictionary")

    def test_vulnerability_scan(self):
        """Test vulnerability scanning functionality"""
        result = self.tool.vulnerability_scan()
        self.assertIsInstance(result, dict, "Vulnerability scan should return a dictionary")

if __name__ == "__main__":
    unittest.main()

