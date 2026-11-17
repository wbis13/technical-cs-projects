import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from detectors.iam_escalation_detector import IAMEscalationDetector

class TestIAMEscalationDetector(unittest.TestCase):
    def setUp(self):
        self.detector = IAMEscalationDetector()

    def test_detects_suspicious_event(self):
        event = {'eventName': 'CreatePolicyVersion'}
        self.assertTrue(self.detector.evaluate_event(event))

    def test_ignores_safe_event(self):
        event = {'eventName': 'DescribeInstances'}
        self.assertFalse(self.detector.evaluate_event(event))

if __name__ == '__main__':
    unittest.main()
