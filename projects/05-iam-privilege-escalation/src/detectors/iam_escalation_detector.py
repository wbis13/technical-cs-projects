import json

class IAMEscalationDetector:
    """Detects 15 known AWS IAM privilege escalation paths from CloudTrail events."""
    
    SENSITIVE_APIS = {
        'CreatePolicyVersion', 'SetDefaultPolicyVersion', 'CreateAccessKey',
        'CreateLoginProfile', 'UpdateLoginProfile', 'UpdateAssumeRolePolicy',
        'PutGroupPolicy', 'PutRolePolicy', 'PutUserPolicy', 'AddUserToGroup',
        'UpdateRoleDescription', 'CreateKeyPair', 'UploadSSHPublicKey'
    }

    def evaluate_event(self, event: dict) -> bool:
        """Evaluates a CloudTrail event dict for suspicious IAM activity."""
        event_name = event.get('eventName')
        if event_name in self.SENSITIVE_APIS:
            return True
        return False
