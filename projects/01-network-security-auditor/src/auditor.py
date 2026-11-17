import boto3
import json
import os
from datetime import datetime

def audit_network(region):
    ec2 = boto3.client('ec2', region_name=region)
    findings = []
    
    print(f"\n--- Starting Audit for Region: {region} ---")
    
    # 1. LIST VPCs & CHECK FLOW LOGS
    vpcs = ec2.describe_vpcs()['Vpcs']
    flow_logs = ec2.describe_flow_logs()['FlowLogs']
    logged_vpcs = [fl['ResourceId'] for fl in flow_logs]

    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        cidr = vpc['CidrBlock']
        print(f"[VPC] Found: {vpc_id} ({cidr})")
        
        if vpc_id not in logged_vpcs:
            findings.append({
                'resource': vpc_id,
                'issue': 'VPC Flow Logs Disabled',
                'severity': 'MEDIUM'
            })

    # 2. SCAN SECURITY GROUPS
    sgs = ec2.describe_security_groups()['SecurityGroups']
    dangerous_ports = {22: 'SSH', 3389: 'RDP', 3306: 'MySQL', -1: 'ALL TRAFFIC'}

    for sg in sgs:
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    from_port = rule.get('FromPort', -1)
                    service = dangerous_ports.get(from_port, 'Unknown')
                    
                    findings.append({
                        'resource': sg['GroupId'],
                        'issue': f'Open Port {from_port} ({service}) to 0.0.0.0/0',
                        'severity': 'CRITICAL' if from_port in [22, 3389, -1] else 'HIGH'
                    })

    return findings

if __name__ == "__main__":
    target_region = 'us-east-2' # Change this to the region where you found your VPC
    all_findings = audit_network('us-east-2')

    # 3. OUTPUT SUMMARY TABLE
    print(f"\n{'RESOURE ID':<25} | {'ISSUE':<35} | {'SEVERITY'}")
    print("-" * 75)
    for f in all_findings:
        print(f"{f['resource']:<25} | {f['issue']:<35} | {f['severity']}")

    # 4. SAVE JSON REPORT
    report_dir = 'reports'
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    
    timestamp = datetime.now().strftime("%Y-%m-%d")
    filename = f"{report_dir}/{timestamp}-audit.json"
    
    with open(filename, 'w') as f:
        json.dump(all_findings, f, indent=4)
    
    print(f"\n✅ Audit Complete. JSON report saved to: {filename}")