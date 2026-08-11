import re
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/action-firewall', methods=['POST'], strict_slashes=False)
def action_firewall():
    # 1. Endpoint Availability / Safe JSON Parsing
    try:
        data = request.get_json(force=True, silent=True)
        if not isinstance(data, dict):
            return jsonify(decision="block", reason="INVALID_SCHEMA")
    except Exception:
        return jsonify(decision="block", reason="INVALID_SCHEMA")
        
    # 2. Top-level Schema Check
    if 'action' not in data or not isinstance(data['action'], dict):
        return jsonify(decision="block", reason="INVALID_SCHEMA")
        
    action = data['action']
    if 'tool' not in action or not isinstance(action.get('tool'), str):
        return jsonify(decision="block", reason="INVALID_SCHEMA")
    if 'args' not in action or not isinstance(action.get('args'), dict):
        return jsonify(decision="block", reason="INVALID_SCHEMA")
        
    tool = action['tool']
    args = action['args']
    
    # 3. Tool Allowlist Check
    allowed_tools = ['search', 'lookup_record', 'send_email', 'render_html']
    if tool not in allowed_tools:
        return jsonify(decision="block", reason="TOOL_NOT_ALLOWED")
        
    # 4. Tool Argument Schema & Constraints (in strict order)
    if tool == 'search':
        if set(args.keys()) != {'query'} or not isinstance(args['query'], str):
            return jsonify(decision="block", reason="INVALID_SCHEMA")
        if not (1 <= len(args['query']) <= 200):
            return jsonify(decision="block", reason="INVALID_SCHEMA")
            
    elif tool == 'lookup_record':
        if set(args.keys()) != {'tenantId', 'recordId'}:
            return jsonify(decision="block", reason="INVALID_SCHEMA")
        if not isinstance(args['tenantId'], str) or not isinstance(args['recordId'], str):
            return jsonify(decision="block", reason="INVALID_SCHEMA")
        if len(args['recordId']) == 0:
            return jsonify(decision="block", reason="INVALID_SCHEMA")
            
        # Tenant Scope Enforcement
        if args['tenantId'] != 'tenant-3s0mzu7':
            return jsonify(decision="block", reason="TENANT_SCOPE")
            
    elif tool == 'send_email':
        if set(args.keys()) != {'to', 'subject', 'body'}:
            return jsonify(decision="block", reason="INVALID_SCHEMA")
        if not isinstance(args['to'], str) or not isinstance(args['subject'], str) or not isinstance(args['body'], str):
            return jsonify(decision="block", reason="INVALID_SCHEMA")
            
        # Exact Email Domain (Egress Check)
        to_email = args['to']
        domain = to_email.split('@')[-1] if '@' in to_email else ''
        if domain != 'notify-v0zgesn.example':
            return jsonify(decision="block", reason="EGRESS_DENIED")
            
        # Human Approval Enforcement
        if data.get('humanApproved') is not True:
            return jsonify(decision="block", reason="APPROVAL_REQUIRED")
            
    elif tool == 'render_html':
        if set(args.keys()) != {'html'} or not isinstance(args['html'], str):
            return jsonify(decision="block", reason="INVALID_SCHEMA")
            
        # HTML Safety Verification (Block scripts, iframes, inline events, javascript: URLs)
        html = args['html'].lower()
        if '<script' in html or '<iframe' in html or 'javascript:' in html or re.search(r'\bon[a-z]+\s*=', html):
            return jsonify(decision="block", reason="UNSAFE_OUTPUT")
            
    # 5. Passed all constraints
    return jsonify(decision="allow", reason="ALLOW")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
