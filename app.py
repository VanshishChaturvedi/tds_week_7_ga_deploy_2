import re
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==========================================
# ENDPOINT 1: CI/CD Container Release Gate
# ==========================================
@app.route('/release-gate', methods=['POST'], strict_slashes=False)
def release_gate():
    try:
        data = request.get_json(force=True, silent=True)
        if not isinstance(data, dict): data = {}
    except Exception:
        data = {}
        
    violations = set()
    target, event, ref = data.get('target'), data.get('event'), data.get('ref')
    
    workflow = data.get('workflow')
    if not isinstance(workflow, dict): workflow = {}
        
    image = data.get('image')
    if not isinstance(image, dict): image = {}
        
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if workflow.get('permissions') != expected_perms: violations.add("EXCESS_PERMISSION")
    if event == 'pull_request' and workflow.get('trigger') != 'pull_request': violations.add("UNSAFE_PR_TRIGGER")
    if not (workflow.get('testsPassed') is True and workflow.get('matrixComplete') is True and workflow.get('failFast') is False): violations.add("TESTS_INCOMPLETE")
        
    actions = workflow.get('actions')
    if actions is None: actions = []
    if isinstance(actions, list):
        for action in actions:
            if isinstance(action, dict):
                if action.get('owner') != 'actions':
                    ref_val = action.get('ref', '')
                    if not isinstance(ref_val, str) or not re.match(r'^[a-f0-9]{40}$', ref_val): violations.add("MUTABLE_ACTION")
            else:
                violations.add("MUTABLE_ACTION")
                
    if image.get('multiStage') is not True: violations.add("SINGLE_STAGE_IMAGE")
    if image.get('runsAsRoot') is not False: violations.add("ROOT_RUNTIME")
    if image.get('secretMode') not in ['none', 'buildkit']: violations.add("SECRET_IN_LAYER")
    try:
        if float(image.get('criticalVulnerabilities', 1)) > 0: violations.add("CRITICAL_CVE")
    except (TypeError, ValueError):
        violations.add("CRITICAL_CVE")
    if image.get('digestPinned') is not True: violations.add("UNPINNED_IMAGE")
        
    if target == 'production':
        if event != 'push' or ref != 'refs/heads/main': violations.add("INVALID_PRODUCTION_REF")
        if workflow.get('environmentApproval') is not True: violations.add("APPROVAL_REQUIRED")
            
    violations_list = list(violations)
    return jsonify({
        "decision": "promote" if not violations_list else "block",
        "violations": violations_list
    })

# ==========================================
# ENDPOINT 2: LLM Action Firewall
# ==========================================
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
    if 'tool' not in action or not isinstance(action['tool'], str):
        return jsonify(decision="block", reason="INVALID_SCHEMA")
    if 'args' not in action or not isinstance(action['args'], dict):
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
            
        # HTML Safety Verification
        html = args['html'].lower()
        if '<script' in html or '<iframe' in html or 'javascript:' in html or re.search(r'\bon[a-z]+\s*=', html):
            return jsonify(decision="block", reason="UNSAFE_OUTPUT")
            
    # 5. Passed all constraints
    return jsonify(decision="allow", reason="ALLOW")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)