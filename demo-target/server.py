"""
VULNERABLE Demo API — Intentionally insecure Flask API for testing the BAC Scanner.

⚠️  THIS IS INTENTIONALLY VULNERABLE. DO NOT DEPLOY TO PRODUCTION. ⚠️

Vulnerabilities included:
1. IDOR — /api/users/{id}/profile (no ownership check)
2. AUTH BYPASS — /api/admin/stats (auth not enforced)
3. PRIVILEGE ESCALATION — /api/admin/users (only checks for header, not real role)
4. METHOD MANIPULATION — /api/documents/{id} allows DELETE without auth
5. ROLE HEADER INJECTION — trusts X-Role header

Demo users:
  Admin:    token = eyAdminTokenHere (see /api/auth/login)
  Alice:    token = eyAliceTokenHere
  Bob:      token = eyBobTokenHere
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import functools

app = Flask(__name__)
CORS(app)

SECRET = "demo-secret-key-not-for-production"

# ==============================
# FAKE DATABASE
# ==============================
USERS = {
    1: {"id": 1, "email": "admin@demo.com", "name": "Admin User", "role": "admin",
        "ssn": "000-00-0001", "credit_card": "4111-1111-1111-0001", "balance": 99999},
    2: {"id": 2, "email": "alice@demo.com", "name": "Alice Smith", "role": "user",
        "ssn": "000-00-0002", "credit_card": "4111-1111-1111-0002", "balance": 500},
    3: {"id": 3, "email": "bob@demo.com", "name": "Bob Jones", "role": "user",
        "ssn": "000-00-0003", "credit_card": "4111-1111-1111-0003", "balance": 750},
    4: {"id": 4, "email": "charlie@demo.com", "name": "Charlie Doe", "role": "user",
        "ssn": "000-00-0004", "credit_card": "4111-1111-1111-0004", "balance": 1200},
}

DOCUMENTS = {
    101: {"id": 101, "owner_id": 2, "title": "Alice's Contract", "content": "CONFIDENTIAL: Alice's employment contract."},
    102: {"id": 102, "owner_id": 3, "title": "Bob's Medical Records", "content": "CONFIDENTIAL: Bob's private medical data."},
    103: {"id": 103, "owner_id": 1, "title": "Admin Report", "content": "CONFIDENTIAL: Admin financial report Q1."},
}

# Pre-generated tokens (in a real app these would be dynamic)
TOKENS = {
    "admin": jwt.encode({"sub": "1", "role": "admin", "name": "Admin User"}, SECRET, algorithm="HS256"),
    "alice": jwt.encode({"sub": "2", "role": "user", "name": "Alice Smith"}, SECRET, algorithm="HS256"),
    "bob": jwt.encode({"sub": "3", "role": "user", "name": "Bob Jones"}, SECRET, algorithm="HS256"),
}


def get_token_identity():
    """Extract user from JWT. Returns None if invalid/missing."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        user_id = int(payload.get("sub", 0))
        return USERS.get(user_id)
    except Exception:
        return None


# ==============================
# AUTH ENDPOINTS
# ==============================

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").lower()
    for user in USERS.values():
        if user["email"] == email:
            if email == "admin@demo.com" and data.get("password") == "admin123":
                return jsonify({"token": TOKENS["admin"], "user": {"id": 1, "name": "Admin", "role": "admin"}})
            elif email == "alice@demo.com" and data.get("password") == "alice123":
                return jsonify({"token": TOKENS["alice"], "user": {"id": 2, "name": "Alice", "role": "user"}})
            elif email == "bob@demo.com" and data.get("password") == "bob123":
                return jsonify({"token": TOKENS["bob"], "user": {"id": 3, "name": "Bob", "role": "user"}})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/auth/tokens", methods=["GET"])
def get_demo_tokens():
    """Returns pre-computed tokens for all demo users — for easy scanner setup."""
    return jsonify({
        "demo_tokens": [
            {"label": "Admin", "token": TOKENS["admin"], "email": "admin@demo.com"},
            {"label": "Alice (User)", "token": TOKENS["alice"], "email": "alice@demo.com"},
            {"label": "Bob (User)", "token": TOKENS["bob"], "email": "bob@demo.com"},
        ],
        "demo_requests": {
            "idor_test": f"GET /api/users/2/profile HTTP/1.1\nHost: localhost:8001\nAuthorization: Bearer {TOKENS['bob']}\n\n",
            "auth_bypass_test": "GET /api/admin/stats HTTP/1.1\nHost: localhost:8001\n\n",
            "priv_esc_test": f"GET /api/admin/users HTTP/1.1\nHost: localhost:8001\nAuthorization: Bearer {TOKENS['alice']}\n\n",
        }
    })


# ==============================
# VULNERABILITY 1: IDOR
# /api/users/{id}/profile — no ownership check
# ==============================

@app.route("/api/users/<int:user_id>/profile", methods=["GET"])
def get_user_profile(user_id):
    """
    VULNERABLE: Returns any user's profile with their sensitive data.
    Fix: Check that current_user.id == user_id.
    """
    current = get_token_identity()
    if not current:
        return jsonify({"error": "Authentication required"}), 401

    # BUG: No ownership check — any authenticated user can access any profile
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Returns sensitive data without checking if requester owns this profile
    return jsonify({
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "ssn": user["ssn"],        # SENSITIVE — should never be exposed
        "balance": user["balance"],
        "role": user["role"],
    })


# ==============================
# VULNERABILITY 2: AUTH BYPASS
# /api/admin/stats — auth not properly enforced
# ==============================

@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    """
    VULNERABLE: Returns admin stats without properly checking authentication.
    Fix: Require valid admin token.
    """
    # BUG: Only checks for the header presence, doesn't validate the JWT
    auth = request.headers.get("Authorization", "")
    if auth:
        pass  # Just trusts that any Authorization header means authenticated
    # SHOULD be: if not current or current["role"] != "admin": return 401/403

    return jsonify({
        "total_users": len(USERS),
        "total_documents": len(DOCUMENTS),
        "revenue": "$1,234,567",
        "admin_actions": ["User #3 deleted", "Report generated", "Config updated"],
        "server_info": {"version": "1.0", "db": "PostgreSQL 15", "os": "Ubuntu 22.04"},
    })


# ==============================
# VULNERABILITY 3: PRIVILEGE ESCALATION
# /api/admin/users — trusts X-Role header
# ==============================

@app.route("/api/admin/users", methods=["GET"])
def list_all_users():
    """
    VULNERABLE: Trusts X-Role header for admin check.
    Fix: Check role from the validated JWT token only.
    """
    current = get_token_identity()
    if not current:
        return jsonify({"error": "Authentication required"}), 401

    # BUG: Trusts client-supplied header instead of JWT role
    role_header = request.headers.get("X-Role", "")
    user_role = current.get("role", "user")

    if role_header == "admin" or user_role == "admin":  # Role header injection possible!
        return jsonify({
            "users": list(USERS.values()),
            "admin_only_data": "Full user list with sensitive info"
        })

    return jsonify({"error": "Admin access required"}), 403


# ==============================
# VULNERABILITY 4: METHOD MANIPULATION
# /api/documents/{id} — DELETE not protected
# ==============================

@app.route("/api/documents/<int:doc_id>", methods=["GET", "DELETE"])
def document(doc_id):
    """
    GET: Properly checks ownership.
    DELETE: VULNERABLE — doesn't check auth or ownership.
    Fix: Add auth + ownership check to DELETE.
    """
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404

    if request.method == "GET":
        current = get_token_identity()
        if not current:
            return jsonify({"error": "Authentication required"}), 401
        if current["id"] != doc["owner_id"] and current["role"] != "admin":
            return jsonify({"error": "Access denied"}), 403
        return jsonify(doc)

    elif request.method == "DELETE":
        # BUG: No auth or ownership check for DELETE!
        del DOCUMENTS[doc_id]
        return jsonify({"success": True, "deleted_id": doc_id}), 200


# ==============================
# PUBLIC ENDPOINTS (for baseline)
# ==============================

@app.route("/api/public/items", methods=["GET"])
def public_items():
    return jsonify({
        "items": [
            {"id": 1, "name": "Public Item A"},
            {"id": 2, "name": "Public Item B"},
        ]
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "BAC Scanner Demo Target API",
        "warning": "INTENTIONALLY VULNERABLE — DO NOT USE IN PRODUCTION",
        "vulnerabilities": ["IDOR", "AUTH_BYPASS", "PRIVILEGE_ESCALATION", "METHOD_MANIPULATION"],
    })


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  BAC Scanner — Demo Vulnerable Target API")
    print("  Running on http://localhost:8001")
    print("  ⚠️  INTENTIONALLY VULNERABLE — FOR TESTING ONLY ⚠️")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=8001, debug=True)
