#!/bin/bash

URL="http://localhost:8080/signup"

declare -A test_cases=(
    ["Valid Input"]='{"username": "user", "email": "user@email.com", "password": "123"}'
    ["Missing Username"]='{"email": "user2@email.com", "password": "123"}'
    ["Missing Email"]='{"username": "user3", "password": "123"}'
    ["Missing Password"]='{"username": "user4", "email": "user4@email.com"}'
    ["Empty Username"]='{"username": "", "email": "user5@email.com", "password": "123"}'
    ["Empty Email"]='{"username": "user6", "email": "", "password": "123"}'
    ["Empty Password"]='{"username": "user7", "email": "user7@email.com", "password": ""}'
    ["Invalid Email Format"]='{"username": "user8", "email": "user8-invalid", "password": "123"}'
    ["Short Password"]='{"username": "user9", "email": "user9@email.com", "password": "12"}'
    ["Long Username"]='{"username": "thisisaverylongusernamethatexceedstheusualcharacterlimit", "email": "user10@email.com", "password": "123"}'
    ["Already Registered Email"]='{"username": "user11", "email": "user@email.com", "password": "123"}'
    ["SQL Injection Attempt"]='{"username": "user12", "email": "user12@email.com", "password": "123\"; DROP TABLE users; --"}'
    ["Cross-Site Scripting (XSS) Attempt"]='{"username": "<script>alert(\"XSS\")</script>", "email": "user13@example.com", "password": "123"}'
    ["Username with Special Characters"]='{"username": "user!@#", "email": "user14@email.com", "password": "123"}'
    ["Password with Special Characters"]='{"username": "user15", "email": "user15@email.com", "password": "Passw@rd!@#"}'
)

for test in "${!test_cases[@]}"; do
    echo "Testing: $test"
    response=$(curl -s -X POST $URL -H "Content-Type: application/json" -d "${test_cases[$test]}")
    echo "Response: $response"
    echo ""
done
