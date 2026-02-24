import os, json, re, subprocess, sys, urllib.request

def die(msg: str, code: int = 1):
    print(msg)
    sys.exit(code)

auth = os.environ.get("L5_AUTH_URL","").rstrip("/")
pin_pk = os.environ.get("L5_PUBKEY_SHA256","").strip().lower()
pin_img = os.environ.get("L5_PIN_IMAGE_DIGEST","").strip()
base = os.environ.get("BASE_SHA","").strip()
head = os.environ.get("HEAD_SHA","").strip()
event = os.environ.get("GITHUB_EVENT_NAME","").strip()

if not auth: die("MISSING_ENV:L5_AUTH_URL")
if not pin_pk: die("MISSING_ENV:L5_PUBKEY_SHA256")
if not pin_img: die("MISSING_ENV:L5_PIN_IMAGE_DIGEST")
if not base: die("MISSING_ENV:BASE_SHA")
if not head: die("MISSING_ENV:HEAD_SHA")
if base == "0000000000000000000000000000000000000000": die("INVALID_BASE_SHA:all_zeros")
if head == "0000000000000000000000000000000000000000": die("INVALID_HEAD_SHA:all_zeros")

print("EVENT_NAME="+event)
print("BASE_SHA="+base)
print("HEAD_SHA="+head)

# --- 1) PIN CHECK: AUTH PUBKEY MUST COME FROM /pubkey ---
try:
    pub_raw = urllib.request.urlopen(auth + "/pubkey", timeout=25).read().decode("utf-8","replace")
except Exception as e:
    die("PUBKEY_FETCH_FAILED " + str(e))

try:
    pub = json.loads(pub_raw)
except Exception:
    die("PUBKEY_BAD_JSON")

got_pk = (pub.get("public_key_sha256") or "").strip().lower()
if not got_pk:
    die("PUBKEY_SHA256_MISSING")

if got_pk != pin_pk:
    die("PIN_FAIL_AUTH_PUBKEY_SHA256 got=" + got_pk + " expected=" + pin_pk)

print("PUBKEY_PIN_OK")

# --- 2) DIFF FACTS (added-lines only) ---
diff = subprocess.check_output(
    ["git","diff","--unified=0",f"{base}..{head}"],
    text=True,
    errors="replace"
)

facts=[]
cur=None
new=None

for ln in diff.splitlines():
    if ln.startswith("+++ b/"):
        cur=ln[6:]
        continue

    m=re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@",ln)
    if m:
        new=int(m.group(1))
        continue

    if cur is None or new is None:
        continue

    if ln.startswith("+") and not ln.startswith("+++"):
        facts.append({"file":cur,"line":new,"added":ln[1:]})
        new+=1
        continue

    if ln.startswith("-") and not ln.startswith("---"):
        continue

    if not ln.startswith("\\"):
        new+=1

payload = {
    "intent":{
        "action_type":"GIT_COMMIT_DIFF",
        "payload":{"diff_facts":facts}
    }
}

data = json.dumps(payload,separators=(",",":")).encode("utf-8")

req = urllib.request.Request(
    auth+"/admit",
    data=data,
    headers={"Content-Type":"application/json"},
    method="POST"
)

try:
    body = urllib.request.urlopen(req,timeout=25).read().decode("utf-8","replace")
except Exception as e:
    die("L5_CALL_FAILED " + str(e))

print("L5_RAW_RESPONSE_BEGIN")
print(body[:4000])
print("L5_RAW_RESPONSE_END")

try:
    o = json.loads(body)
except Exception:
    die("L5_BAD_JSON_RESPONSE")

# --- 3) PIN CHECK: IMAGE DIGEST MUST MATCH ---
img = ""
if isinstance(o.get("signed_record"), dict):
    img = (o["signed_record"].get("image_digest") or "").strip()
elif isinstance(o.get("signed_payload"), dict):
    img = (o["signed_payload"].get("image_digest") or "").strip()
else:
    img = (o.get("image_digest") or "").strip().strip()
if img != pin_img:
    die("PIN_FAIL_IMAGE_DIGEST got=" + img + " expected=" + pin_img)

print("IMAGE_PIN_OK")

# --- 4) DECISION ---
decision = (o.get("decision") or "").strip()
if not decision and isinstance(o.get("signed_payload"), dict):
    decision = (o["signed_payload"].get("decision") or "").strip()
if not decision and isinstance(o.get("signed_record"), dict):
    decision = (o["signed_record"].get("decision") or "").strip()

print("DECISION="+decision)

if decision != "ALLOW":
    sp = o.get("signed_payload") or {}
    f = sp.get("findings") if isinstance(sp, dict) else None
    if isinstance(f, list):
        print("FINDINGS_COUNT="+str(len(f)))
        if f:
            print(json.dumps(f[:5], ensure_ascii=False))
    sys.exit(1)

print("L5_ALLOW_OK")


