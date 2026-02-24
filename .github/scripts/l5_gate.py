import os, json, re, subprocess, sys, urllib.request

def die(msg: str, code: int = 1):
    print(msg)
    sys.exit(code)

auth = os.environ.get("L5_AUTH_URL","").rstrip("/")
pin_pk = os.environ.get("L5_PUBKEY_SHA256","").strip().lower()
pin_img = os.environ.get("L5_PIN_IMAGE_DIGEST","").strip()
base = os.environ.get("BASE_SHA","").strip()
head = os.environ.get("HEAD_SHA","").strip()

if not auth: die("MISSING_ENV:L5_AUTH_URL")
if not pin_pk: die("MISSING_ENV:L5_PUBKEY_SHA256")
if not pin_img: die("MISSING_ENV:L5_PIN_IMAGE_DIGEST")
if not base: die("MISSING_ENV:BASE_SHA")
if not head: die("MISSING_ENV:HEAD_SHA")
if base == "0000000000000000000000000000000000000000": die("INVALID_BASE_SHA:all_zeros")
if head == "0000000000000000000000000000000000000000": die("INVALID_HEAD_SHA:all_zeros")

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

pk=(o.get("authority_pubkey_sha256") or "").strip().lower()
img=(o.get("image_digest") or "").strip()

if pk!=pin_pk:
    die("PIN_FAIL_AUTH_PUBKEY_SHA256 got=" + pk + " expected=" + pin_pk)

if img!=pin_img:
    die("PIN_FAIL_IMAGE_DIGEST got=" + img + " expected=" + pin_img)

decision=(o.get("decision") or "").strip()
if not decision and isinstance(o.get("signed_payload"), dict):
    decision=(o["signed_payload"].get("decision") or "").strip()
if not decision and isinstance(o.get("signed_record"), dict):
    decision=(o["signed_record"].get("decision") or "").strip()

print("DECISION="+decision)

if decision!="ALLOW":
    sp=o.get("signed_payload") or {}
    f=sp.get("findings") if isinstance(sp,dict) else None
    if isinstance(f,list):
        print("FINDINGS_COUNT="+str(len(f)))
        if f:
            print(json.dumps(f[:5],ensure_ascii=False))
    sys.exit(1)

print("L5_ALLOW_OK")
