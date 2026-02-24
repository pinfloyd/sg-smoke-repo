import os, json, re, subprocess, sys, urllib.request

auth = os.environ["L5_AUTH_URL"].rstrip("/")
pin_pk = os.environ["L5_PUBKEY_SHA256"].strip().lower()
pin_img = os.environ["L5_PIN_IMAGE_DIGEST"].strip()
base = os.environ["BASE_SHA"]
head = os.environ["HEAD_SHA"]

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
    body = urllib.request.urlopen(req,timeout=25).read().decode()
except Exception as e:
    print("L5_CALL_FAILED",str(e))
    sys.exit(1)

print(body)

o = json.loads(body)

pk=(o.get("authority_pubkey_sha256") or "").strip().lower()
img=(o.get("image_digest") or "").strip()

if pk!=pin_pk:
    print("PIN_FAIL_AUTH")
    sys.exit(1)

if img!=pin_img:
    print("PIN_FAIL_IMAGE")
    sys.exit(1)

decision=o.get("decision","").strip()
print("DECISION="+decision)

if decision!="ALLOW":
    sys.exit(1)

print("L5_ALLOW_OK")
