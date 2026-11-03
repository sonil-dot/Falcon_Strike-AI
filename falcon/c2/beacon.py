"""Beacon emulation: periodic callbacks with jitter to a lab sink. Payload is an inert marker.
Egress allowlist is enforced here too (defence in depth). Proxy env vars are ignored."""
import json
import random
import time
import urllib.request

LAB_SINK_HOSTS = {"127.0.0.1", "localhost"}
UA = "falcon-beacon/1.0"
MARKER = "FALCON-INERT-BEACON"


class EgressViolation(Exception):
    pass


def run_beacons(sink, interval_s, jitter_pct, beacons, seed, run_id,
                sleep=time.sleep, should_stop=lambda: False, time_scale=1.0):
    if sink.split(":")[0] not in LAB_SINK_HOSTS:
        raise EgressViolation(f"{sink} is not a lab-owned endpoint")
    rnd = random.Random(seed)                       # deterministic jitter
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    sent = []
    for i in range(beacons):
        if should_stop():
            break
        delay = interval_s * (1 + rnd.uniform(-jitter_pct / 100, jitter_pct / 100))
        if i > 0:
            sleep(delay * time_scale)
        body = json.dumps({"marker": MARKER, "seq": i, "run_id": run_id}).encode()
        req = urllib.request.Request(f"http://{sink}/beacon", data=body,
                                     headers={"User-Agent": UA, "Content-Type": "application/json"})
        with opener.open(req, timeout=3) as r:
            reply = json.loads(r.read())
        sent.append({"seq": i, "delay_s": round(delay, 3), "reply": reply})
    return sent
