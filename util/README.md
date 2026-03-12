# util — P2Pool Authority Tools

Standalone utilities for **authority key holders** and **node operators**.  
No build step required — pure Python 3.

---

## `create_transition_message.py`

Creates, signs, encrypts, and verifies P2Pool V36 authority messages.

Messages are:
1. **Signed** with an ECDSA secp256k1 key (proving authorship)
2. **Encrypted** using the authority pubkey (preventing on-the-wire sniffing)

Only an authority key holder (matching a `COMBINED_DONATION_SCRIPT` pubkey)
can produce a valid message.  Node operators just receive and paste the hex string.

### Install dependencies

```bash
pip3 install ecdsa          # or: pip3 install coincurve  (faster)
pip3 install mnemonic       # optional — only needed for BIP39 seed phrases
```

### Quick-start (authority key holder)

```bash
# Create a transition signal  v36 → v37
python3 create_transition_message.py create \
    --privkey <64-hex-chars> \
    --from 36 --to 37 \
    --msg "Upgrade to V37" \
    --urgency recommended \
    --url "https://github.com/frstrtr/p2pool-merged-v36/releases"

# Create a general announcement
python3 create_transition_message.py announce \
    --privkey <64-hex-chars> \
    --msg "Maintenance window: Feb 28 00:00-02:00 UTC" \
    --urgency info

# Create an emergency alert
python3 create_transition_message.py announce \
    --privkey <64-hex-chars> --emergency \
    --msg "Critical bug — upgrade immediately" \
    --urgency required

# Encrypt your key into a keystore file
python3 create_transition_message.py create-keystore \
    --privkey <64-hex-chars> --keystore-out keystore.json

# Verify any hex blob (authority or operator)
python3 create_transition_message.py verify --file transition_message_v36_v37.hex
```

### Quick-start (node operator)

```bash
# Pass the hex string on startup
python run_p2pool.py [options] --transition-message 01a2b3c4d5e6...

# Or point to the saved .hex file
python run_p2pool.py [options] --transition-message transition_message_v36_v37.hex
```

### Authority pubkeys (from `COMBINED_DONATION_REDEEM_SCRIPT`)

| Name        | Compressed pubkey |
|------------|-------------------|
| forrestv   | `03ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1` |
| maintainer | `02fe6578f8021a7d466787827b3f26437aef88279ef380af326f87ec362633293a` |
