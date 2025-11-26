/***************************************************
   ESP32 Voting Machine Prototype
   Features:
   - RFID Authentication (MFRC522)
   - OLED Display Menu
   - RTC CLOCK TIMESTAMPS
   - AES-256-CBC Encryption
   - SHA256 Receipt
   - HMAC-SHA256 Integrity
   - SPIFFS Log Storage
   - Two Buttons (Next/Select)
   - EXPORT,STATS,CLEAR,CLOSE command for admin

   Wiring:
   OLED (SSD1306):
     SDA → GPIO21
     SCL → GPIO22

   RTC Clock:
     SDA → GPIO21
     SCL → GPIO22

   RFID RC522 (SPI):
     SDA/SS → GPIO5
     RST → GPIO4
     SCK → GPIO18
     MOSI → GPIO23
     MISO → GPIO19

   Buttons:
     NEXT → GPIO32 → GND
     SELECT → GPIO33 → GND
 ***************************************************/
#include <RTClib.h>
#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include <SPIFFS.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <ArduinoJson.h>
#include <vector>
#include <Preferences.h>

void drawText(const char* l1, const char* l2 = NULL);


Preferences prefs;//NVS(non-volatile storage)

// ---------- Poll window & auto-close ----------
bool pollClosed = false;
DateTime vote_start;
DateTime vote_end;
bool autoCloseEnabled = true;    // flip to false to disable auto-close (for testing)

int voteCount = 0;

#define OLED_RESET -1
Adafruit_SSD1306 display(128, 64, &Wire, OLED_RESET);

#define SS_PIN   5
#define RST_PIN  4
MFRC522 mfrc(SS_PIN, RST_PIN);

// Buttons
#define BTN_NEXT   32
#define BTN_SELECT 33

//Clock
RTC_DS3231 rtc;

// Candidates
const char* candidates[] = {"Prakash(BJP)", "Smita(Congress)", "Arjun(NCP)","NOTA"};
const int NUM_CANDIDATES = 4;
int candidateVotes[NUM_CANDIDATES] = {0};

// AES Key (32 bytes for AES-256)
const uint8_t ELECTION_KEY[32] = {
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
  0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
  0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
};

String toHex(const uint8_t *data, size_t len) {
  String s; s.reserve(len*2);
  const char hexmap[] = "0123456789ABCDEF";
  for (size_t i = 0; i < len; i++) {
    s += hexmap[(data[i] >> 4) & 0xF];
    s += hexmap[data[i] & 0xF];
  }
  return s;
}

void sha256_hash(const uint8_t* data, size_t len, uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

// helper: compute SHA256 hex from bytes
String sha256HexBytes(const uint8_t *data, size_t len) {
  uint8_t out[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
  return toHex(out, 32);
}

// helper: compute SHA256 hex of an ASCII String
String sha256HexString(const String &s) {
  return sha256HexBytes((const uint8_t*)s.c_str(), s.length());
}

// Build Merkle root from /votes.log and return hex root; also fill count
String computeMerkleRootFromFile(const char *path, int &outCount) {
  File f = SPIFFS.open(path, "r");
  if (!f) {
    outCount = 0;
    return String("");
  }

  // Read all leaves into a vector (leaf = sha256(ciphertext || iv) )
  std::vector<String> leaves;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    DynamicJsonDocument doc(2048);
    DeserializationError err = deserializeJson(doc, line);
    if (err) continue;

    String ciphertext = doc["ciphertext"].as<String>();
    String iv = doc["iv"].as<String>();

    // leaf = SHA256(ciphertext || iv) using ASCII concat
    String cat = ciphertext + iv;
    String leaf = sha256HexString(cat);
    leaves.push_back(leaf);
  }
  f.close();

  outCount = leaves.size();
  if (leaves.size() == 0) return String("");

  // Build tree upward: using vector of strings
  std::vector<String> cur = leaves;
  while (cur.size() > 1) {
    std::vector<String> next;
    for (size_t i = 0; i < cur.size(); i += 2) {
      String left = cur[i];
      String right = (i + 1 < cur.size()) ? cur[i + 1] : left; // duplicate last if odd
      String pair = left + right;
      String ph = sha256HexString(pair);
      next.push_back(ph);
    }
    cur = next;
  }
  return cur[0]; // root hex
}



bool aes256_encrypt(
  const uint8_t key[32],
  const uint8_t iv_in[16],
  const uint8_t* plain,
  size_t plen,
  uint8_t* out,
  size_t &olen
){
  size_t pad = 16 - (plen % 16);
  size_t total = plen + pad;
  uint8_t* buf = (uint8_t*)malloc(total);
  memcpy(buf, plain, plen);
  memset(buf + plen, pad, pad);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256);

  uint8_t iv[16];
  memcpy(iv, iv_in, 16);

  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, total, iv, buf, out);
  olen = total;

  free(buf);
  mbedtls_aes_free(&aes);
  return true;
}

void drawText(const char* l1, const char* l2) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,10);
  display.println(l1);
  if (l2) {
    display.println();
    display.println(l2);
  }
  display.display();
}

// closePoll() prints the final export block with root and all logs
void closePoll() {
  pollClosed = true;
  drawText("Poll closing", "Please wait");

  Serial.println("=== POLL CLOSED ===");

  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0,0);
  display.println("Generating proofs...");
  display.display();
  delay(500);

  int total = 0;
  String root = computeMerkleRootFromFile("/votes.log", total);

  // ======== BEGIN: MERKLE EXPORT BLOCK ========
{
  DynamicJsonDocument merkleDoc(60000);

  // 1) Add Merkle root
  merkleDoc["merkle_root"] = root;

  // 2) Recompute leaves EXACTLY as ESP32 hashed them: SHA256(ciphertext + iv)
  JsonArray leavesArr     = merkleDoc.createNestedArray("leaves");
  JsonArray leafInputsArr = merkleDoc.createNestedArray("leaf_inputs");   // NEW
  std::vector<String> leavesVec;

  File f = SPIFFS.open("/votes.log", "r");
  if (f) {
    while (f.available()) {
      String line = f.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) continue;

      DynamicJsonDocument d2(2048);
      if (deserializeJson(d2, line)) continue;

      String ciphertext = d2["ciphertext"].as<String>();
      String iv         = d2["iv"].as<String>();

      // EXACT hashing input
      String cat = ciphertext + iv;

      leafInputsArr.add(cat);    // export exact hashing input

      String leaf = sha256HexString(cat);
      leavesArr.add(leaf);
      leavesVec.push_back(leaf);
    }
    f.close();
  }

  // 3) Build Merkle levels
  std::vector<std::vector<String>> levels;
  if (!leavesVec.empty()) {
    levels.push_back(leavesVec);
    std::vector<String> cur = leavesVec;

    while (cur.size() > 1) {
      std::vector<String> next;
      for (size_t i = 0; i < cur.size(); i += 2) {
        String left  = cur[i];
        String right = (i + 1 < cur.size()) ? cur[i+1] : cur[i];
        String parent = sha256HexString(left + right);   // ASCII concat
        next.push_back(parent);
      }
      levels.push_back(next);
      cur = next;
    }
  }

  // 4) Build proofs
  JsonObject proofsObj = merkleDoc.createNestedObject("proofs");

  for (size_t idx = 0; idx < leavesVec.size(); ++idx) {
    JsonArray pArr = proofsObj.createNestedArray(leavesVec[idx]);
    size_t index = idx;

    for (size_t lvl = 0; lvl < levels.size() - 1; ++lvl) {
      auto &layer = levels[lvl];

      size_t sib_i = (index % 2 == 0) ? index + 1 : index - 1;
      String pos   = (index % 2 == 0) ? "right" : "left";
      if (sib_i >= layer.size()) sib_i = index;

      JsonObject step = pArr.createNestedObject();
      step["sibling"] = layer[sib_i];
      step["pos"]     = pos;

      index /= 2;
    }
  }

  // 5) Print JSON to serial
  String exportJSON;
  serializeJson(merkleDoc, exportJSON);

  Serial.println("BEGIN_MERKLE_EXPORT");
  Serial.println(exportJSON);
  Serial.println("END_MERKLE_EXPORT");
}
// ======== END: MERKLE EXPORT BLOCK ========




  Serial.print("MERKLE_ROOT: ");
  Serial.println(root);
  Serial.print("LOG_COUNT: ");
  Serial.println(total);

  Serial.println("BEGIN LOGS");
  File f = SPIFFS.open("/votes.log", "r");
  if (f) {
    while (f.available()) {
      String line = f.readStringUntil('\n');
      if (line.length()) Serial.println(line);
    }
    f.close();
  }

// ---- OLED tally ----
display.clearDisplay();
display.setTextSize(1);
display.setCursor(0,0);
display.println("Vote Tally:");

for (int i = 0; i < NUM_CANDIDATES; i++) {
    display.printf("%s: %d votes\n", candidates[i], candidateVotes[i]);
}
display.display();
delay(2500);
// ===================== NOTA SAFETY LOGIC =====================
bool repeatElection = false;       // whether NOTA invalidates election
bool skipWinnerAnimation = false;  // whether to skip the winner display

int notaIndex = NUM_CANDIDATES - 1;
int notaVotes = candidateVotes[notaIndex];

// Find top candidate EXCLUDING NOTA
int topCandidate = 0;
for (int i = 1; i < NUM_CANDIDATES - 1; i++) {
    if (candidateVotes[i] > candidateVotes[topCandidate]) {
        topCandidate = i;
    }
}
int topCandidateVotes = candidateVotes[topCandidate];

// CASE 1 — NOTA strictly higher → Election must be repeated
if (notaVotes > topCandidateVotes) {
    repeatElection = true;
    skipWinnerAnimation = true;
}

// CASE 2 — NOTA ties → Candidate still wins
else if (notaVotes == topCandidateVotes) {
    skipWinnerAnimation = false;  // winner = topCandidate
}

// CASE 3 — Normal winner case
int winner = topCandidate;
// ===================== END NOTA SAFETY LOGIC =====================

// ===== DISPLAY NOTA RESULT IF NEEDED =====
if (repeatElection) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(0,10);
    display.println("Highest votes = NOTA");
    display.setCursor(0,30);
    display.println("Election must be");
    display.setCursor(0,45);
    display.println("REPEATED");
    display.display();
    delay(4000);
}


for (int i = 1; i < NUM_CANDIDATES - 1; i++) {  
    // EXCLUDE LAST INDEX (NOTA)
    if (candidateVotes[i] > candidateVotes[winner]) {
        winner = i;
    }
}

int bestCount = -1;

  if (!skipWinnerAnimation) {
    display.clearDisplay();
    display.setTextSize(2);
    display.setCursor(0,10);
    display.println("WINNER:");
    display.setCursor(0,35);
    display.println(candidates[winner]);
    display.display();

  // Blink animation
  for (int i = 0; i < 6; i++) {
      display.invertDisplay(true);
      delay(250);
      display.invertDisplay(false);
      delay(250);
  }


  Serial.println("END LOGS");
  Serial.println("=== END POLL ===");

  drawText("Poll closed", "Export printed");

  // Final END POLL screen (always shown)
  display.clearDisplay();
  display.setTextSize(2);
  display.setCursor(0,20);
  display.println("END POLL");
  display.display();
  delay(2000);

}
}


void exportLogs(){
  Serial.println("=== BEGIN LOGS ===");
  File f = SPIFFS.open("/votes.log", "r");
  if (!f) {
    Serial.println("LOG EMPTY");
    Serial.println("=== END LOGS ===");
    return;
  }
  if(!f.available()) { 
    f.close();
    Serial.println("LOG EMPTY"); // Prints if file exists but is empty
    Serial.println("=== END LOGS ===");
    return;
  }
  while (f.available()) {
    Serial.println(f.readStringUntil('\n'));
  }
  f.close();
  Serial.println("=== END LOGS ===");
}

// ---------------- MAIN VOTING ----------------
void handleVote(){

  // check if poll time is over
  if (pollClosed) {
    drawText("Voting closed", "No new votes");
    return;
  }


  // 1) RFID detection
  if (!mfrc.PICC_IsNewCardPresent()) return;
  if (!mfrc.PICC_ReadCardSerial()) return;

  String uid = "";
  for (byte i = 0; i < mfrc.uid.size; i++) {
    uid += (mfrc.uid.uidByte[i] < 0x10 ? "0" : "");
    uid += String(mfrc.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();

  // ---------- Enforce voting window ----------
  DateTime now = rtc.now();
  if (autoCloseEnabled && now < vote_start) {
    drawText("Voting not started", "");
    Serial.println("Vote attempt before start");
    delay(800);
    return;
  }
  if (autoCloseEnabled && now >= vote_end) {
    if (!pollClosed) {
      closePoll();   // auto-close once
    }
    drawText("Voting closed", "No new votes");
    delay(800);
    return;
  }

  // ---- DOUBLE VOTE PREVENTION ----
  String key = "voted_" + uid;

  if (prefs.isKey(key.c_str())) {
      // This voter has already voted
      drawText("Already voted", "Access denied");
      Serial.print("Double vote blocked: ");
      Serial.println(uid);
      delay(2000);
      drawText("Device Ready", "Scan card");
      return;   // IMPORTANT: stop here!
  }
// ---- END DOUBLE VOTE PREVENTION ----


  drawText("Card Detected", uid.c_str());
  Serial.print("RFID UID: "); Serial.println(uid);

  delay(800);

  // 2) Candidate selection
  int index = 0;
  unsigned long last = 0;
  while (true) {
    display.clearDisplay();
    display.setCursor(0,0);
    display.setTextSize(1);
    display.print("Select Candidate:\n\n");
    for(int i = 0; i < NUM_CANDIDATES; i++){
      if (i == index) display.print("> ");
      else display.print("  ");
      display.println(candidates[i]);
    }
    display.display();

    if (digitalRead(BTN_NEXT) == LOW && millis() - last > 200) {
      index = (index + 1) % NUM_CANDIDATES;
      last = millis();
    }

    if (digitalRead(BTN_SELECT) == LOW && millis() - last > 200) {
      last = millis();
      break;
      
      display.clearDisplay();
      display.setTextSize(1);
      display.setCursor(0, 0);
      display.printf("Selected: %s", candidates[index]);
      display.setCursor(0, 20);
      display.println("Press OK to confirm");
      display.display();
      delay(1200);

    }

    delay(50);
  }

  // 3) Create ballot JSON
  DynamicJsonDocument doc(256);
  doc["uid"] = uid;
  doc["candidate"] = candidates[index];
  doc["candidate_id"] = index;
  DateTime now1 = rtc.now();
  char ts[20];
  sprintf(ts, "%04d-%02d-%02d %02d:%02d:%02d",
        now1.year(), now1.month(), now1.day(),
        now1.hour(), now1.minute(), now1.second());
  doc["timestamp"] = ts;
  doc["device_id"] = "esp32-device-001";
  
  String plain;
  serializeJson(doc, plain);

  // 4) Encrypt
  uint8_t iv[16];
  for (int i = 0; i < 16; i++) iv[i] = esp_random() & 0xFF;

  uint8_t ciphertext[512];
  size_t clen = 0;
  aes256_encrypt(ELECTION_KEY, iv, (uint8_t*)plain.c_str(), plain.length(), ciphertext, clen);

  // 5) Receipt hash = SHA256(ciphertext || iv)
  uint8_t temp[600];
  memcpy(temp, ciphertext, clen);
  memcpy(temp + clen, iv, 16);
  uint8_t receipt[32];
  sha256_hash(temp, clen + 16, receipt);

  // 6) Save to SPIFFS
  DynamicJsonDocument out(1024);
  out["receipt"] = toHex(receipt, 32);
  out["iv"] = toHex(iv, 16);
  out["ciphertext"] = toHex(ciphertext, clen);
  DateTime now2 = rtc.now();
  char ts2[20];
  sprintf(ts2, "%04d-%02d-%02d %02d:%02d:%02d",
        now2.year(), now2.month(), now2.day(),
        now2.hour(), now2.minute(), now2.second());
  out["timestamp"] = ts2;
  out["device_id"] = "esp32-device-001";
  out["candidate"] = index;
  candidateVotes[index]++;   // <-- Track per-candidate tally
  // placeholder for device signature: in prod, sign receiptHash with device private key
  out["deviceSig"] = "TODO_DEVICE_SIGNATURE";


  File f = SPIFFS.open("/votes.log", "a");
  String line;
  serializeJson(out, line);
  f.println(line);
  f.close();
  voteCount++;

  // Mark voter as voted
  prefs.putBool(key.c_str(), true);


  // 7) Show receipt
  drawText("Vote Recorded", toHex(receipt,32).c_str());
  Serial.print("Receipt: "); Serial.println(toHex(receipt,32));

  delay(1000);

  // Thank you splash
  display.clearDisplay();
  display.setTextSize(2);
  display.setCursor(10, 15);
  display.println("Thank You!");
  display.setTextSize(1);
  display.setCursor(5, 45);
  display.println("Receipt Generated");
  display.display();
  delay(1500);

  // Ready screen
  drawText("Device Ready", "Scan card");

}

void setup() {
  Serial.begin(115200);
  delay(200);

  // Filesystem
  if(!SPIFFS.begin(true)) {
    Serial.println("SPIFFS failed!");
  } else {
    Serial.println("SPIFFS mounted");
  }

  // NVS Initialization
  prefs.begin("voters", false);


  // Buttons
  pinMode(BTN_NEXT, INPUT_PULLUP);
  pinMode(BTN_SELECT, INPUT_PULLUP);

  // OLED FIRST (IMPORTANT)
  Wire.begin(21,22);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED FAIL");
    while(1);
  }
  // RTC Clock Start and Check
  if(!rtc.begin()){
    Serial.println("RTC Clock Fail");
  }else{
    Serial.println("RTC OK");
  }

  // OPTIONAL — sets time to compile time (run only once):
  //rtc.adjust(DateTime(F(__DATE__), F(__TIME__))); // intialize clock

  // --------- Configure demo voting window (in setup) ----------
  if (autoCloseEnabled) {
    DateTime now = rtc.now();
    vote_start = now;                       // start now
    vote_end = now + TimeSpan(0, 0, 2, 0); // end in 2 minutes (hh,mm,ss)
    Serial.print("Voting window start: ");
    Serial.println(now.timestamp());        // human readable compact timestamp
    Serial.print("Voting window end: ");
    Serial.println(vote_end.timestamp());
  }


  Serial.println("OLED initialized");

  drawText("Initializing...", "");
  display.display();

  // RFID (SPI next)
  Serial.println("Starting SPI...");
  SPI.begin();
  Serial.println("SPI Started");
  Serial.println("Initializing RFID...");
  delay(100);
  mfrc.PCD_Init();
  Serial.println("RFID ready");
  display.clearDisplay();
  delay(50); // Small delay to ensure SPI communication stabilizes
  drawText("Device Ready", "Scan card");
}

String serialCmd = "";

void loop() {
  // Background auto-close check
  if (autoCloseEnabled && !pollClosed) {
    DateTime now = rtc.now();
    if (now >= vote_end) {
      closePoll();
    }
  }

  // Check SERIAL Commands
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n') {
      
      // ===== ADMIN COMMANDS =====
      if (serialCmd.equalsIgnoreCase("EXPORT")) {
        exportLogs();
      }
      else if (serialCmd.equalsIgnoreCase("STATS")) {
        Serial.println("=== STATS ===");
        Serial.print("Total votes: ");
        Serial.println(voteCount);
        Serial.println("==============");
      }
      else if (serialCmd.equalsIgnoreCase("CLEAR")) {
        Serial.println("Clearing logs and voter registry...");
        
        // Clear SPIFFS file
        SPIFFS.remove("/votes.log");
        File nf = SPIFFS.open("/votes.log", "w");
        nf.close();

        // Clear NVS (voter registry)
        prefs.clear();

        // Reset vote counter
        voteCount = 0;

        Serial.println("Logs cleared");
      }
      else if (serialCmd.equalsIgnoreCase("CLOSE")) {
        Serial.println("Admin close: closing poll now...");
        if (!pollClosed) closePoll();
        else Serial.println("Poll already closed");
      }


      // ==========================

      serialCmd = "";  // reset input buffer
    } 
    else if (c != '\r') {
      serialCmd += c;
    }
}


  // Voting workflow
  handleVote();
}
