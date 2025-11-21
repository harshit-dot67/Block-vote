# Block-vote

Block-vote is a prototype blockchain-inspired voting system designed for tamper-resistance, transparency, verifiability, privacy, and affordability. It uses modern microcontroller hardware and advanced cryptography to protect the integrity and privacy of every vote.

## System Architecture

Block-vote uses the following components:

- **ESP32 Microcontroller:** The hardware platform manages authentication, vote casting, cryptography, and data storage.
- **RFID Voter Authentication:** Only authorized users (with valid RFID cards) can cast votes.
- **OLED Display Interface:** Provides clear user feedback and status throughout the voting process.
- **Hardware Buttons:** Physical controls for intuitive vote casting.
- **Encrypted Vote Storage:** 
  - Votes are encrypted using **AES-256 encryption** for maximum privacy and security.
  - The system stores ONLY encrypted data—no plaintext votes anywhere on device or database.
- **Blockchain-style Merkle Root Anchoring:**
  - Votes are grouped in a Merkle Tree and the Merkle Root is recorded—ensuring session-level integrity and immutability.
- **Receipts via Cryptographic Hashing:**
  - Each vote generates a unique **SHA-256 hash** as a “receipt.”
  - Voters can use this hash to verify their vote inclusion, without revealing vote contents or choices.

## Privacy by Design

- **Zero Knowledge Storage:** As only encrypted data is saved, *even system administrators cannot see who voted for whom or what was voted*.
- **Receipt System:** Every voter receives a unique SHA-256 hash based on their encrypted vote, allowing independent verification without exposing vote details.

## How It Works

1. **Authenticate:** Voters scan RFID cards to access the system.
2. **Cast a Vote:** Use hardware buttons, with guidance on the OLED display.
3. **Encrypt & Hash:** Vote is encrypted using AES-256, then a SHA-256 hash receipt is generated.
4. **Store Securely:** Only the AES-encrypted vote data is stored.
5. **Anchor with Merkle Root:** Session votes are combined in a Merkle Tree and anchored for auditability and tamper proofing.

## Key Attributes

- **Tamper-resistant:** Merkle root and encrypted storage prevent any manipulation.
- **Transparent:** External parties can audit Merkle roots and vote hashes for integrity.
- **Verifiable:** Any vote can be verified by its hash, while actual choices remain private.
- **Secure:** End-to-end AES encryption and authenticated RFID access.
- **User-friendly:** Simple interface and clear confirmation at every step.
- **Affordable:** Based on ESP32 and off-the-shelf components.

## Getting Started

1. **Clone the code**
   ```bash
   git clone https://github.com/harshit-dot67/Block-vote.git
   cd Block-vote
   ```
2. **Prepare hardware**
   - ESP32 board
   - RFID reader and cards
   - OLED display (e.g. SSD1306)
   - Hardware buttons
3. **Build and flash** using ESP32 development tools.
4. **Connect and test** voting flow as described above.

## Contributing

PRs and suggestions are welcome. For issues, start a discussion or open a ticket.

## License

*Please add your chosen open source license here.*

---

*Block-vote makes real-world, secure, private voting possible—harnessing encryption and blockchain principles for modern democracy.*
