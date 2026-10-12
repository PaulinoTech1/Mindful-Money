/* Recovery key wordlist: 256 common short words.
 * Each word encodes 8 bits. A 256-bit recovery key = 32 words.
 *
 * NOTE: This is a simplified scheme for the prototype. Production should
 * use BIP-39 (2048 words, 24 words for 256 bits with checksum).
 * Words are chosen to be distinct and easy to transcribe.
 */

const RECOVERY_WORDS = [
  "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
  "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
  "acoustic", "acquire", "across", "action", "actor", "actress", "actual", "adapt",
  "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice",
  "aerobic", "affair", "afford", "afraid", "again", "agent", "agree", "ahead",
  "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
  "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
  "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused",
  "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle",
  "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any",
  "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
  "area", "arena", "argue", "arm", "armed", "armor", "army", "around",
  "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork",
  "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
  "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august",
  "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
  "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor",
  "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
  "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket",
  "battle", "beach", "bean", "beauty", "because", "become", "beef", "before",
  "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
  "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike",
  "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame",
  "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse",
  "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb",
  "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
  "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass",
  "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring",
  "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush",
  "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet",
  "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
  "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage",
  "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel",
  "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain",
];

// Reverse lookup: word -> index
const RECOVERY_WORD_INDEX = new Map(RECOVERY_WORDS.map((w, i) => [w, i]));

/**
 * Encode 32 bytes as 32 recovery words.
 */
function encodeRecoveryKey(bytes) {
  if (bytes.length !== 32) throw new Error('Recovery key must be 32 bytes');
  return Array.from(bytes).map(b => RECOVERY_WORDS[b]).join(' ');
}

/**
 * Decode 32 recovery words to 32 bytes.
 * Throws on invalid words or wrong count.
 */
function decodeRecoveryKey(mnemonic) {
  const words = mnemonic.toLowerCase().trim().split(/\s+/);
  if (words.length !== 32) {
    throw new Error(`Recovery key must be 32 words, got ${words.length}`);
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const idx = RECOVERY_WORD_INDEX.get(words[i]);
    if (idx === undefined) throw new Error(`Invalid recovery word: "${words[i]}"`);
    bytes[i] = idx;
  }
  return bytes;
}
