#[derive(Clone, Copy)]
pub struct Hash([u8; 32]);

impl Hash {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct Hasher {
    buf: [u8; 64],
    len: usize,
    keyed: bool,
    key_words: [u64; 4],
}

impl Hasher {
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [0u8; 64],
            len: 0,
            keyed: false,
            key_words: [0u64; 4],
        }
    }

    #[inline]
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u64; 4];
        // Pack the 32-byte key into four little-endian u64 words
        for i in 0..4 {
            let mut w = 0u64;
            for b in 0..8 {
                w |= (key[i * 8 + b] as u64) << (8 * b);
            }
            key_words[i] = w;
        }
        Self {
            buf: [0u8; 64],
            len: 0,
            keyed: true,
            key_words,
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        // Consume up to 64 bytes; excess input is ignored to match single-block semantics
        let take = core::cmp::min(data.len(), 64usize.saturating_sub(self.len));
        self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
        self.len += take;
    }

    #[inline]
    pub fn finalize(&self) -> Hash {
        let input_words = pack_le_u64_8(&self.buf[..self.len]);
        let mut m = input_words;

        // If keyed, blend the key into the message words to derive a keyed hash
        if self.keyed {
            for i in 0..4 { m[i] = m[i].wrapping_add(self.key_words[i]); }
        }

        let state = hash_internal(&m);
        // Derive 32-byte digest by mixing halves of the 512-bit state
        let out_words = [
            state[0] ^ state[4],
            state[1] ^ state[5],
            state[2] ^ state[6],
            state[3] ^ state[7],
        ];
        let mut out = [0u8; 32];
        let mut pos = 0usize;
        for &w in out_words.iter() {
            for b in 0..8 {
                out[pos] = ((w >> (8 * b)) & 0xFF) as u8;
                pos += 1;
            }
        }
        Hash(out)
    }
}

#[inline]
pub fn hash(data: &[u8]) -> Hash {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

// Blake3 IV constants (64-bit form, simplified).
const IV: [u64; 4] = [
    0xbb67_ae85_6a09_e667,
    0xa54f_f53a_3c6e_f372,
    0x9b05_688c_510e_527f,
    0x5be0_cd19_1f83_d9ab,
];

#[inline]
fn pack_le_u64_8(data: &[u8]) -> [u64; 8] {
    let mut words = [0u64; 8];
    let len = core::cmp::min(data.len(), 64);
    let mut off = 0usize;
    for i in 0..8 {
        let mut w = 0u64;
        for b in 0..8 {
            if off < len {
                w |= (data[off] as u64) << (8 * b);
                off += 1;
            } else {
                break;
            }
        }
        words[i] = w;
    }
    words
}

#[inline]
fn hash_internal(block: &[u64; 8]) -> [u64; 8] {
    let mut state = [0u64; 8];
    state[..4].copy_from_slice(&IV);

    let mut v = [0u64; 16];
    // v[0..3] = state
    v[0] = state[0];
    v[1] = state[1];
    v[2] = state[2];
    v[3] = state[3];
    // v[4..7] = IV
    v[4] = IV[0];
    v[5] = IV[1];
    v[6] = IV[2];
    v[7] = IV[3];
    // v[8..15] = input
    for i in 0..8 { v[8 + i] = block[i]; }

    // Local message words that get permuted per-round
    let mut m = *block;

    for round in 0..5 {
        // Column rounds
        g(&mut v, 0, 4, 8, 12, m[0], m[1]);
        g(&mut v, 1, 5, 9, 13, m[2], m[3]);
        g(&mut v, 2, 6, 10, 14, m[4], m[5]);
        g(&mut v, 3, 7, 11, 15, m[6], m[7]);

        // Diagonal rounds
        g(&mut v, 0, 5, 10, 15, m[1], m[2]);
        g(&mut v, 1, 6, 11, 12, m[3], m[4]);
        g(&mut v, 2, 7, 8, 13, m[5], m[6]);
        g(&mut v, 3, 4, 9, 14, m[7], m[0]);

        // Simple message permutation
        if round < 4 {
            let temp = m[0];
            for i in 0..7 { m[i] = m[i + 1]; }
            m[7] = temp;
        }
    }

    // Finalize
    for i in 0..4 {
        state[i] = v[i] ^ v[i + 8];
    }
    for i in 4..8 {
        state[i] = v[i] ^ v[i + 4];
    }
    state
}

#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, mx: u64, my: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}