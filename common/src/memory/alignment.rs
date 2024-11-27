// use crate::constants::WORD_SIZE;

#[macro_export]
macro_rules! word_align {
    ($len:expr) => {
        ($len + $crate::constants::WORD_SIZE - 1) & !($crate::constants::WORD_SIZE - 1)
    };
}

#[macro_export]
macro_rules! bytes_to_words {
    ($bytes:expr) => {{
        // Convert the associated data to word representation.
        let mut bytes = $bytes.to_vec();
        let padded_len = $crate::word_align!(bytes.len());
        bytes.resize(padded_len, 0);
        // Convert to u32 chunks.
        bytes
            .chunks($crate::constants::WORD_SIZE)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<u32>>()
    }};
}

#[macro_export]
macro_rules! words_to_bytes {
    ($words:expr) => {{
        let mut bytes: Vec<u8> = Vec::with_capacity($words.len() * $crate::constants::WORD_SIZE);
        for word in $words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }};
}
