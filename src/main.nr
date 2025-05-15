use dep::std;

// Hangman circuit that prevents frontrunning and verifies the validity of the word
fn main(
    word: [Field; 10], // Word to guess, maximum of 10 characters
    word_length: pub Field, // Length of the word, number of characters
    winner: pub Field, // Wallet of the winner, must be included in the transaction parameters to prevent frontrunning
) -> pub Field {
    // Converts the word to bytes to be compatible with the keccak256 library implementation we'll use
    // Also, we verify that the word contains only alphabetic characters
    let mut word_bytes = [0; 10];
    for i in 0..10 {
        if i < word_length as u8 {
            let current_char = word[i] as u8;
            let is_uppercase = (current_char >= 65) & (current_char <= 90);
            let is_lowercase = (current_char >= 97) & (current_char <= 122);
            assert(is_uppercase | is_lowercase);
        }
        word_bytes[i] = word[i] as u8;
    }

    // Compute the hash of the word
    let hash_bytes = std::hash::blake3(word_bytes);

    // Convert the hash into a 256-bit number to reduce proof size
    let mut computed_hash = 0 as Field;
    for i in 0..30 {
        computed_hash = computed_hash * 256 + (hash_bytes[i] as Field);
    }

    println(computed_hash);
    println(hash_bytes);

    // Return the hash of the word; remember that return values are public parameters in the contract
    computed_hash
}
