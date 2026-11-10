use rand::seq::IndexedRandom;

const ADJECTIVES: &[&str] = &[
    "amber", "arctic", "azure", "bold", "brave", "bright", "bronze", "calm",
    "cedar", "clever", "cloud", "cobalt", "copper", "coral", "cosmic", "crimson",
    "crystal", "dawn", "delta", "desert", "drift", "dusty", "eagle", "echo",
    "ember", "emerald", "falcon", "fern", "flame", "forest", "frost", "frozen",
    "golden", "granite", "green", "harbor", "haven", "indigo", "island", "jasper",
    "jungle", "laser", "lunar", "magic", "maple", "marble", "meadow", "midnight",
    "misty", "moon", "moss", "mystic", "nebula", "neon", "ninja", "noble",
    "nordic", "nova", "oasis", "ocean", "onyx", "orbit", "pale", "pearl",
    "phantom", "pine", "pixel", "polar", "prism", "pulse", "quantum", "quiet",
    "radiant", "rapid", "raven", "reef", "ridge", "river", "ruby", "rusty",
    "sage", "sapphire", "shadow", "shining", "silent", "silver", "solar", "spark",
    "spring", "steel", "stellar", "storm", "summit", "sunny", "swift", "taiga",
    "thunder", "tidal", "timber", "titan", "topaz", "twilight", "ultra", "valley",
    "velvet", "vibrant", "vortex", "wild", "wind", "winter", "zenith", "zephyr",
];

const NOUNS: &[&str] = &[
    "anchor", "badger", "beacon", "bear", "beaver", "bison", "blazer", "blizzard",
    "breeze", "canyon", "castle", "cat", "cheetah", "cliff", "comet", "condor",
    "coyote", "crater", "creek", "crow", "dolphin", "dragon", "dune", "eagle",
    "falcon", "feather", "finch", "fjord", "fox", "galaxy", "glacier", "goose",
    "grotto", "grove", "gull", "hawk", "hedgehog", "heron", "horizon", "hound",
    "hunter", "husky", "iguana", "island", "jaguar", "jetty", "kite", "koala",
    "lagoon", "leopard", "lighthouse", "lion", "lynx", "mammoth", "mantis", "meadow",
    "meteor", "moose", "mountain", "nebula", "otter", "owl", "panther", "peak",
    "pelican", "penguin", "phoenix", "pinnacle", "planet", "puma", "quarry", "rabbit",
    "raccoon", "raven", "ridge", "river", "robin", "sailor", "salmon", "sanctuary",
    "satellite", "seal", "shark", "sparrow", "star", "stream", "tiger", "torpedo",
    "tower", "trail", "tundra", "turtle", "valley", "vessel", "viper", "voyager",
    "walrus", "whale", "wolf", "wombat", "zebra",
];

/// Generates a human-friendly croc-style code: e.g. "4829-cosmic-falcon"
pub fn generate_code() -> String {
    let mut rng = rand::rng();
    let num: u16 = rand::random_range(1000..=9999);
    let adj = ADJECTIVES.choose(&mut rng).unwrap_or(&"swift");
    let noun = NOUNS.choose(&mut rng).unwrap_or(&"falcon");
    format!("{}-{}-{}", num, adj, noun)
}

/// Normalizes a user-input code (lowercased, trimmed)
pub fn normalize_code(input: &str) -> String {
    input.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_format() {
        let code = generate_code();
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3);
        let num: u16 = parts[0].parse().expect("first part is a 4-digit number");
        assert!((1000..=9999).contains(&num));
        assert!(ADJECTIVES.contains(&parts[1]));
        assert!(NOUNS.contains(&parts[2]));
    }

    #[test]
    fn test_normalize_code() {
        assert_eq!(normalize_code("  4829-COSMIC-Falcon  "), "4829-cosmic-falcon");
        assert_eq!(normalize_code(""), "");
    }
}
