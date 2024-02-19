mod CONSTANTS {
    const WAD: u256 = 1_000_000_000_000_000_000; // 1e18
    const DEPOSIT: u256 = 0;
    const REPORT: u256 = 1;
    const WITHDRAWAL: u256 = 2;
}

mod MATH {
    fn pow(base: u256, mut exp: u256) -> u256 {
        if exp == 0 {
            1
        } else {
            base * pow(base, exp - 1)
        }
    }
}
