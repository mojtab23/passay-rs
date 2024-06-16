pub trait Entropy {
    /// Returns the estimated entropy bits of a password.
    fn estimate() -> f64;
}
