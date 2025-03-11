/// Strategy trait to support objects that produce hash outputs in various formats, e.g. raw bytes, hex output, etc.
pub trait Hasher<E> {
    /// Hashes the given data.
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, E>;

    ///Compares a known hash value with the hash of the given data.
    fn compare(&self, hash: &[u8], data: &[u8]) -> Result<bool, E>;
}
