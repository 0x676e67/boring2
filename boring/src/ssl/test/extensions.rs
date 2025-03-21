use crate::ssl::ExtensionType;

#[test]
fn test_exntension_order_index() {
    for (i, ext) in ExtensionType::BORING_SSLEXTENSION_PERMUTATION
        .iter()
        .enumerate()
    {
        assert_eq!(ExtensionType::index_of(*ext), Some(i));
    }
}
