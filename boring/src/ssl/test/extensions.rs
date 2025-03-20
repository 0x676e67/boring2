use crate::ssl::ExtensionType;

#[test]
fn test_exntension_order_index() {
    let mut i = 0;
    for ext in ExtensionType::BORING_SSLEXTENSION_PERMUTATION {
        assert_eq!(ExtensionType::index_of(*ext), Some(i));
        i += 1;
    }
}
