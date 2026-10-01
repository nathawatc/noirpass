mod aliases;
mod collections;
mod items;
mod persistence;
mod properties;
mod sessions;
mod signals;

pub(super) async fn run_ordered() {
    eprintln!("scenario 1: encrypted session roundtrip");
    sessions::s1_encrypted_roundtrip().await;
    eprintln!("scenario 2: plain session roundtrip");
    sessions::s2_plain_roundtrip().await;
    eprintln!("scenario 3: strict plain protocol validation");
    sessions::s3_plain_protocol_validation().await;
    eprintln!("scenario 3b: replace semantics");
    items::s3_replace_semantics().await;
    eprintln!("scenario 4: aliases");
    aliases::s4_aliases().await;
    eprintln!("scenario 5: collection lifecycle");
    collections::s5_collection_lifecycle().await;
    eprintln!("scenario 6: bulk GetSecrets");
    sessions::s6_get_secrets_bulk().await;
    eprintln!("scenario 6b: cross-client session rejection");
    sessions::s6b_cross_client_session_rejected().await;
    eprintln!("scenario 6c: temporary session collection");
    sessions::s6c_temporary_session_collection().await;
    eprintln!("scenario 6d: temporary collection modification notifications");
    sessions::s6d_session_collection_notifications().await;
    eprintln!("scenario 7: persistence across restart");
    persistence::s7_persistence_across_restart().await;
    #[cfg(feature = "secret-tool-smoke")]
    {
        eprintln!("scenario 8: secret-tool smoke");
        persistence::s8_secret_tool_smoke().await;
    }
    eprintln!("scenario 10: signals");
    signals::s10_signals().await;
    eprintln!("scenario 11: lock semantics");
    signals::s11_lock_semantics().await;
    eprintln!("scenario 12: item mutation signals");
    signals::s12_item_mutation_signals().await;
    eprintln!("scenario 13: existing alias collection creation");
    aliases::s13_existing_alias_collection().await;
    eprintln!("scenario 14: collection and alias notifications");
    Box::pin(aliases::s14_collection_alias_notifications()).await;
    eprintln!("scenario 15: malformed known properties");
    properties::s15_malformed_known_properties().await;
}
