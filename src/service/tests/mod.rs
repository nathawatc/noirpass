mod support;

pub(in crate::service) use support::test_state;
use support::{get_property, next_stream_item, p2p_pair};

mod basic;
mod bulk;
mod collection_items;
mod lifecycle;
mod namespace;
mod objects;
mod registry;
mod sessions;
mod state;
mod temporary;
