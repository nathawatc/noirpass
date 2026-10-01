//! Collection serialization and blocking worker reservations.

use std::sync::{Arc, Weak};

use tokio::sync::Mutex as AsyncMutex;
use zbus::fdo;

use super::{ADMITTED_REQUEST, CollectionGuard, LifecycleGuard, MutationGuard, ServiceState};
use crate::service::{SESSION_COLLECTION_ID, SecretError};

impl ServiceState {
    /// Serialize namespace changes against collection mutations and publication.
    #[cfg(test)]
    pub(crate) async fn lock_object_lifecycle(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.object_lifecycle.write().await
    }

    /// Serialize only the selected collection; reclaim unused lock entries on admission.
    pub(crate) async fn lock_collection_lifecycle(&self, id: &str) -> CollectionGuard {
        let collection = {
            let mut locks = self
                .collection_lifecycle
                .lock()
                .expect("collection lifecycle lock poisoned");
            locks.retain(|_, lock| lock.strong_count() != 0);
            if let Some(lock) = locks.get(id).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(AsyncMutex::new(()));
                locks.insert(id.to_string(), Arc::downgrade(&lock));
                lock
            }
        };
        // Do not pin the namespace while queued behind another mutation of this collection.
        let collection = collection.lock_owned().await;
        let namespace = self.object_lifecycle.clone().read_owned().await;
        CollectionGuard {
            _collection: collection,
            _namespace: namespace,
        }
    }

    /// Run synchronous encryption/storage without blocking executor threads.
    /// Keep admission, capacity, and any mutation lock alive even if the waiter is cancelled.
    pub(crate) async fn blocking<T: Send + 'static>(
        self: &Arc<Self>,
        lifecycle: Option<Arc<MutationGuard>>,
        operation: impl FnOnce(&Self) -> Result<T, SecretError> + Send + 'static,
    ) -> Result<T, SecretError> {
        let activity = self.activity()?;
        let permit = if lifecycle.is_none() {
            Some(
                self.blocking_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| fdo::Error::Failed("blocking work is unavailable".into()))?,
            )
        } else {
            None // MutationGuard already reserved capacity before acquiring the lifecycle lock.
        };
        let request = ADMITTED_REQUEST.try_with(Arc::clone).ok();
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            let (_activity, _permit, _lifecycle, _request) = (activity, permit, lifecycle, request);
            operation(&state)
        })
        .await
        .map_err(|_| fdo::Error::Failed("blocking work failed".into()))?
    }

    pub(crate) async fn lock_owned_collection_lifecycle(&self, id: &str) -> Arc<MutationGuard> {
        // Temporary mutations must remain available when every persistent worker is busy.
        let permit = if id == SESSION_COLLECTION_ID {
            None
        } else {
            Some(
                self.blocking_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("blocking capacity is never closed"),
            )
        };
        let lifecycle = self.lock_collection_lifecycle(id).await;
        Arc::new(MutationGuard {
            _lifecycle: LifecycleGuard::Collection { _guard: lifecycle },
            _permit: permit,
        })
    }

    /// Reserve worker capacity before exclusive namespace admission, through publication.
    pub(crate) async fn lock_owned_namespace_lifecycle(&self) -> Arc<MutationGuard> {
        let permit = self
            .blocking_slots
            .clone()
            .acquire_owned()
            .await
            .expect("blocking capacity is never closed");
        let namespace = self.object_lifecycle.clone().write_owned().await;
        Arc::new(MutationGuard {
            _lifecycle: LifecycleGuard::Namespace { _guard: namespace },
            _permit: Some(permit),
        })
    }
}
