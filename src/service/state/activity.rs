//! Request admission, activity tracking, and shutdown selection.

use std::sync::Arc;
use std::time::Duration;

use zbus::fdo;

use super::{ADMITTED_REQUEST, ActivityGuard, RequestGuard, ServiceState};

impl ServiceState {
    /// Admit work without building an unbounded queue of client-owned arguments.
    pub(crate) fn request<T>(self: &Arc<Self>, input: &T) -> fdo::Result<Arc<RequestGuard>>
    where
        T: ?Sized + serde::Serialize + zbus::zvariant::DynamicType,
    {
        let activity = self.activity()?;
        let limit = || fdo::Error::LimitsExceeded("request capacity exhausted; retry later".into());
        let slot = self
            .request_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| limit())?;
        // Size calculation writes to a null sink; it creates no plaintext copy.
        let bytes = zbus::wire::serialized_size(
            zbus::wire::serialized::Context::new(zbus::wire::LE, 0),
            input,
        )
        .map_err(|err| fdo::Error::InvalidArgs(err.to_string()))?
        .size();
        let bytes = u32::try_from(bytes).map_err(|_| limit())?;
        let bytes = self
            .request_bytes
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| limit())?;
        Ok(Arc::new(RequestGuard {
            activity,
            _slot: slot,
            _bytes: bytes,
        }))
    }

    /// Track one D-Bus method until its handler returns.
    pub(crate) fn activity(self: &Arc<Self>) -> fdo::Result<ActivityGuard> {
        let mut activity = self.activity.lock().expect("activity lock poisoned");
        let admitted = ADMITTED_REQUEST
            .try_with(|request| Arc::ptr_eq(&request.activity.state, self))
            .unwrap_or(false);
        if activity.shutting_down && !admitted {
            return Err(fdo::Error::Failed("service is shutting down".into()));
        }
        activity.active_calls += 1;
        activity.had_activity = true;
        Ok(ActivityGuard {
            state: self.clone(),
        })
    }

    /// Close admission for new application handlers.
    pub fn begin_shutdown(&self) {
        self.activity
            .lock()
            .expect("activity lock poisoned")
            .shutting_down = true;
    }

    /// Wake shutdown selection when the last active handler completes.
    pub async fn wait_for_activity_completion(&self) {
        self.activity_complete.notified().await;
    }

    /// Wake shutdown selection after background cleanup completes (e.g. session reaping).
    pub fn notify_activity_completion(&self) {
        self.activity_complete.notify_one();
    }

    /// Wait until every already-admitted application handler has returned.
    pub async fn wait_for_active_calls(&self) {
        loop {
            // Create notification future before checking the condition. `notify_one`
            // preserves a completion that races with the check as a stored permit.
            let notified = self.activity_complete.notified();
            let active_calls = self
                .activity
                .lock()
                .expect("activity lock poisoned")
                .active_calls;
            if active_calls == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Atomically select idle shutdown against application-handler admission.
    pub fn try_begin_idle_shutdown(&self, idle_exit: i64) -> bool {
        if idle_exit < 0 {
            return false;
        }

        let mut activity = self.activity.lock().expect("activity lock poisoned");
        if activity.shutting_down || activity.active_calls != 0 {
            return false;
        }
        if !self
            .sessions
            .lock()
            .expect("session lock poisoned")
            .is_empty()
            || !self
                .session_collection
                .lock()
                .expect("session collection lock poisoned")
                .items
                .is_empty()
        {
            return false;
        }

        let eligible = if idle_exit == 0 {
            activity.had_activity
        } else {
            let idle_limit = Duration::from_secs(
                u64::try_from(idle_exit).expect("positive idle timeout must fit u64"),
            );
            activity.last_activity.elapsed() >= idle_limit
        };
        if eligible {
            activity.shutting_down = true;
        }
        eligible
    }
}
