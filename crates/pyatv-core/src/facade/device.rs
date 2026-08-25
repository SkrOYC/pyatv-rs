//! Per-method relaying for the device-level interfaces: power, apps and user accounts.
//!
//! Ports `FacadePower` (`pyatv/core/facade.py:305-353`), `FacadeApps` (`facade.py:398-413`) and
//! `FacadeUserAccounts` (`facade.py:416-431`). All three are the same shape as
//! [`crate::facade::FacadeRemoteControl`]: every member is `self.relay("name")(...)` upstream and
//! every member here resolves through [`crate::relayer::Relayer::instance_for`] on the
//! [`FeatureName`] that method's `@feature(...)` decorator carries.
//!
//! `FacadePower`'s relayer is the one built from [`crate::facade::POWER_PRIORITIES`] rather than
//! the default list, which is upstream's `OVERRIDE_PRIORITIES` and its comment "generally favor
//! Companion as it implements power better than MRP". The ordering lives in the relayer, so
//! nothing here has to know about it.
//!
//! The listening half of `FacadePower` — forwarding `powerstate_update` to the caller — is not
//! here; it lives in [`crate::facade::ListenerHub`], for the reason that module documents.

use std::sync::Arc;

use crate::consts::PowerState;
use crate::features::FeatureName;
use crate::interface::{Apps, BoxFuture, Power, UserAccounts};
use crate::models::{App, UserAccount};
use crate::relayer::Relayer;
use crate::{Error, Result};

/// The instance that declared `feature`, or the error upstream's `_find_instance` raises.
fn target<T: ?Sized>(relayer: &Relayer<T>, feature: FeatureName) -> Result<Arc<T>> {
    relayer
        .instance_for(feature)
        .ok_or_else(|| Error::NotSupported(format!("{feature} is not supported")))
}

/// Relays each power call to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadePower {
    relayer: Arc<Relayer<dyn Power>>,
}

impl FacadePower {
    /// Relay through `relayer`, which is expected to carry [`crate::facade::POWER_PRIORITIES`].
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn Power>>) -> Self {
        Self { relayer }
    }
}

impl Power for FacadePower {
    /// The declared protocol's power state, or [`PowerState::Unknown`] when nobody declared one.
    ///
    /// Upstream raises `NotSupportedError` here (`relayer.py:114-115`); the trait's signature has
    /// nowhere to put an error, and "unknown" is what a caller that cannot ask means anyway.
    fn power_state(&self) -> PowerState {
        target(&self.relayer, FeatureName::PowerState)
            .map_or(PowerState::Unknown, |target| target.power_state())
    }

    fn turn_on(&self, await_new_state: bool) -> BoxFuture<'_, Result<()>> {
        match target(&self.relayer, FeatureName::TurnOn) {
            Ok(target) => Box::pin(async move { target.turn_on(await_new_state).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn turn_off(&self, await_new_state: bool) -> BoxFuture<'_, Result<()>> {
        match target(&self.relayer, FeatureName::TurnOff) {
            Ok(target) => Box::pin(async move { target.turn_off(await_new_state).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}

/// Relays each app call to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadeApps {
    relayer: Arc<Relayer<dyn Apps>>,
}

impl FacadeApps {
    /// Relay through `relayer`.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn Apps>>) -> Self {
        Self { relayer }
    }
}

impl Apps for FacadeApps {
    fn app_list(&self) -> BoxFuture<'_, Result<Vec<App>>> {
        match target(&self.relayer, FeatureName::AppList) {
            Ok(target) => Box::pin(async move { target.app_list().await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn launch_app(&self, bundle_id_or_url: &str) -> BoxFuture<'_, Result<()>> {
        let bundle_id_or_url = bundle_id_or_url.to_owned();
        match target(&self.relayer, FeatureName::LaunchApp) {
            Ok(target) => Box::pin(async move { target.launch_app(&bundle_id_or_url).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}

/// Relays each account call to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadeUserAccounts {
    relayer: Arc<Relayer<dyn UserAccounts>>,
}

impl FacadeUserAccounts {
    /// Relay through `relayer`.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn UserAccounts>>) -> Self {
        Self { relayer }
    }
}

impl UserAccounts for FacadeUserAccounts {
    fn account_list(&self) -> BoxFuture<'_, Result<Vec<UserAccount>>> {
        match target(&self.relayer, FeatureName::AccountList) {
            Ok(target) => Box::pin(async move { target.account_list().await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn switch_account(&self, account_id: &str) -> BoxFuture<'_, Result<()>> {
        let account_id = account_id.to_owned();
        match target(&self.relayer, FeatureName::SwitchAccount) {
            Ok(target) => Box::pin(async move { target.switch_account(&account_id).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::{FacadeApps, FacadePower, FacadeUserAccounts};
    use crate::consts::{PowerState, Protocol};
    use crate::facade::{DEFAULT_PRIORITIES, POWER_PRIORITIES};
    use crate::features::FeatureName;
    use crate::interface::{Apps, BoxFuture, Power, UserAccounts};
    use crate::models::{App, UserAccount};
    use crate::relayer::Relayer;
    use crate::{Error, Result};

    /// Answers with its own name, so a test can see which protocol was reached.
    #[derive(Debug)]
    struct Named {
        name: &'static str,
        state: PowerState,
    }

    impl Power for Named {
        fn power_state(&self) -> PowerState {
            self.state
        }

        fn turn_on(&self, _await_new_state: bool) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn turn_off(&self, _await_new_state: bool) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    impl Apps for Named {
        fn app_list(&self) -> BoxFuture<'_, Result<Vec<App>>> {
            Box::pin(async move {
                Ok(vec![App {
                    name: self.name.to_owned(),
                    identifier: self.name.to_owned(),
                }])
            })
        }

        fn launch_app(&self, _bundle_id_or_url: &str) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    impl UserAccounts for Named {
        fn account_list(&self) -> BoxFuture<'_, Result<Vec<UserAccount>>> {
            Box::pin(async move {
                Ok(vec![UserAccount {
                    name: self.name.to_owned(),
                    identifier: self.name.to_owned(),
                }])
            })
        }

        fn switch_account(&self, _account_id: &str) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn named(name: &'static str, state: PowerState) -> Arc<Named> {
        Arc::new(Named { name, state })
    }

    fn declaring(features: &[FeatureName]) -> BTreeSet<FeatureName> {
        features.iter().copied().collect()
    }

    /// Companion outranks MRP for power (`OVERRIDE_PRIORITIES`, `facade.py:311-318`), and a handle
    /// taken before a takeover still follows it.
    #[test]
    fn power_prefers_companion_and_follows_a_takeover() {
        let relayer: Arc<Relayer<dyn Power>> = Arc::new(Relayer::new(POWER_PRIORITIES.to_vec()));
        let declared = declaring(&[FeatureName::PowerState, FeatureName::TurnOn]);
        relayer
            .register(
                Protocol::Mrp,
                named("mrp", PowerState::Off),
                declared.clone(),
            )
            .expect("the protocol is in the priority list");
        relayer
            .register(
                Protocol::Companion,
                named("companion", PowerState::On),
                declared,
            )
            .expect("the protocol is in the priority list");

        let power = FacadePower::new(Arc::clone(&relayer));
        assert_eq!(power.power_state(), PowerState::On);

        relayer.takeover(Protocol::Mrp).expect("free relayer");
        assert_eq!(power.power_state(), PowerState::Off);

        relayer.release();
        assert_eq!(power.power_state(), PowerState::On);
    }

    /// A protocol that registered a [`Power`] but never declared `TurnOff` does not answer it.
    #[tokio::test]
    async fn power_skips_a_protocol_that_did_not_declare_the_method() {
        let relayer: Arc<Relayer<dyn Power>> = Arc::new(Relayer::new(POWER_PRIORITIES.to_vec()));
        relayer
            .register(
                Protocol::Mrp,
                named("mrp", PowerState::Off),
                declaring(&[FeatureName::PowerState]),
            )
            .expect("the protocol is in the priority list");

        let power = FacadePower::new(relayer);
        let error = power.turn_off(false).await.expect_err("never declared");
        assert!(matches!(error, Error::NotSupported(_)), "{error}");
    }

    /// Nothing registered at all: the state is unknown rather than a guess.
    #[test]
    fn an_empty_power_relayer_reports_unknown() {
        let relayer: Arc<Relayer<dyn Power>> = Arc::new(Relayer::new(POWER_PRIORITIES.to_vec()));
        assert_eq!(FacadePower::new(relayer).power_state(), PowerState::Unknown);
    }

    #[tokio::test]
    async fn apps_and_accounts_relay_to_the_declaring_protocol() {
        let apps: Arc<Relayer<dyn Apps>> = Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        apps.register(
            Protocol::Mrp,
            named("mrp", PowerState::Unknown),
            BTreeSet::new(),
        )
        .expect("the protocol is in the priority list");
        apps.register(
            Protocol::Companion,
            named("companion", PowerState::Unknown),
            declaring(&[FeatureName::AppList]),
        )
        .expect("the protocol is in the priority list");

        let facade = FacadeApps::new(apps);
        let listed = facade.app_list().await.expect("Companion declared AppList");
        assert_eq!(
            listed.first().map(|app| app.identifier.clone()),
            Some("companion".to_owned()),
            "MRP outranks Companion but never declared AppList"
        );
        let error = facade
            .launch_app("com.example")
            .await
            .expect_err("nobody declared LaunchApp");
        assert!(matches!(error, Error::NotSupported(_)), "{error}");

        let accounts: Arc<Relayer<dyn UserAccounts>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        accounts
            .register(
                Protocol::Companion,
                named("companion", PowerState::Unknown),
                declaring(&[FeatureName::AccountList]),
            )
            .expect("the protocol is in the priority list");
        let listed = FacadeUserAccounts::new(accounts)
            .account_list()
            .await
            .expect("Companion declared AccountList");
        assert_eq!(
            listed.first().map(|account| account.identifier.clone()),
            Some("companion".to_owned())
        );
    }
}
