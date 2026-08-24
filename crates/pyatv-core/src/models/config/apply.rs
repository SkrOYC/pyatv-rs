//! Applying persisted [`crate::storage::Settings`] onto a [`BaseConfig`], split out of `mod.rs`
//! for module-size discipline.

use super::BaseConfig;
use crate::consts::Protocol;

impl BaseConfig {
    /// Apply persisted settings, so each service carries its stored credentials and password.
    ///
    /// Ports `pyatv/interface.py:1428-1440` (`BaseConfig.apply`) together with the
    /// [`crate::models::service::BaseService::apply`] it delegates to: a setting that is unset
    /// never clears a value the config already has, so credentials passed on the command line
    /// survive a settings file that has none. Protocols the device does not advertise are
    /// skipped.
    ///
    /// This is what `scan()` and `connect()` call after reading storage
    /// (`pyatv/__init__.py:96-97,120-121`), and it is the reason a paired device needs no
    /// credential arguments on later runs.
    pub fn apply(&mut self, settings: &crate::storage::Settings) {
        for protocol in Protocol::ALL {
            let credentials = settings.protocols.credentials(protocol).map(str::to_owned);
            let password = settings.protocols.password(protocol).map(str::to_owned);

            if let Some(service) = self.get_service_mut(protocol) {
                service.apply(credentials.as_deref(), password.as_deref());
            }
        }
    }
}
