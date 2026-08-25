//! Apps, user accounts, the on-screen keyboard and power.
//!
//! Four of upstream's interface groups, together here because each is two or three one-line calls:
//! `interface.Apps` (`atvremote.py:941-942`), `interface.UserAccounts` (`:944-945`),
//! `interface.Keyboard` (`:935-936`) and `interface.Power` (`:925-926`).

use anyhow::Result;
use pyatv::AppleTV;

use crate::cli::Command;
use crate::report::{Reporter, unsupported};

/// Run an app, account or keyboard command.
///
/// # Errors
///
/// Returns [`pyatv::Error::NotSupported`] when no connected protocol serves the capability, and
/// whatever the device reports otherwise.
pub async fn run(atv: &dyn AppleTV, command: &Command, reporter: Reporter) -> Result<()> {
    match command {
        Command::AppList => {
            let apps = requires_apps(atv, "app_list")?.app_list().await?;
            reporter.apps(&apps);
        }
        Command::LaunchApp { target } => {
            requires_apps(atv, "launch_app")?.launch_app(target).await?;
            reporter.acknowledge("launch_app");
        }

        Command::AccountList => {
            let accounts = requires_accounts(atv, "account_list")?
                .account_list()
                .await?;
            reporter.accounts(&accounts);
        }
        Command::SwitchAccount { account_id } => {
            requires_accounts(atv, "switch_account")?
                .switch_account(account_id)
                .await?;
            reporter.acknowledge("switch_account");
        }

        // A property upstream, so it prints its value rather than acknowledging
        // (`pyatv/interface.py:1255-1259`).
        Command::TextFocusState => {
            reporter.focus_state(requires_keyboard(atv, "text_focus_state")?.text_focus_state());
        }
        Command::TextGet => {
            let text = requires_keyboard(atv, "text_get")?.text_get().await?;
            reporter.optional_value("text", text.as_deref());
        }
        Command::TextSet { text } => {
            requires_keyboard(atv, "text_set")?.text_set(text).await?;
            reporter.acknowledge("text_set");
        }
        Command::TextAppend { text } => {
            requires_keyboard(atv, "text_append")?
                .text_append(text)
                .await?;
            reporter.acknowledge("text_append");
        }
        Command::TextClear => {
            requires_keyboard(atv, "text_clear")?.text_clear().await?;
            reporter.acknowledge("text_clear");
        }

        other => unreachable!("{other:?} is not an app, account or keyboard command"),
    }

    Ok(())
}

/// Wake, sleep, or report the power state.
///
/// # Errors
///
/// Returns [`pyatv::Error::NotSupported`] when neither Companion nor MRP is connected.
pub async fn power(atv: &dyn AppleTV, command: &Command, reporter: Reporter) -> Result<()> {
    let power = atv
        .power()
        .ok_or_else(|| unsupported("power control", "Companion or MRP"))?;

    match command {
        // `await_new_state` defaults to false upstream (`pyatv/interface.py::Power.turn_on`), and
        // the CLI has no flag for it, so the command returns as soon as the device acknowledges.
        Command::TurnOn => {
            power.turn_on(false).await?;
            reporter.acknowledge("turn_on");
        }
        Command::TurnOff => {
            power.turn_off(false).await?;
            reporter.acknowledge("turn_off");
        }
        Command::PowerState => reporter.power_state(power.power_state()),
        other => unreachable!("{other:?} is not a power command"),
    }

    Ok(())
}

fn requires_apps(atv: &dyn AppleTV, what: &str) -> Result<std::sync::Arc<dyn pyatv::Apps>> {
    atv.apps().ok_or_else(|| unsupported(what, "Companion"))
}

fn requires_accounts(
    atv: &dyn AppleTV,
    what: &str,
) -> Result<std::sync::Arc<dyn pyatv::UserAccounts>> {
    atv.user_accounts()
        .ok_or_else(|| unsupported(what, "Companion"))
}

fn requires_keyboard(atv: &dyn AppleTV, what: &str) -> Result<std::sync::Arc<dyn pyatv::Keyboard>> {
    atv.keyboard().ok_or_else(|| unsupported(what, "Companion"))
}
