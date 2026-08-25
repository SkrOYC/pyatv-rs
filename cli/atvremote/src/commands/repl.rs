//! The `cli` subcommand: a line loop over the same dispatcher.
//!
//! `DeviceCommands.cli` (`pyatv/scripts/atvremote.py:392-408`), including the two opening lines,
//! the `pyatv> ` prompt, `exit` to leave, and the refusal to re-enter itself. One connection is
//! opened before the loop starts and every line runs against it, which is the point of the command:
//! it is how upstream avoids paying for a scan and a pairing handshake per button press.
//!
//! No readline, so no history and no line editing — the alternative is a dependency, and the loop
//! reads perfectly well from a pipe without one, which is what makes it testable.

use anyhow::Result;
use clap::Parser;
use pyatv::AppleTV;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::cli::{Cli, Command};
use crate::report::Reporter;

/// The prompt, verbatim from `atvremote.py:398`.
const PROMPT: &str = "pyatv> ";

/// One line typed at the prompt, parsed as if it were the tail of a command line.
///
/// `no_binary_name` is what makes clap treat the first word as the subcommand rather than as the
/// program name.
#[derive(Debug, Parser)]
#[command(name = "pyatv", no_binary_name = true, disable_version_flag = true)]
struct Line {
    #[command(subcommand)]
    command: Command,
}

/// Read commands until `exit`, end of input, or Ctrl-C.
///
/// # Errors
///
/// Only for a failure to read standard input. A command that fails prints its error and the loop
/// carries on, which is what upstream's `_handle_device_command` return code does
/// (`atvremote.py:406-408` ignores it).
pub async fn run(cli: &Cli, atv: &dyn AppleTV, reporter: Reporter) -> Result<()> {
    reporter.notice("Enter commands and press enter");
    reporter.notice("Type help for help and exit to quit");

    let mut lines = BufReader::new(tokio::io::stdin()).lines();

    loop {
        prompt(reporter);

        let Some(line) = lines.next_line().await? else {
            // End of input. Upstream blocks forever on a closed stdin; leaving is more useful and
            // is what makes `echo menu | atvremote cli` terminate.
            return Ok(());
        };

        match classify(&line) {
            Input::Blank => {}
            Input::Exit => return Ok(()),
            Input::Reentrant => reporter.notice("Command not available here"),
            Input::Help => reporter.notice("Run `atvremote --help`, or `commands` for buttons."),
            Input::Words(words) => run_line(cli, atv, reporter, &words).await,
        }
    }
}

/// What a typed line turned out to be.
#[derive(Debug, PartialEq, Eq)]
enum Input {
    /// Nothing but whitespace.
    Blank,
    /// `exit` (`atvremote.py:399-400`).
    Exit,
    /// `cli`, which upstream refuses inside itself (`atvremote.py:402-404`).
    Reentrant,
    /// `help` (`atvremote.py:395`).
    Help,
    /// A command and its arguments.
    Words(Vec<String>),
}

fn classify(line: &str) -> Input {
    let words = tokenize(line);
    match words.first().map(|word| word.to_ascii_lowercase()) {
        None => Input::Blank,
        Some(first) if first == "exit" => Input::Exit,
        Some(first) if first == "cli" => Input::Reentrant,
        Some(first) if first == "help" => Input::Help,
        Some(_) => Input::Words(words),
    }
}

/// Parse and run one line, reporting failures rather than propagating them.
async fn run_line(cli: &Cli, atv: &dyn AppleTV, reporter: Reporter, words: &[String]) {
    let parsed = match Line::try_parse_from(words) {
        Ok(parsed) => parsed,
        Err(error) => {
            // clap renders its own usage text; printing it whole is what a shell would do.
            eprint!("{error}");
            return;
        }
    };

    if let Err(error) = super::device::dispatch(cli, &parsed.command, atv, reporter).await {
        eprintln!("{error}");
    }
}

/// Write the prompt without a trailing newline, and flush so it appears.
fn prompt(reporter: Reporter) {
    use std::io::Write as _;

    // Upstream writes the prompt to stdout (`atvremote.py:52-53`). It goes to stderr under
    // `--json` for the same reason every other notice does: stdout must stay parseable.
    if reporter.is_json() {
        eprint!("{PROMPT}");
        let _ = std::io::stderr().flush();
    } else {
        print!("{PROMPT}");
        let _ = std::io::stdout().flush();
    }
}

/// Split a line into words, honouring double quotes.
///
/// Upstream's own argument parser has a quoting rule — `value.startswith('"') and
/// value.endswith('"')` forces a value to stay a string (`atvremote.py:820-823`) — and a
/// whitespace-only split would make `text_set "hello world"` impossible. Backslash escapes are not
/// supported; an unterminated quote runs to the end of the line rather than failing, because there
/// is no second line to continue onto.
fn tokenize(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;

    for character in line.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            character if character.is_whitespace() && !quoted => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            character => {
                current.push(character);
                started = true;
            }
        }
    }

    if started {
        words.push(current);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::{Input, Line, classify, tokenize};
    use crate::cli::Command;
    use clap::Parser as _;

    fn words(items: &[&str]) -> Input {
        Input::Words(items.iter().map(|it| (*it).to_owned()).collect())
    }

    #[test]
    fn blank_lines_do_nothing() {
        assert_eq!(classify(""), Input::Blank);
        assert_eq!(classify("   \t "), Input::Blank);
    }

    /// `if command.lower() == "exit": break` (`atvremote.py:399-400`).
    #[test]
    fn exit_leaves_the_loop_whatever_its_casing() {
        assert_eq!(classify("exit"), Input::Exit);
        assert_eq!(classify("EXIT"), Input::Exit);
        assert_eq!(classify("  Exit  "), Input::Exit);
    }

    /// `if command == "cli": print("Command not available here")` (`atvremote.py:402-404`).
    #[test]
    fn the_repl_refuses_to_re_enter_itself() {
        assert_eq!(classify("cli"), Input::Reentrant);
    }

    #[test]
    fn help_is_recognised_before_clap_sees_it() {
        assert_eq!(classify("help"), Input::Help);
    }

    #[test]
    fn ordinary_lines_become_word_lists() {
        assert_eq!(classify("remote up 1"), words(&["remote", "up", "1"]));
        assert_eq!(classify("  playing  "), words(&["playing"]));
    }

    #[test]
    fn quoted_arguments_survive_their_spaces() {
        assert_eq!(
            tokenize(r#"text_set "hello world""#),
            ["text_set", "hello world"]
        );
        assert_eq!(tokenize(r#"a "" b"#), ["a", "", "b"]);
        assert_eq!(
            tokenize(r#"launch_app "com.a b""#),
            ["launch_app", "com.a b"]
        );
    }

    #[test]
    fn an_unterminated_quote_runs_to_the_end_of_the_line() {
        assert_eq!(tokenize(r#"text_set "hello"#), ["text_set", "hello"]);
    }

    /// A typed line must parse through exactly the dispatcher the command line uses.
    #[test]
    fn typed_lines_parse_into_the_same_commands() {
        let parsed = Line::try_parse_from(["playing"]).expect("a bare command must parse");
        assert!(matches!(parsed.command, Command::Playing));

        let parsed = Line::try_parse_from(["remote", "up", "1"])
            .expect("a command with arguments must parse");
        let Command::Remote { button, args } = parsed.command else {
            panic!("expected a remote command");
        };
        assert_eq!(button, "up");
        assert_eq!(args, ["1"]);
    }

    #[test]
    fn an_unknown_line_is_a_parse_error_rather_than_a_panic() {
        assert!(Line::try_parse_from(["nonsense"]).is_err());
    }
}
