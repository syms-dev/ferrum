//! Asking the operator questions, behind a trait so every decision this
//! installer makes is testable without a human.
//!
//! That matters more here than it usually would: the two questions this
//! installer asks are the only things standing between a typed command and
//! an irreversibly repartitioned disk, or between a default install and
//! five admin panels published on the public internet with no login. A
//! prompt that cannot be tested is a guard that cannot be trusted.

use std::io::{BufRead, Write};

/// A question-and-answer channel with the operator.
pub trait PromptIo {
    /// Prints `question` and returns the operator's answer, trimmed.
    ///
    /// # Errors
    /// Returns an error if the input stream closes -- which is what
    /// happens when the installer is run non-interactively. That must be a
    /// refusal, never a default: there is deliberately no `--yes` in this
    /// phase, so an unanswerable question means stop.
    fn ask(&mut self, question: &str) -> anyhow::Result<String>;

    /// Prints a line of context. Not a question.
    fn say(&mut self, message: &str);
}

/// The real terminal.
pub struct Terminal<R: BufRead, W: Write> {
    pub reader: R,
    pub writer: W,
}

impl<R: BufRead, W: Write> PromptIo for Terminal<R, W> {
    fn ask(&mut self, question: &str) -> anyhow::Result<String> {
        write!(self.writer, "{question} ")?;
        self.writer.flush()?;
        let mut line = String::new();
        let n = self.reader.read_line(&mut line)?;
        if n == 0 {
            anyhow::bail!(
                "input closed while waiting for an answer. This installer has no \
                 non-interactive mode: every question it asks guards something \
                 irreversible."
            );
        }
        Ok(line.trim().to_string())
    }

    fn say(&mut self, message: &str) {
        let _ = writeln!(self.writer, "{message}");
    }
}

/// Builds a `Terminal` over the process's real stdin and stdout.
pub fn stdio() -> Terminal<std::io::BufReader<std::io::Stdin>, std::io::Stdout> {
    Terminal {
        reader: std::io::BufReader::new(std::io::stdin()),
        writer: std::io::stdout(),
    }
}

/// Requires the operator to type `expected` exactly.
///
/// Used for every irreversible or security-relevant confirmation. A yes/no
/// prompt is answered by reflex; typing a specific string is not, and it
/// also proves the operator read the thing they are typing.
///
/// # Errors
/// Propagates an input failure. A wrong answer is `Ok(false)`, not an
/// error -- the caller decides whether that is fatal.
pub fn confirm_exact(
    io: &mut impl PromptIo,
    question: &str,
    expected: &str,
) -> anyhow::Result<bool> {
    let answer = io.ask(question)?;
    Ok(answer == expected)
}

#[cfg(test)]
pub(crate) mod testing {
    use super::PromptIo;

    /// A scripted operator. Answers are consumed in order and trimmed
    /// exactly as `Terminal::ask` trims them; running out is the same
    /// failure as a closed stdin, so a test can never accidentally assert
    /// on an unanswered question.
    pub struct Scripted {
        answers: Vec<String>,
        pub said: Vec<String>,
        pub asked: Vec<String>,
    }

    impl Scripted {
        pub fn new(answers: &[&str]) -> Self {
            Self {
                answers: answers.iter().rev().map(|s| s.to_string()).collect(),
                said: Vec::new(),
                asked: Vec::new(),
            }
        }

        /// Everything printed or asked, for asserting that a warning
        /// actually reached the operator.
        pub fn transcript(&self) -> String {
            format!("{}\n{}", self.said.join("\n"), self.asked.join("\n"))
        }
    }

    impl PromptIo for Scripted {
        fn ask(&mut self, question: &str) -> anyhow::Result<String> {
            self.asked.push(question.to_string());
            // Trimmed, because that is the trait's documented contract and
            // what Terminal::ask really does. A double that is more
            // permissive than the real implementation makes every test
            // using it worth less than it appears.
            self.answers
                .pop()
                .map(|a| a.trim().to_string())
                .ok_or_else(|| anyhow::anyhow!("scripted input exhausted at: {question}"))
        }
        fn say(&mut self, message: &str) {
            self.said.push(message.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Scripted;
    use super::*;

    #[test]
    fn confirm_exact_accepts_only_the_exact_string() {
        for (answer, expected_ok) in [
            ("DESTROY", true),
            ("destroy", false),
            (" DESTROY", true), // trimmed by ask()
            ("DESTROY!", false),
            ("y", false),
            ("", false),
        ] {
            let mut io = Scripted::new(&[answer]);
            assert_eq!(
                confirm_exact(&mut io, "type DESTROY:", "DESTROY").unwrap(),
                expected_ok,
                "answer {answer:?}"
            );
        }
    }

    /// Non-interactive use must fail, not fall through to a default.
    #[test]
    fn a_closed_input_is_a_refusal_not_a_default() {
        let mut io = Terminal {
            reader: std::io::BufReader::new(std::io::Cursor::new(Vec::new())),
            writer: Vec::new(),
        };
        let err = io.ask("anything?").unwrap_err().to_string();
        assert!(err.contains("input closed"), "{err}");
        assert!(err.contains("no non-interactive mode"), "{err}");
    }

    #[test]
    fn answers_are_trimmed_and_the_question_is_shown() {
        let mut io = Terminal {
            reader: std::io::BufReader::new(std::io::Cursor::new(b"  hello \n".to_vec())),
            writer: Vec::new(),
        };
        assert_eq!(io.ask("name?").unwrap(), "hello");
        assert!(String::from_utf8(io.writer).unwrap().contains("name?"));
    }
}
